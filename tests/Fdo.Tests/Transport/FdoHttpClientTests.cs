// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Linq;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Enrollment;
using Fdo.Transport;
using Fdo.Transport.Http;

namespace Fdo.Tests.Transport;

[UnsupportedOSPlatform("browser")]
public sealed class FdoHttpClientTests
{
    private static readonly byte[] Body = [0x81, 0x01];

    [Test]
    public async Task PairedTransportEndsAfterTheServerChangesItsAuthorizationToken()
    {
        using var origin = new LoopbackHttpServer();
        using var client = FdoHttpClient.CreatePaired();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var session = new FdoHttpClientSession(
            client, origin.Address, FdoProtocolKind.TransferOwnership2, FdoProtocolVersion.V20);
        IFdoDeviceTransport transport = session.CreateDeviceTransport();
        Task<RecordedRequest> first = origin.RespondOnceAsync(
            "200 OK\r\nMessage-Type: 81\r\nAuthorization: Bearer first\r\nContent-Type: application/cbor",
            Body, timeout.Token);
        await transport.SendAsync(200, FdoTo2MessageType.HelloDeviceProbe, Body, timeout.Token);
        await first;
        Task<RecordedRequest> second = origin.RespondOnceAsync(
            "200 OK\r\nMessage-Type: 83\r\nAuthorization: Bearer changed\r\nContent-Type: application/cbor",
            Body, timeout.Token);

        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => transport.SendAsync(200, FdoTo2MessageType.ProveDevice20, Body, timeout.Token).AsTask());
        RecordedRequest request = await second;

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.Authorization);
        await Assert.That(request.Authorization).IsEqualTo("Bearer first");
        await Assert.That(session.IsTerminated).IsTrue();
        await CatchAsync<InvalidOperationException>(
            () => transport.SendAsync(200, FdoTo2MessageType.ProveDevice20, Body, timeout.Token).AsTask());
        await Assert.That(origin.HasPendingConnection).IsFalse();
    }

    [Test]
    [Arguments(FdoMessageTypes.TO2DeviceServiceInfoRdy20)]
    [Arguments(FdoMessageTypes.TO2DeviceSvcInfo20)]
    [Arguments(FdoMessageTypes.TO2Done20)]
    public async Task V20DoesNotOpenAConnectionWithoutRequiredSessionProtection(ushort messageType)
    {
        using var origin = new LoopbackHttpServer();
        using var client = new FdoHttpClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var session = new FdoHttpClientSession(
            client, origin.Address, FdoProtocolKind.TransferOwnership2, FdoProtocolVersion.V20);

        bool rejected = false;
        try
        {
            await session.SendAsync(messageType, Body, timeout.Token);
        }
        catch (NotSupportedException error)
        {
            rejected = error.Message.Contains("session protection", StringComparison.Ordinal);
        }

        await Assert.That(rejected).IsTrue();
        await Assert.That(origin.HasPendingConnection).IsFalse();
        await Assert.That(session.IsTerminated).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DefaultClientDoesNotReplayPostToCrossOrigin307Target(bool sendError)
    {
        using var origin = new LoopbackHttpServer();
        using var target = new LoopbackHttpServer();
        using var client = new FdoHttpClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var session = new FdoHttpClientSession(
            client, origin.Address, FdoProtocolKind.TransferOwnership1, FdoTestVersions.SyntheticHttp);
        Task<RecordedRequest> received = origin.RespondOnceAsync(
            $"307 Temporary Redirect\r\nLocation: {target.Address.AbsoluteUri}", [], timeout.Token);

        if (sendError)
        {
            FdoTransportException? failure = null;
            try
            {
                await session.SendErrorAsync(Body, timeout.Token);
            }
            catch (FdoTransportException ex)
            {
                failure = ex;
            }

            await Assert.That(failure?.Failure).IsEqualTo(FdoTransportFailure.UnexpectedStatus);
        }
        else
        {
            FdoHttpResponse response = await session.SendAsync(FdoMessageTypes.TO1HelloRV, Body, timeout.Token);
            await Assert.That(response.Kind).IsEqualTo(FdoHttpResponseKind.Redirect);
            await Assert.That(response.RedirectLocation).IsEqualTo(target.Address);
        }

        RecordedRequest request = await received;
        await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
        await Assert.That(request.Body.SequenceEqual(Body)).IsTrue();
        await Assert.That(target.HasPendingConnection).IsFalse();
    }

    [Test]
    public async Task RealResponseAuthorizationIsReadAndReused()
    {
        using var origin = new LoopbackHttpServer();
        using var client = new FdoHttpClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var session = new FdoHttpClientSession(
            client, origin.Address, FdoProtocolKind.TransferOwnership1, FdoTestVersions.SyntheticHttp);
        Task<RecordedRequest> first = origin.RespondOnceAsync(
            "200 OK\r\nMessage-Type: 31\r\nAuthorization: token-1", Body, timeout.Token);
        await session.SendAsync(FdoMessageTypes.TO1HelloRV, Body, timeout.Token);
        RecordedRequest firstRequest = await first;
        Task<RecordedRequest> second = origin.RespondOnceAsync(
            "200 OK\r\nMessage-Type: 33\r\nAuthorization: token-1", Body, timeout.Token);

        FdoHttpResponse response = await session.SendAsync(FdoMessageTypes.TO1ProveToRV, Body, timeout.Token);
        RecordedRequest secondRequest = await second;

        await Assert.That(firstRequest.Authorization).IsNull();
        await Assert.That(secondRequest.Authorization).IsEqualTo("token-1");
        await Assert.That(response.MessageType).IsEqualTo(FdoMessageTypes.TO1RVRedirect);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InjectedTransportWithAutomaticRedirectsIsRejected(bool sockets)
    {
        using HttpMessageHandler handler = sockets ? new SocketsHttpHandler() : new HttpClientHandler();
        await Assert.That(RejectsHandler(handler)).IsTrue();
    }

    [Test]
    public async Task InjectedDelegatingChainWithAutomaticRedirectsIsRejected()
    {
        using var handler = new ScriptedHandler(new SocketsHttpHandler());
        await Assert.That(RejectsHandler(handler)).IsTrue();
    }

    [Test]
    public async Task OpaqueInjectedTransportIsRejected()
    {
        using var handler = new OpaqueHandler();
        await Assert.That(RejectsHandler(handler)).IsTrue();
    }

    [Test]
    public async Task EnablingRedirectsAfterConstructionIsRejectedBeforeSending()
    {
        using var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
        using var client = new FdoHttpClient(handler);
        handler.AllowAutoRedirect = true;
        using var request = new HttpRequestMessage(HttpMethod.Post, "http://127.0.0.1:1/");
        bool rejected = false;
        try
        {
            using HttpResponseMessage response = await client.SendAsync(request, CancellationToken.None);
        }
        catch (ArgumentException)
        {
            rejected = true;
        }

        await Assert.That(rejected).IsTrue();
    }

    private static bool RejectsHandler(HttpMessageHandler handler)
    {
        try
        {
            using var client = new FdoHttpClient(handler);
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private static async Task<TException> CatchAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private sealed class OpaqueHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("An opaque handler must be rejected before sending.");
    }
}
