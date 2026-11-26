// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Transport;
using Fdo.Transport.Http;

namespace Fdo.Tests.Transport;

[UnsupportedOSPlatform("browser")]
public sealed class FdoHttpClientSessionTests
{
    private static readonly Uri BaseAddress = new("http://rv.example/");
    private static readonly byte[] RequestBody = [0x83, 0x01, 0x02, 0x03];
    private static readonly byte[] ResponseBody = [0x82, 0x0A, 0x0B];

    [Test]
    public async Task FirstRequestPostsCborWithoutAuthorizationToVersionedPath()
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, ResponseBody, "token-1"));
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);

        FdoHttpResponse response = await session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody);

        RecordedRequest request = handler.Requests.Single();
        await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
        await Assert.That(request.Uri!.AbsoluteUri).IsEqualTo("http://rv.example/fdo/65099/msg/30");
        await Assert.That(request.ContentType).IsEqualTo("application/cbor");
        await Assert.That(request.Authorization).IsNull();
        await Assert.That(request.Body.SequenceEqual(RequestBody)).IsTrue();
        await Assert.That(response.Kind).IsEqualTo(FdoHttpResponseKind.Message);
        await Assert.That(response.MessageType).IsEqualTo(FdoMessageTypes.TO1HelloRVAck);
        await Assert.That(response.Body.ToArray().SequenceEqual(ResponseBody)).IsTrue();
        await Assert.That(response.StreamMessage!.Version).IsEqualTo(FdoTestVersions.SyntheticHttp);
        await Assert.That(response.StreamMessage.Authorization).IsEqualTo("token-1");
        await Assert.That(response.StreamMessage.Body.ToArray().SequenceEqual(ResponseBody)).IsTrue();
        await Assert.That(session.HasAuthorizationToken).IsTrue();
    }

    [Test]
    public async Task LaterRequestsCarryTheAllocatedToken()
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, ResponseBody, "token-1"))
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1RVRedirect, ResponseBody, null));
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);

        await session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody);
        FdoHttpResponse second = await session.SendAsync(FdoMessageTypes.TO1ProveToRV, RequestBody);

        await Assert.That(handler.Requests[1].Authorization).IsEqualTo("token-1");
        await Assert.That(handler.Requests[1].Uri!.AbsoluteUri).IsEqualTo("http://rv.example/fdo/65099/msg/32");
        await Assert.That(second.MessageType).IsEqualTo(FdoMessageTypes.TO1RVRedirect);
    }

    [Test]
    public async Task BaseAddressPathPrefixesTheProvisionalNumericFdoPath()
    {
        using var client = new FdoHttpClient(new ScriptedHandler());
        var session = new FdoHttpClientSession(
            client,
            new Uri("https://owner.example:8443/onboarding/"),
            FdoProtocolKind.TransferOwnership2,
            FdoProtocolVersion.V20);

        Uri uri = session.GetMessageUri(FdoMessageTypes.TO2HelloDeviceProbe);

        await Assert.That(uri.AbsoluteUri).IsEqualTo("https://owner.example:8443/onboarding/fdo/200/msg/80");
    }

    [Test]
    public async Task ProtocolVersionEncodesMajorTimesHundredPlusMinor()
    {
        await Assert.That(FdoProtocolVersion.V20.Value).IsEqualTo((ushort)200);
        await Assert.That(new FdoProtocolVersion(1, 1).Value).IsEqualTo((ushort)101);
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new FdoProtocolVersion(2, 100))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new FdoProtocolVersion(0, 0))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new FdoProtocolVersion(656, 0))).IsTrue();
    }

    [Test]
    [Arguments((int)FdoProtocolKind.TransferOwnership1, FdoMessageTypes.TO2HelloDeviceProbe)]
    [Arguments((int)FdoProtocolKind.TransferOwnership2, FdoMessageTypes.TO2HelloDeviceAck20)]
    [Arguments((int)FdoProtocolKind.TransferOwnership0, FdoMessageTypes.Error)]
    public async Task RequestTypeOutsideTheSubProtocolIsRejectedBeforeSending(int protocol, ushort messageType)
    {
        var handler = new ScriptedHandler();
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, (FdoProtocolKind)protocol);

        await CatchAsync<ArgumentOutOfRangeException>(() => session.SendAsync(messageType, RequestBody));

        await Assert.That(handler.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments((int)FdoProtocolKind.DeviceInitialize, FdoMessageTypes.DIAppStart, FdoMessageTypes.DISetCredentials, "10")]
    [Arguments((int)FdoProtocolKind.TransferOwnership0, FdoMessageTypes.TO0Hello, FdoMessageTypes.TO0HelloAck, "20")]
    [Arguments((int)FdoProtocolKind.TransferOwnership1, FdoMessageTypes.TO1HelloRV, FdoMessageTypes.TO1HelloRVAck, "30")]
    [Arguments((int)FdoProtocolKind.TransferOwnership2, FdoMessageTypes.TO2HelloDeviceProbe, FdoMessageTypes.TO2HelloDeviceAck20, "80")]
    [Arguments((int)FdoProtocolKind.TransferOwnership2, FdoMessageTypes.TO2GetOVNextEntry20, FdoMessageTypes.TO2OVNextEntry20, "84")]
    public async Task V20RequestsUseTheSelectedNumericRoute(
        int protocol, ushort messageType, ushort responseType, string suffix)
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(responseType, ResponseBody, "token-1"));
        using var client = new FdoHttpClient(handler);
        var session = new FdoHttpClientSession(
            client, BaseAddress, (FdoProtocolKind)protocol, FdoProtocolVersion.V20);

        FdoHttpResponse response = await session.SendAsync(messageType, RequestBody);

        RecordedRequest request = handler.Requests.Single();
        await Assert.That(request.Uri!.AbsoluteUri).IsEqualTo("http://rv.example/fdo/200/msg/" + suffix);
        await Assert.That(request.Body.SequenceEqual(RequestBody)).IsTrue();
        await Assert.That(response.MessageType).IsEqualTo(responseType);
        await Assert.That(response.StreamMessage!.Version).IsEqualTo(FdoProtocolVersion.V20);
        await Assert.That(session.HasAuthorizationToken).IsTrue();
        await Assert.That(session.IsTerminated).IsFalse();
    }

    [Test]
    public async Task UnresolvedV20ErrorBodyIsBlockedBeforeSending()
    {
        var handler = new ScriptedHandler();
        using var client = new FdoHttpClient(handler);
        var session = new FdoHttpClientSession(
            client, BaseAddress, FdoProtocolKind.TransferOwnership2, FdoProtocolVersion.V20);

        NotSupportedException error = await CatchAsync<NotSupportedException>(
            () => session.SendErrorAsync(RequestBody));

        await Assert.That(error.Message.Contains("phase-specific protection", StringComparison.Ordinal)).IsTrue();
        await Assert.That(handler.Requests.Count).IsEqualTo(0);
        await Assert.That(session.HasAuthorizationToken).IsFalse();
        await Assert.That(session.IsTerminated).IsFalse();
    }

    [Test]
    public async Task V20DoesNotRetryAnotherRouteAfterFailure()
    {
        var handler = new ScriptedHandler().Respond(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        using var client = new FdoHttpClient(handler);
        var session = new FdoHttpClientSession(
            client, BaseAddress, FdoProtocolKind.TransferOwnership2, FdoProtocolVersion.V20);

        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => session.SendAsync(FdoMessageTypes.TO2HelloDeviceProbe, RequestBody));

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.UnexpectedStatus);
        await Assert.That(handler.Requests.Count).IsEqualTo(1);
        await Assert.That(handler.Requests[0].Uri!.AbsoluteUri).IsEqualTo("http://rv.example/fdo/200/msg/80");
    }

    [Test]
    [Arguments(FdoMessageTypes.TO2DeviceServiceInfoRdy20)]
    [Arguments(FdoMessageTypes.TO2DeviceSvcInfo20)]
    [Arguments(FdoMessageTypes.TO2Done20)]
    public async Task To2RequestsRequiringUnavailableProtectionAreRejectedBeforeSending(ushort messageType)
    {
        var handler = new ScriptedHandler();
        using var client = new FdoHttpClient(handler);
        var session = new FdoHttpClientSession(
            client, BaseAddress, FdoProtocolKind.TransferOwnership2, FdoProtocolVersion.V20);

        NotSupportedException error = await CatchAsync<NotSupportedException>(
            () => session.SendAsync(messageType, RequestBody));

        await Assert.That(FdoMessageTypes.IsRequest(FdoProtocolKind.TransferOwnership2, messageType)).IsTrue();
        await Assert.That(error.Message.Contains("session protection", StringComparison.Ordinal)).IsTrue();
        await Assert.That(handler.Requests.Count).IsEqualTo(0);
        await Assert.That(session.IsTerminated).IsFalse();
    }

    [Test]
    public async Task SelectedDone20RouteRemainsBlockedWithoutSessionProtection()
    {
        var handler = new ScriptedHandler();
        using var client = new FdoHttpClient(handler);
        var session = new FdoHttpClientSession(
            client, BaseAddress, FdoProtocolKind.TransferOwnership2, FdoProtocolVersion.V20);

        Uri uri = session.GetMessageUri(FdoMessageTypes.TO2Done20);
        NotSupportedException error = await CatchAsync<NotSupportedException>(
            () => session.SendAsync(FdoMessageTypes.TO2Done20, RequestBody));

        await Assert.That(FdoMessageTypes.IsRequest(
            FdoProtocolKind.TransferOwnership2, FdoMessageTypes.TO2Done20)).IsTrue();
        await Assert.That(FdoMessageTypes.RequiresUnavailableTo2Protection(
            FdoProtocolKind.TransferOwnership2, FdoMessageTypes.TO2Done20)).IsTrue();
        await Assert.That(uri.AbsolutePath.EndsWith("/msg/90", StringComparison.Ordinal)).IsTrue();
        await Assert.That(error.Message.Contains("session protection", StringComparison.Ordinal)).IsTrue();
        await Assert.That(handler.Requests.Count).IsEqualTo(0);
        await Assert.That(session.IsTerminated).IsFalse();
    }

    [Test]
    public async Task MissingMessageTypeIsInvalid()
    {
        var handler = new ScriptedHandler().Respond(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(ResponseBody) };
            response.Headers.TryAddWithoutValidation("Authorization", "token-1");
            return response;
        });

        await ExpectFailureAsync(handler, FdoTransportFailure.InvalidResponse);
    }

    [Test]
    [Arguments("abc")]
    [Arguments("+31")]
    [Arguments("65536")]
    public async Task MalformedMessageTypeIsInvalid(string headerValue)
    {
        var handler = new ScriptedHandler().Respond(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(ResponseBody) };
            response.Headers.TryAddWithoutValidation("Authorization", "token-1");
            response.Headers.TryAddWithoutValidation("Message-Type", headerValue);
            return response;
        });

        await ExpectFailureAsync(handler, FdoTransportFailure.InvalidResponse);
    }

    [Test]
    [Arguments(FdoMessageTypes.TO2HelloDeviceAck20)]
    [Arguments(FdoMessageTypes.TO1HelloRV)]
    [Arguments(FdoMessageTypes.Error)]
    public async Task ResponseTypeOutsideTheSubProtocolIsInvalid(ushort messageType)
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(messageType, ResponseBody, "token-1"));

        await ExpectFailureAsync(handler, FdoTransportFailure.InvalidResponse);
    }

    [Test]
    [Arguments("1800")]
    [Arguments("9F00FF")]
    [Arguments("A21818006000")]
    [Arguments("0000")]
    [Arguments("5A7FFFFFFF")]
    public async Task MalformedOrNondeterministicCborResponseIsInvalid(string hex)
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, Convert.FromHexString(hex), "token-1"));

        await ExpectFailureAsync(handler, FdoTransportFailure.InvalidResponse);
    }

    [Test]
    public async Task InvalidFirstBodyRetainsTokenForErrorReporting()
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, [0x18, 0x00], "token-1"))
            .Respond(_ => new HttpResponseMessage(HttpStatusCode.OK));
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);

        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody));
        await session.SendErrorAsync(RequestBody);

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.InvalidResponse);
        await Assert.That(handler.Requests[1].Authorization).IsEqualTo("token-1");
        await Assert.That(session.IsTerminated).IsTrue();
    }

    [Test]
    public async Task EmptySuccessBodyIsInvalid()
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, [], "token-1"));

        await ExpectFailureAsync(handler, FdoTransportFailure.InvalidResponse);
    }

    [Test]
    public async Task FirstResponseWithoutTokenFailsAuthorization()
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, ResponseBody, null));

        await ExpectFailureAsync(handler, FdoTransportFailure.Authorization);
    }

    [Test]
    public async Task SameTokenInSuccessiveResponsesIsAccepted()
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, ResponseBody, "token-1"))
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1RVRedirect, ResponseBody, "token-1"));
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);

        await session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody);
        FdoHttpResponse response = await session.SendAsync(FdoMessageTypes.TO1ProveToRV, RequestBody);

        await Assert.That(response.MessageType).IsEqualTo(FdoMessageTypes.TO1RVRedirect);
        await Assert.That(handler.Requests[1].Authorization).IsEqualTo("token-1");
    }

    [Test]
    public async Task DuplicateTokenValuesInOneResponseAreRejected()
    {
        var handler = new ScriptedHandler().Respond(_ =>
        {
            HttpResponseMessage response = ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, ResponseBody, "token-1");
            response.Headers.TryAddWithoutValidation("Authorization", "token-1");
            return response;
        });

        await ExpectFailureAsync(handler, FdoTransportFailure.Authorization);
    }

    [Test]
    public async Task ChangedTokenFailsAuthorization()
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, ResponseBody, "token-1"))
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1RVRedirect, ResponseBody, "token-2"));
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);
        await session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody);

        FdoTransportException ex = await CatchAsync<FdoTransportException>(
            () => session.SendAsync(FdoMessageTypes.TO1ProveToRV, RequestBody));

        await Assert.That(ex.Failure).IsEqualTo(FdoTransportFailure.Authorization);
    }

    [Test]
    public async Task DeclaredLengthAboveLimitIsRejected()
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, new byte[17], "token-1"));

        await ExpectFailureAsync(handler, FdoTransportFailure.ResponseTooLarge, maxResponseBytes: 16);
    }

    [Test]
    public async Task UndeclaredLengthAboveLimitIsRejected()
    {
        var handler = new ScriptedHandler().Respond(_ =>
        {
            HttpResponseMessage response = ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, [], "token-1");
            response.Content = new UnknownLengthContent(new byte[17]);
            return response;
        });

        await ExpectFailureAsync(handler, FdoTransportFailure.ResponseTooLarge, maxResponseBytes: 16);
    }

    [Test]
    public async Task UndeclaredLengthAtLimitIsAccepted()
    {
        byte[] body = [0x4f, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        var handler = new ScriptedHandler().Respond(_ =>
        {
            HttpResponseMessage response = ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, [], "token-1");
            response.Content = new UnknownLengthContent(body);
            return response;
        });
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1, maxResponseBytes: 16);

        FdoHttpResponse response = await session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody);

        await Assert.That(response.Body.ToArray().SequenceEqual(body)).IsTrue();
    }

    [Test]
    public async Task ErrorResponseTerminatesTheSession()
    {
        var handler = new ScriptedHandler().Respond(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new ByteArrayContent(ResponseBody) };
            response.Headers.TryAddWithoutValidation("Message-Type", "255");
            return response;
        });
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);

        FdoHttpResponse response = await session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody);

        await Assert.That(response.Kind).IsEqualTo(FdoHttpResponseKind.Error);
        await Assert.That(response.MessageType).IsEqualTo(FdoMessageTypes.Error);
        await Assert.That(response.Body.ToArray().SequenceEqual(ResponseBody)).IsTrue();
        await Assert.That(session.IsTerminated).IsTrue();
        await CatchAsync<InvalidOperationException>(() => session.SendAsync(FdoMessageTypes.TO1ProveToRV, RequestBody));
        await CatchAsync<InvalidOperationException>(() => session.SendErrorAsync(RequestBody));
        await Assert.That(handler.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ErrorResponseMayOmitMessageType()
    {
        var handler = new ScriptedHandler().Respond(_ =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new ByteArrayContent(ResponseBody) });
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);

        FdoHttpResponse response = await session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody);

        await Assert.That(response.Kind).IsEqualTo(FdoHttpResponseKind.Error);
    }

    [Test]
    public async Task ErrorResponseWithOtherMessageTypeIsInvalid()
    {
        var handler = new ScriptedHandler().Respond(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new ByteArrayContent(ResponseBody) };
            response.Headers.TryAddWithoutValidation("Message-Type", "31");
            return response;
        });

        await ExpectFailureAsync(handler, FdoTransportFailure.InvalidResponse);
    }

    [Test]
    public async Task ServerErrorWithoutBodyIsUnexpectedStatus()
    {
        var handler = new ScriptedHandler().Respond(_ =>
            new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new ByteArrayContent([]) });

        await ExpectFailureAsync(handler, FdoTransportFailure.UnexpectedStatus);
    }

    [Test]
    [Arguments(HttpStatusCode.Found)]
    [Arguments(HttpStatusCode.TemporaryRedirect)]
    public async Task HelloRVRedirectReturnsAbsoluteLocationAndTerminates(HttpStatusCode status)
    {
        var handler = new ScriptedHandler().Respond(_ =>
        {
            var response = new HttpResponseMessage(status);
            response.Headers.Location = new Uri("/other", UriKind.Relative);
            return response;
        });
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);

        FdoHttpResponse response = await session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody);

        await Assert.That(response.Kind).IsEqualTo(FdoHttpResponseKind.Redirect);
        await Assert.That(response.RedirectLocation!.AbsoluteUri).IsEqualTo("http://rv.example/other");
        await Assert.That(session.IsTerminated).IsTrue();
    }

    [Test]
    public async Task RedirectOutsideHelloRVIsUnexpectedStatus()
    {
        var handler = new ScriptedHandler().Respond(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
            response.Headers.Location = new Uri("http://other.example/");
            return response;
        });
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership2);

        FdoTransportException ex = await CatchAsync<FdoTransportException>(
            () => session.SendAsync(FdoMessageTypes.TO2HelloDeviceProbe, RequestBody));

        await Assert.That(ex.Failure).IsEqualTo(FdoTransportFailure.UnexpectedStatus);
        await Assert.That(session.IsTerminated).IsFalse();
    }

    [Test]
    public async Task RedirectToNonHttpSchemeIsInvalid()
    {
        var handler = new ScriptedHandler().Respond(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
            response.Headers.Location = new Uri("ftp://other.example/");
            return response;
        });

        await ExpectFailureAsync(handler, FdoTransportFailure.InvalidResponse);
    }

    [Test]
    public async Task AutomaticallyFollowedRedirectIsInvalid()
    {
        var handler = new ScriptedHandler().Respond(request =>
        {
            request.RequestUri = new Uri("http://other.example/fdo/65099/msg/30");
            HttpResponseMessage response = ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, ResponseBody, "token-1");
            response.RequestMessage = request;
            return response;
        });

        await ExpectFailureAsync(handler, FdoTransportFailure.InvalidResponse);
    }

    [Test]
    [Arguments(HttpStatusCode.NotFound)]
    [Arguments(HttpStatusCode.Unauthorized)]
    [Arguments(HttpStatusCode.ServiceUnavailable)]
    public async Task OtherStatusIsUnexpected(HttpStatusCode status)
    {
        var handler = new ScriptedHandler().Respond(_ => new HttpResponseMessage(status));

        FdoTransportException ex = await ExpectFailureAsync(handler, FdoTransportFailure.UnexpectedStatus);

        await Assert.That(ex.StatusCode).IsEqualTo(status);
    }

    [Test]
    public async Task NetworkFailureLeavesTheSessionUsable()
    {
        var handler = new ScriptedHandler()
            .Respond(_ => throw new HttpRequestException("connection reset"))
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, ResponseBody, "token-1"));
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);

        FdoTransportException ex = await CatchAsync<FdoTransportException>(
            () => session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody));
        FdoHttpResponse retry = await session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody);

        await Assert.That(ex.Failure).IsEqualTo(FdoTransportFailure.Network);
        await Assert.That(session.IsTerminated).IsFalse();
        await Assert.That(retry.Kind).IsEqualTo(FdoHttpResponseKind.Message);
    }

    [Test]
    public async Task CallerCancellationPropagates()
    {
        var handler = new ScriptedHandler();
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await CatchAsync<OperationCanceledException>(
            () => session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody, cts.Token));

        await Assert.That(session.IsTerminated).IsFalse();
    }

    [Test]
    public async Task ConcurrentExchangeIsRejected()
    {
        var release = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new ScriptedHandler().RespondAsync(_ => release.Task);
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);

        Task<FdoHttpResponse> first = session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody);
        await CatchAsync<InvalidOperationException>(() => session.SendAsync(FdoMessageTypes.TO1ProveToRV, RequestBody));
        release.SetResult(ScriptedHandler.Message(FdoMessageTypes.TO1HelloRVAck, ResponseBody, "token-1"));
        FdoHttpResponse response = await first;

        await Assert.That(response.Kind).IsEqualTo(FdoHttpResponseKind.Message);
        await Assert.That(handler.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task SendErrorPostsType255WithTokenAndTerminates()
    {
        var handler = new ScriptedHandler()
            .Respond(_ => ScriptedHandler.Message(FdoMessageTypes.TO2HelloDeviceAck20, ResponseBody, "token-1"))
            .Respond(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([]) });
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership2);
        await session.SendAsync(FdoMessageTypes.TO2HelloDeviceProbe, RequestBody);

        await session.SendErrorAsync(RequestBody);

        RecordedRequest error = handler.Requests[1];
        await Assert.That(error.Uri!.AbsoluteUri).IsEqualTo("http://rv.example/fdo/65099/msg/255");
        await Assert.That(error.Authorization).IsEqualTo("token-1");
        await Assert.That(error.ContentType).IsEqualTo("application/cbor");
        await Assert.That(session.IsTerminated).IsTrue();
        await CatchAsync<InvalidOperationException>(() => session.SendErrorAsync(RequestBody));
    }

    [Test]
    public async Task RejectedSendErrorStillTerminates()
    {
        var handler = new ScriptedHandler().Respond(_ => new HttpResponseMessage(HttpStatusCode.BadRequest));
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership2);

        FdoTransportException ex = await CatchAsync<FdoTransportException>(() => session.SendErrorAsync(RequestBody));

        await Assert.That(ex.Failure).IsEqualTo(FdoTransportFailure.UnexpectedStatus);
        await Assert.That(session.IsTerminated).IsTrue();
    }

    [Test]
    public async Task ConstructorRejectsInvalidArguments()
    {
        using var client = new FdoHttpClient(new ScriptedHandler());
        FdoProtocolKind to1 = FdoProtocolKind.TransferOwnership1;
        FdoProtocolVersion v20 = FdoProtocolVersion.V20;

        await Assert.That(Throws<ArgumentException>(() => new FdoHttpClientSession(client, new Uri("/rv", UriKind.Relative), to1, v20))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new FdoHttpClientSession(client, new Uri("ftp://rv.example/"), to1, v20))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new FdoHttpClientSession(client, new Uri("http://rv.example/?a=b"), to1, v20))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new FdoHttpClientSession(client, BaseAddress, (FdoProtocolKind)99, v20))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new FdoHttpClientSession(client, BaseAddress, to1, default))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new FdoHttpClientSession(client, BaseAddress, to1, v20, 0))).IsTrue();
    }

    [Test]
    public async Task NoncanonicalOutboundBodiesAreRejectedWithoutSendingOrEndingTheSession()
    {
        var handler = new ScriptedHandler();
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);
        byte[] noncanonical = [0x18, 0x00];

        await CatchAsync<ArgumentException>(() => session.SendAsync(FdoMessageTypes.TO1HelloRV, noncanonical));
        await CatchAsync<ArgumentException>(() => session.SendErrorAsync(noncanonical));

        await Assert.That(handler.Requests.Count).IsEqualTo(0);
        await Assert.That(session.IsTerminated).IsFalse();
    }

    [Test]
    public async Task EmptyRequestBodyIsRejected()
    {
        var handler = new ScriptedHandler();
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1);

        await CatchAsync<ArgumentException>(() => session.SendAsync(FdoMessageTypes.TO1HelloRV, ReadOnlyMemory<byte>.Empty));
        await CatchAsync<ArgumentException>(() => session.SendErrorAsync(ReadOnlyMemory<byte>.Empty));

        await Assert.That(handler.Requests.Count).IsEqualTo(0);
    }

    private static FdoHttpClientSession CreateSession(
        FdoHttpClient client,
        FdoProtocolKind protocol,
        int maxResponseBytes = FdoHttpClientSession.DefaultMaxResponseBytes) =>
        new(client, BaseAddress, protocol, FdoTestVersions.SyntheticHttp, maxResponseBytes);

    private static async Task<FdoTransportException> ExpectFailureAsync(
        ScriptedHandler handler,
        FdoTransportFailure expected,
        int maxResponseBytes = FdoHttpClientSession.DefaultMaxResponseBytes)
    {
        using var client = new FdoHttpClient(handler);
        var session = CreateSession(client, FdoProtocolKind.TransferOwnership1, maxResponseBytes);

        FdoTransportException ex = await CatchAsync<FdoTransportException>(
            () => session.SendAsync(FdoMessageTypes.TO1HelloRV, RequestBody));

        await Assert.That(ex.Failure).IsEqualTo(expected);
        return ex;
    }

    private static async Task<T> CatchAsync<T>(Func<Task> action)
        where T : Exception
    {
        try
        {
            await action();
        }
        catch (T ex)
        {
            return ex;
        }

        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static bool Throws<T>(Action action)
        where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return true;
        }

        return false;
    }
}
