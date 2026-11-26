// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.IO;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Rendezvous;
using Fdo.Serialization;
using Fdo.Tests.Cryptography;
using Fdo.Tests.Transport;
using Fdo.Transport.Http;
using AuthenticationFixture = Fdo.Tests.Cryptography.FdoTo2OwnerDeviceAuthenticatorTests.Fixture;

namespace Fdo.Tests.Rendezvous;

[UnsupportedOSPlatform("browser")]
public sealed class FdoDelegatedRendezvousTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task HttpBatchCachesExactSignedBlobsBeforeReturning(bool paged)
    {
        using var run = new Fixture();
        var (direct, delegated) = await RegisterPageFixtureAsync(run, paged);
        using var server = run.Rendezvous.CreateServer(FdoRendezvousProtocol.DeviceLookup, run.Store, multiple: true);
        using var binding = FdoHttpServerSession.ForRendezvous(server);
        using var listener = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<IReadOnlyList<RecordedRequest>> serving = listener.ServeSessionAsync(binding, timeout.Token);
        IReadOnlyList<FdoDeviceRendezvousResult> result = await FdoHttp.RunDeviceRendezvousBatchAsync(
            run.Rendezvous.CreateDevice(delegated: true), listener.Address, cancellationToken: timeout.Token);
        await Assert.That(result.Count).IsEqualTo(2);
        FdoRendezvousRegistration[] expected = direct.RegistrationId.CompareTo(delegated.RegistrationId) < 0
            ? [direct, delegated] : [delegated, direct];
        for (int i = 0; i < expected.Length; i++)
        {
            await Assert.That(result[i].SignedRedirect.Span.SequenceEqual(expected[i].SignedRedirect.Span)).IsTrue();
        }

        IReadOnlyList<RecordedRequest> requests = await serving;
        await Assert.That(requests.Count).IsEqualTo(paged ? 3 : 2);
        if (paged)
        {
            await Assert.That(requests[2].Uri!.AbsolutePath).IsEqualTo("/fdo/200/msg/32");
            await Assert.That(requests[2].Authorization).IsEqualTo(requests[1].Authorization);
            await Assert.That(requests[2].Body.AsSpan().SequenceEqual(FdoRendezvousCodec.EncodeRvMore(1).Span)).IsTrue();
        }

        await Assert.That(server.FinalResponseHandoffConfirmed).IsTrue();
    }

    [Test]
    [Arguments("total")]
    [Arguments("index")]
    [Arguments("transport")]
    public async Task BatchLookupDoesNotReturnPartialResultsOrRetryOnFailure(string failure)
    {
        using var run = new Fixture();
        await RegisterPageFixtureAsync(run, paged: true);
        using var server = run.Rendezvous.CreateServer(FdoRendezvousProtocol.DeviceLookup, run.Store, multiple: true);
        var transport = run.Rendezvous.CreateTransport(server);
        int redirects = 0;
        transport.Change = message =>
        {
            if (message.Type != FdoRendezvousMessageType.Redirect || ++redirects != 2)
            {
                return message;
            }

            if (failure == "transport")
            {
                throw new IOException("The second page did not reach the Device.");
            }

            byte[] body = message.Body.ToArray();
            body[failure == "total" ? 1 : 2] = failure == "total" ? (byte)3 : (byte)0;
            return message with { Body = body };
        };
        Exception error = await CaptureAsync(async () =>
            await run.Rendezvous.CreateDevice(delegated: true).RunBatchAsync(transport));
        await Assert.That(failure == "transport" ? error is IOException : error is CborContentException).IsTrue();
        await Assert.That(redirects).IsEqualTo(2);
        await Assert.That(transport.Messages.Count).IsEqualTo(6);
    }

    [Test]
    [Arguments("repeat")]
    [Arguments("expiry")]
    [Arguments("revision")]
    [Arguments("wrong-index")]
    public async Task RvMoreChecksSnapshotBeforeServingOrRepeatingAPage(string change)
    {
        using var run = new Fixture();
        await RegisterPageFixtureAsync(run, paged: true);
        int maxMessage = run.Rendezvous.MaxMessageSize;
        using var lookup = run.Rendezvous.CreateServer(FdoRendezvousProtocol.DeviceLookup, run.Store, multiple: true);
        FdoRendezvousResponse hello = await lookup.ProcessAsync(200, FdoRendezvousMessageType.DeviceHello,
            run.Rendezvous.Codec.EncodeInitial(30, run.Authentication.Voucher.Guid, true));
        lookup.ConfirmResponseSent();
        var ack = run.Rendezvous.Codec.ReadInitial(31, hello.EncodedBody, true);
        ReadOnlyMemory<byte> proof = run.Rendezvous.Codec.SignDeviceProof(
            run.Authentication.Voucher.Guid, ack.GuidOrNonce!.Value, run.Authentication.DeviceSigningKey);
        FdoRendezvousResponse first = await lookup.ProcessAsync(200, FdoRendezvousMessageType.ProveToRendezvous, proof);
        lookup.ConfirmResponseSent();
        await Assert.That(run.Rendezvous.Codec.ReadRedirectPage(first.EncodedBody).Blobs.Length).IsEqualTo(1);
        await Assert.That(lookup.FinalResponseHandoffConfirmed).IsFalse();

        if (change == "wrong-index")
        {
            await ExpectAsync<CborContentException>(async () => await PageAsync(2));
            await Assert.That(lookup.FinalResponseHandoffConfirmed).IsFalse();
            return;
        }

        FdoRendezvousResponse last = await PageAsync(1);
        lookup.ConfirmResponseSent();
        await Assert.That(last.EncodedBody.Length <= maxMessage).IsTrue();
        await Assert.That(lookup.FinalResponseHandoffConfirmed).IsTrue();
        if (change == "expiry")
        {
            run.Rendezvous.Clock.Now = run.Disk.Now = run.Disk.Now.AddSeconds(120);
        }
        else if (change == "revision")
        {
            run.Rendezvous.MaxMessageSize = 8192;
            using var replacement = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
            await run.RegisterAsync(replacement);
        }

        if (change == "repeat")
        {
            var repeated = await PageAsync(1);
            await Assert.That(repeated.EncodedBody.Span.SequenceEqual(last.EncodedBody.Span)).IsTrue();
            lookup.ConfirmResponseSent();
            await ExpectAsync<CborContentException>(async () => await PageAsync(1));
        }
        else
        {
            await ExpectAsync<InvalidOperationException>(async () => await PageAsync(1));
        }

        async ValueTask<FdoRendezvousResponse> PageAsync(int index) =>
            await lookup.ProcessAsync(200, FdoRendezvousMessageType.ProveToRendezvous, FdoRendezvousCodec.EncodeRvMore(index));
    }

    private static async Task<(FdoRendezvousRegistration Direct, FdoRendezvousRegistration Delegated)>
        RegisterPageFixtureAsync(Fixture run, bool paged)
    {
        using var direct = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        await run.Rendezvous.CreateOwner().RunAsync(run.Rendezvous.CreateTransport(direct));
        using var delegated = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        await run.RegisterAsync(delegated);
        FdoRendezvousRegistration owner = direct.StoredRegistration!;
        FdoRendezvousRegistration leaf = delegated.StoredRegistration!;
        if (paged)
        {
            run.Rendezvous.MaxMessageSize = (ushort)(4 + Math.Max(owner.SignedRedirect.Length, leaf.SignedRedirect.Length));
        }

        return (owner, leaf);
    }

    [Test]
    [Arguments("dns")]
    [Arguments("ip")]
    [Arguments("both")]
    [Arguments("direct")]
    [Arguments("count")]
    public async Task ExtraAddressesRejectInvalidOrDuplicateRoutesBeforeTheExchange(string invalid)
    {
        using var run = new Fixture();
        var dns = new FdoRendezvousAddress(null, "b\u00fccher.example", 443, FdoRendezvousTransportProtocol.Https);
        var ip = new FdoRendezvousAddress(new byte[] { 192, 0, 2, 1 }, null, 443, FdoRendezvousTransportProtocol.Https);
        run.Rendezvous.Address = invalid == "ip" ? ip : dns;
        FdoRendezvousAddress[] extras = invalid switch
        {
            "dns" => [new(null, "XN--BCHER-KVA.example", 443, FdoRendezvousTransportProtocol.Https)],
            "ip" => [new(IPAddress.Parse("::ffff:192.0.2.1").GetAddressBytes(), null, 443, FdoRendezvousTransportProtocol.Https)],
            "both" => [new(new byte[] { 192, 0, 2, 1 }, "both.example", 443, FdoRendezvousTransportProtocol.Https)],
            "count" => [ip, ip, ip],
            _ => [ip],
        };
        Exception failure = await CaptureAsync(() =>
        {
            _ = invalid == "direct" ? run.Rendezvous.CreateOwner(additionalAddresses: extras) :
                run.Rendezvous.CreateOwner(delegateKey: run.Key, delegateCertificates: [run.Leaf], additionalAddresses: extras);
            return Task.CompletedTask;
        });
        await Assert.That(invalid is "direct" or "count" ? failure is ArgumentException : failure is CborContentException)
            .IsTrue();
        await Assert.That(run.Admission.Seen).IsNull();
        await Assert.That((await run.Store.ReadAsync(run.DeviceId, default)).Revision).IsNull();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task HttpOwnerSignUsesTheRequestSourceAndOnlyReturns104ForMissingPermission(bool missingPermission)
    {
        using var run = new Fixture();
        using var server = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        using var binding = FdoHttpServerSession.ForRendezvous(server);
        using var helloBody = new MemoryStream(run.Rendezvous.Codec.EncodeInitial(20, delegated: true).ToArray());
        FdoHttpServerResponse hello = await binding.ProcessAsync(new FdoHttpServerRequest
        {
            Method = "POST",
            Target = "/fdo/200/msg/20",
            ContentTypeValues = ["application/cbor"],
            Body = helloBody,
            ObservedSource = IPAddress.Parse("192.0.2.90"),
        });
        binding.ConfirmResponseSent();
        ReadOnlyMemory<byte> nonce = run.Rendezvous.Codec.ReadInitial(21, hello.EncodedBody, true).GuidOrNonce!.Value;
        using var ownerSignBody = new MemoryStream(run.Rendezvous.Codec.EncodeOwnerSign(
            run.Rendezvous.EncodeVoucher(), 120, nonce, run.Rendezvous.Address, FdoHashAlgorithm.Sha256, run.Key,
            new FdoX5ChainCodec().Encode([missingPermission
                ? run.Certificate(FdoDelegateChainVerifier.OnboardReuseCredentialsOid) : run.Leaf])).ToArray());
        FdoHttpServerResponse accepted = await binding.ProcessAsync(new FdoHttpServerRequest
        {
            Method = "POST",
            Target = "/fdo/200/msg/22",
            ContentTypeValues = ["application/cbor"],
            AuthorizationValues = [hello.Authorization],
            Body = ownerSignBody,
            ObservedSource = IPAddress.Parse("192.0.2.10"),
        });
        if (missingPermission)
        {
            await Assert.That(accepted.StatusCode).IsEqualTo(500);
            await Assert.That(accepted.MessageType).IsEqualTo((ushort)255);
            await Assert.That(accepted.Authorization).IsEqualTo(hello.Authorization);
            await Assert.That(accepted.IsTerminal).IsTrue();
            var error = new FdoErrorMessageCodec().Decode(accepted.EncodedBody);
            await Assert.That(error.ErrorCode).IsEqualTo((ushort)104);
            await Assert.That(error.PreviousMessageId).IsEqualTo((byte)22);
            await Assert.That(run.Admission.Seen).IsNull();
            await Assert.That(server.AttemptedMutation).IsNull();
            await Assert.That(server.RegistrationWriteStarted).IsFalse();
            return;
        }

        binding.ConfirmResponseSent();
        await Assert.That(accepted.MessageType).IsEqualTo((ushort)FdoRendezvousMessageType.AcceptOwner);
        await Assert.That(run.Admission.Seen!.DelegateSource!.ToString()).IsEqualTo("192.0.2.10");
        await Assert.That(server.AttemptedMutation!.Record.DelegateSource!.ToString()).IsEqualTo("192.0.2.10");
    }

    [Test]
    public async Task OfflineRendezvousStatusBlocksAdmissionAndIsRecheckedBeforeReturningABlob()
    {
        using var run = new Fixture();
        var source = new OfflineStatusFixture(run.Rendezvous.Clock);
        bool revoked = true;
        source.Transform = statuses => revoked
            ? [statuses[0] with { Status = FdoDelegateCertificateStatus.Revoked }] : statuses;
        using var denied = run.Rendezvous.CreateServer(
            FdoRendezvousProtocol.OwnerRegistration, run.Store, run.Admission, source.Policy);
        await ExpectAsync<CryptographicException>(async () => await run.RegisterAsync(denied));
        await Assert.That(source.Calls).IsEqualTo(1);
        await Assert.That(run.Admission.Seen).IsNull();
        await Assert.That(denied.RegistrationWriteStarted).IsFalse();

        revoked = false;
        using var registration = run.Rendezvous.CreateServer(
            FdoRendezvousProtocol.OwnerRegistration, run.Store, run.Admission, source.Policy);
        var ownerTransport = run.Rendezvous.CreateTransport(registration);
        ownerTransport.OwnerSignSource = IPAddress.Loopback;
        await run.Rendezvous.CreateOwner(delegateKey: run.Key, delegateCertificates: [run.Leaf], offlineRevocation: source.Policy)
            .RunAsync(ownerTransport);
        await Assert.That(source.Calls).IsEqualTo(4);
        using var lookup = run.Rendezvous.CreateServer(
            FdoRendezvousProtocol.DeviceLookup, run.Store, offlineRevocation: source.Policy);
        var lookupTransport = run.Rendezvous.CreateTransport(lookup);
        lookupTransport.Change = message =>
        {
            if (message.Type == FdoRendezvousMessageType.DeviceHelloAck)
            {
                revoked = true;
            }

            return message;
        };
        await ExpectAsync<CryptographicException>(async () =>
            await run.Rendezvous.CreateDevice(delegated: true).RunAsync(lookupTransport));
        await Assert.That(source.Calls).IsEqualTo(6);
        await Assert.That(lookupTransport.Messages.Count).IsEqualTo(3);
        await Assert.That(lookup.FinalResponseHandoffConfirmed).IsFalse();
    }

    [Test]
    public async Task DiscoversOnlyEligibleRecordsAndForwardsTheExactSignedBlob()
    {
        using var run = new Fixture();
        using var delegated = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        await Assert.That(await run.RegisterAsync(delegated)).IsEqualTo(120U);
        var stored = delegated.StoredRegistration!;
        FdoRendezvousRegistrationEvidence admitted = run.Admission.Seen!;
        await Assert.That(admitted.DelegateSource!.ToString()).IsEqualTo("192.0.2.10");
        var keys = new FdoPublicKeyCodec();
        await Assert.That(admitted.SigningKey.Span.SequenceEqual(keys.Encode(run.Key).Span)).IsTrue();
        await Assert.That(await run.Store.HasCommittedAsync(delegated.AttemptedMutation!, default)).IsTrue();

        using var unsupported = run.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        var noDelegate = run.Rendezvous.CreateTransport(unsupported);
        await ExpectAsync<InvalidOperationException>(async () => await run.Rendezvous.CreateDevice().RunAsync(noDelegate));
        await Assert.That(noDelegate.Messages.Count).IsEqualTo(1);

        using var lookup = run.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        var transport = run.Rendezvous.CreateTransport(lookup);
        FdoDeviceRendezvousResult candidate = await run.Rendezvous.CreateDevice(true).RunAsync(transport);
        await Assert.That(candidate.SignedRedirect.Span.SequenceEqual(stored.SignedRedirect.Span)).IsTrue();
        await Assert.That(FdoRendezvousCodec.IsDelegated(
            run.Rendezvous.Codec.ReadInitial(31, transport.Messages[1].Body, true).CapabilityFlags)).IsTrue();

        using var direct = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        await run.Rendezvous.CreateOwner().RunAsync(run.Rendezvous.CreateTransport(direct));
        using var directLookup = run.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        FdoDeviceRendezvousResult directCandidate = await run.Rendezvous.CreateDevice().RunAsync(
            run.Rendezvous.CreateTransport(directLookup));
        await Assert.That(directCandidate.SignedRedirect.Span.SequenceEqual(direct.StoredRegistration!.SignedRedirect.Span)).IsTrue();

        using var ambiguous = run.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        var ambiguousTransport = run.Rendezvous.CreateTransport(ambiguous);
        await ExpectAsync<NotSupportedException>(async () =>
            await run.Rendezvous.CreateDevice(true).RunAsync(ambiguousTransport));
        await Assert.That(ambiguousTransport.Messages.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("hash")]
    [Arguments("proof")]
    [Arguments("capability")]
    [Arguments("source")]
    public async Task InvalidOwnerSignNeverReachesAdmissionOrStorage(string reason)
    {
        using var run = new Fixture();
        using var server = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        FdoRendezvousResponse hello = await server.ProcessAsync(
            200, FdoRendezvousMessageType.OwnerHello, run.Rendezvous.Codec.EncodeInitial(20, delegated: true),
            IPAddress.Loopback, default);
        server.ConfirmResponseSent();
        byte[] nonce = run.Rendezvous.Codec.ReadInitial(21, hello.EncodedBody, true).GuidOrNonce!.Value.ToArray();
        if (reason == "nonce")
        {
            nonce[0] ^= 1;
        }

        using ECDsa wrong = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] cert = run.Certificate(FdoDelegateChainVerifier.OnboardReuseCredentialsOid);
        ReadOnlyMemory<byte> signed = run.Rendezvous.Codec.EncodeOwnerSign(
            run.Rendezvous.EncodeVoucher(), 120, nonce, run.Rendezvous.Address, FdoHashAlgorithm.Sha256,
            reason == "proof" ? wrong : run.Key, new FdoX5ChainCodec().Encode([cert]));
        if (reason is "hash" or "capability")
        {
            signed = ChangeSubmission(signed, reason == "capability");
        }

        Exception failure = await CaptureAsync(async () => await server.ProcessAsync(
            200, FdoRendezvousMessageType.OwnerSign, signed, reason == "source" ? null : IPAddress.Loopback, default));
        await Assert.That(reason switch
        {
            "capability" => failure is NotSupportedException,
            "source" => failure is InvalidOperationException,
            _ => failure is CryptographicException and not FdoDelegateChainException,
        }).IsTrue();
        await Assert.That(run.Admission.Seen).IsNull();
        await Assert.That(server.RegistrationWriteStarted).IsFalse();
        await Assert.That((await run.Store.ReadAsync(run.DeviceId, default)).Revision).IsNull();
    }

    [Test]
    [Arguments(0x05)]
    [Arguments(0x06)]
    [Arguments(0x07)]
    [Arguments(0x85)]
    [Arguments(0x86)]
    [Arguments(0x87)]
    public async Task ServerSelectsOnlyFdo20FromKnownHelloOffers(int offer)
    {
        using var run = new Fixture();
        bool delegated = (offer & 0x80) != 0;
        byte selected = delegated ? (byte)0x84 : (byte)0x04;
        using var registration = delegated
            ? run.CreateServer(FdoRendezvousProtocol.OwnerRegistration)
            : run.Rendezvous.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        var ownerTransport = Offer(registration, FdoRendezvousMessageType.OwnerHello);
        ownerTransport.OwnerSignSource = IPAddress.Loopback;
        FdoOwnerRendezvousSession owner = delegated
            ? run.Rendezvous.CreateOwner(delegateKey: run.Key, delegateCertificates: [run.Leaf])
            : run.Rendezvous.CreateOwner();
        await owner.RunAsync(ownerTransport);
        await Assert.That(Flags(ownerTransport.Messages[0].Body)).IsEqualTo(selected);
        await Assert.That(Flags(ownerTransport.Messages[1].Body)).IsEqualTo(selected);
        await Assert.That(Flags(ownerTransport.Messages[2].Body)).IsEqualTo(selected);

        using var lookup = delegated
            ? run.CreateServer(FdoRendezvousProtocol.DeviceLookup)
            : run.Rendezvous.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        var deviceTransport = Offer(lookup, FdoRendezvousMessageType.DeviceHello);
        FdoDeviceRendezvousResult result = await run.Rendezvous.CreateDevice(delegated).RunAsync(deviceTransport);
        await Assert.That(Flags(deviceTransport.Messages[0].Body)).IsEqualTo(selected);
        await Assert.That(Flags(deviceTransport.Messages[1].Body)).IsEqualTo(selected);
        await Assert.That(result.SignedRedirect.Span.SequenceEqual(registration.StoredRegistration!.SignedRedirect.Span)).IsTrue();

        RendezvousFixture.TestTransport Offer(FdoRendezvousServerSession server, FdoRendezvousMessageType hello)
        {
            var transport = run.Rendezvous.CreateTransport(server);
            transport.Change = message => message.Type == hello
                ? message with { Body = RewriteInitial(message, [(byte)offer]) }
                : message;
            return transport;
        }
    }

    [Test]
    [Arguments("legacy")]
    [Arguments("reserved")]
    [Arguments("extended")]
    [Arguments("vendor")]
    [Arguments("delegation")]
    public async Task InvalidHelloOffersStopBothServerRolesBeforeStoreAccess(string invalid)
    {
        using var run = new Fixture();
        byte[] flags = invalid switch
        {
            "legacy" => [0x03],
            "reserved" => [0x0d],
            "extended" => [0x05, 0x01],
            "delegation" => [0x85],
            _ => [0x05],
        };
        foreach (bool device in new[] { false, true })
        {
            using var server = run.Rendezvous.CreateServer(device
                ? FdoRendezvousProtocol.DeviceLookup : FdoRendezvousProtocol.OwnerRegistration);
            FdoRendezvousMessageType type = device ? FdoRendezvousMessageType.DeviceHello : FdoRendezvousMessageType.OwnerHello;
            var hello = new CborWriter(CborConformanceMode.Canonical);
            hello.WriteStartArray(device ? 3 : 2);
            hello.WriteByteString(flags);
            hello.WriteStartArray(invalid == "vendor" ? 1 : 0);
            if (invalid == "vendor")
            {
                hello.WriteTextString("test.example");
            }

            hello.WriteEndArray();
            if (device)
            {
                hello.WriteByteString(run.Authentication.Voucher.Guid);
            }

            hello.WriteEndArray();
            Exception failure = await CaptureAsync(async () => await server.ProcessAsync(200, type, hello.Encode()));
            await Assert.That(invalid == "reserved" ? failure is CborContentException : failure is NotSupportedException)
                .IsTrue();
            await Assert.That(server.RegistrationWriteStarted).IsFalse();
        }

        await Assert.That(run.Rendezvous.Store.Reads).IsEqualTo(0);
        await Assert.That(run.Rendezvous.Store.Writes).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AdmissionDenialOrCancellationCannotWrite(bool cancel)
    {
        using var run = new Fixture();
        using var cancellation = new CancellationTokenSource();
        run.Admission.Deny = !cancel;
        run.Admission.OnAuthorize = cancel ? cancellation.Cancel : null;
        using var server = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        Exception failure = await CaptureAsync(async () => await run.RegisterAsync(server, cancellation.Token));
        await Assert.That(cancel ? failure is OperationCanceledException : failure is InvalidOperationException).IsTrue();
        await Assert.That(run.Admission.Seen).IsNotNull();
        await Assert.That(server.RegistrationWriteStarted).IsFalse();
        await Assert.That((await run.Store.ReadAsync(run.DeviceId, default)).Revision).IsNull();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task LookupNeverReturnsAnExpiredOrChangedSnapshot(bool expire)
    {
        using var run = new Fixture();
        using var registration = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        await run.RegisterAsync(registration);
        using var lookup = run.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        FdoRendezvousResponse ack = await lookup.ProcessAsync(200, FdoRendezvousMessageType.DeviceHello,
            run.Rendezvous.Codec.EncodeInitial(30, run.Authentication.Voucher.Guid, true));
        lookup.ConfirmResponseSent();
        if (expire)
        {
            run.Rendezvous.Clock.Now = run.Disk.Now = run.Disk.Now.AddSeconds(120);
        }
        else
        {
            using var replacement = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
            await run.RegisterAsync(replacement);
        }

        ReadOnlyMemory<byte> nonce = run.Rendezvous.Codec.ReadInitial(31, ack.EncodedBody, true).GuidOrNonce!.Value;
        ReadOnlyMemory<byte> proof = run.Rendezvous.Codec.SignDeviceProof(
            run.Authentication.Voucher.Guid, nonce, run.Authentication.DeviceSigningKey);
        await ExpectAsync<InvalidOperationException>(async () =>
            await lookup.ProcessAsync(200, FdoRendezvousMessageType.ProveToRendezvous, proof));
        await Assert.That(lookup.FinalResponseHandoffConfirmed).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ARemovedDelegationCapabilityDoesNotRestartOrProceed(bool device)
    {
        using var run = new Fixture();
        using var registration = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        if (device)
        {
            await run.RegisterAsync(registration);
        }

        using var lookup = run.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        var transport = run.Rendezvous.CreateTransport(device ? lookup : registration);
        transport.OwnerSignSource = IPAddress.Loopback;
        transport.Change = message =>
        {
            if (message.Type is not (FdoRendezvousMessageType.OwnerHelloAck or FdoRendezvousMessageType.DeviceHelloAck))
            {
                return message;
            }

            var ack = run.Rendezvous.Codec.ReadInitial((ushort)message.Type, message.Body, true);
            return message with { Body = run.Rendezvous.Codec.EncodeInitial((ushort)message.Type, ack.GuidOrNonce) };
        };
        await ExpectAsync<NotSupportedException>(async () =>
        {
            if (device)
            {
                await run.Rendezvous.CreateDevice(true).RunAsync(transport);
            }
            else
            {
                await run.Rendezvous.CreateOwner(delegateKey: run.Key, delegateCertificates: [run.Leaf]).RunAsync(transport);
            }
        });
        await Assert.That(transport.Messages.Count).IsEqualTo(2);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task MixedAcknowledgmentIsNotAcceptedAsAnExactSelection(bool device)
    {
        using var run = new Fixture();
        using var registration = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        if (device)
        {
            await run.RegisterAsync(registration);
        }

        using var lookup = run.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        var transport = run.Rendezvous.CreateTransport(device ? lookup : registration);
        transport.Change = message =>
            message.Type is FdoRendezvousMessageType.OwnerHelloAck or FdoRendezvousMessageType.DeviceHelloAck
                ? message with { Body = RewriteInitial(message, [0x87]) } : message;
        await ExpectAsync<NotSupportedException>(async () =>
        {
            if (device)
            {
                await run.Rendezvous.CreateDevice(true).RunAsync(transport);
            }
            else
            {
                await run.Rendezvous.CreateOwner(delegateKey: run.Key, delegateCertificates: [run.Leaf]).RunAsync(transport);
            }
        });
        await Assert.That(transport.Messages.Count).IsEqualTo(2);
    }

    [Test]
    public async Task MixedOwnerSignIsRejectedBeforeAdmissionEvenAfterAMixedHello()
    {
        using var run = new Fixture();
        using var server = run.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        var transport = run.Rendezvous.CreateTransport(server);
        transport.OwnerSignSource = IPAddress.Loopback;
        transport.Change = message => message.Type switch
        {
            FdoRendezvousMessageType.OwnerHello => message with { Body = RewriteInitial(message, [0x85]) },
            FdoRendezvousMessageType.OwnerSign => message with { Body = ChangeSubmission(message.Body, true, 0x85) },
            _ => message,
        };
        await ExpectAsync<NotSupportedException>(async () =>
            await run.Rendezvous.CreateOwner(delegateKey: run.Key, delegateCertificates: [run.Leaf]).RunAsync(transport));
        await Assert.That(Flags(transport.Messages[1].Body)).IsEqualTo((byte)0x84);
        await Assert.That(Flags(transport.Messages[2].Body)).IsEqualTo((byte)0x84);
        await Assert.That(run.Admission.Seen).IsNull();
        await Assert.That(server.RegistrationWriteStarted).IsFalse();
        await Assert.That((await run.Store.ReadAsync(run.DeviceId, default)).Revision).IsNull();
    }

    private static ReadOnlyMemory<byte> RewriteInitial(RendezvousFixture.TestMessage message, byte[] flags)
    {
        var codec = new FdoInitialMessageCodec();
        var initial = codec.Decode((ushort)message.Type, message.Body);
        return codec.Encode(initial with { CapabilityFlags = flags });
    }

    private static byte Flags(ReadOnlyMemory<byte> body)
    {
        var reader = new CborReader(body);
        reader.ReadStartArray();
        return reader.ReadByteString()[0];
    }

    private static byte[] ChangeSubmission(ReadOnlyMemory<byte> body, bool changeCapability, byte flags = 0x04)
    {
        var reader = new CborReader(body, CborConformanceMode.Canonical);
        reader.ReadStartArray();
        byte[] capability = reader.ReadByteString();
        ReadOnlyMemory<byte> vendors = reader.ReadEncodedValue();
        byte[] to0 = reader.ReadByteString();
        ReadOnlyMemory<byte> signed = reader.ReadEncodedValue();
        if (changeCapability)
        {
            capability[0] = flags;
        }
        else
        {
            var data = new CborReader(to0, CborConformanceMode.Canonical);
            data.ReadStartArray();
            ReadOnlyMemory<byte> voucher = data.ReadEncodedValue();
            uint wait = data.ReadUInt32();
            byte[] nonce = data.ReadByteString();
            var changed = new CborWriter(CborConformanceMode.Canonical);
            changed.WriteStartArray(3);
            changed.WriteEncodedValue(voucher.Span);
            changed.WriteUInt32(wait + 1);
            changed.WriteByteString(nonce);
            changed.WriteEndArray();
            to0 = changed.Encode();
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(4);
        writer.WriteByteString(capability);
        writer.WriteEncodedValue(vendors.Span);
        writer.WriteByteString(to0);
        writer.WriteEncodedValue(signed.Span);
        writer.WriteEndArray();
        return writer.Encode();
    }

    private static async Task ExpectAsync<TException>(Func<Task> action) where TException : Exception =>
        await Assert.That(await CaptureAsync(action) is TException).IsTrue();

    private static async Task<Exception> CaptureAsync(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception e)
        {
            return e;
        }

        throw new InvalidOperationException("The operation was expected to fail.");
    }

    private sealed class Fixture : IDisposable
    {
        public Fixture()
        {
            Rendezvous = new RendezvousFixture(Authentication);
            Disk.Now = Rendezvous.Clock.Now;
            Store = Disk.Open();
            Leaf = Certificate(FdoDelegateChainVerifier.RedirectOid);
        }

        public AuthenticationFixture Authentication { get; } = new();
        public ECDsa Key { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public FdoAtomicRendezvousStoreTests.TestDisk Disk { get; } = new();
        public RendezvousFixture Rendezvous { get; }
        public IFdoAtomicRendezvousRegistrationStore Store { get; }
        public Admission Admission { get; } = new();
        public byte[] Leaf { get; }
        public Guid DeviceId => new(Authentication.Voucher.Guid, bigEndian: true);

        public byte[] Certificate(string permission)
        {
            var request = new CertificateRequest("CN=Redirect Delegate", Key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(permission) }, false));
            using X509Certificate2 certificate = request.Create(
                new X500DistinguishedName("CN=Voucher Owner"),
                X509SignatureGenerator.CreateForECDsa(Authentication.Voucher.FinalOwner),
                Disk.Now.AddDays(-1), Disk.Now.AddDays(1), RandomNumberGenerator.GetBytes(16));
            return certificate.RawData;
        }

        public FdoRendezvousServerSession CreateServer(FdoRendezvousProtocol protocol) =>
            Rendezvous.CreateServer(protocol, Store, Admission);

        public ValueTask<uint> RegisterAsync(FdoRendezvousServerSession server, CancellationToken cancellationToken = default)
        {
            var transport = Rendezvous.CreateTransport(server);
            transport.OwnerSignSource = IPAddress.Parse("::ffff:192.0.2.10");
            return Rendezvous.CreateOwner(delegateKey: Key, delegateCertificates: [Leaf]).RunAsync(transport, cancellationToken);
        }

        public void Dispose()
        {
            Authentication.Dispose();
            Key.Dispose();
            Disk.Dispose();
        }
    }

    internal sealed class Admission : IFdoRendezvousRegistrationAdmission
    {
        private readonly Guid _identity = Guid.NewGuid();
        public FdoRendezvousRegistrationEvidence? Seen { get; private set; }
        public bool Deny { get; set; }
        public Action? OnAuthorize { get; set; }

        public ValueTask<FdoRendezvousRegistrationGrant?> AuthorizeAsync(
            FdoRendezvousRegistrationEvidence evidence, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Seen = evidence;
            OnAuthorize?.Invoke();
            return ValueTask.FromResult<FdoRendezvousRegistrationGrant?>(Deny ? null : new(_identity));
        }
    }
}
