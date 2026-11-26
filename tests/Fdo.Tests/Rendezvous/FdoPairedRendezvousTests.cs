using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Initialization;
using Fdo.Ownership;
using Fdo.Rendezvous;
using Fdo.Serialization;
using Fdo.Tests.Transport;
using Fdo.Transport;
using Fdo.Transport.Http;
using AuthenticationFixture = Fdo.Tests.Cryptography.FdoTo2OwnerDeviceAuthenticatorTests.Fixture;

namespace Fdo.Tests.Rendezvous;

[UnsupportedOSPlatform("browser")]
public sealed class FdoPairedRendezvousTests
{
    [Test]
    [Arguments(2048, false)]
    [Arguments(2048, true)]
    [Arguments(3072, false)]
    public async Task RegistersAndLooksUpAnAuthenticatedRsaOwner(int keySize, bool restricted)
    {
        using var authentication = new AuthenticationFixture();
        using RSA manufacturer = RSA.Create(keySize);
        using RSA ownerKey = RSA.Create(keySize);
        using RSA wrongOwner = RSA.Create(keySize);
        var keys = new FdoPublicKeyCodec();
        ReadOnlyMemory<byte> manufacturerKey = keys.EncodeRsa(manufacturer, restricted);
        byte[] header = authentication.Voucher.CreateHeaderTag(manufacturerKey: manufacturerKey);
        ReadOnlyMemory<byte> headerContents = new CborReader(header).ReadDefiniteLengthByteString();
        FdoHashValue hmac = FdoHashValue.ComputeHmac(
            authentication.Voucher.HmacAlgorithm, authentication.Voucher.Secret, headerContents.Span);
        ReadOnlyMemory<byte> original = FdoInitializationFields.CreateVoucher(
            header, hmac, authentication.EncodedChain);
        FdoTransferredOwnershipVoucher voucher =
            FdoOwnershipVoucherTransfer.ExtendRsa(original, manufacturer, ownerKey);
        var fixture = new RendezvousFixture(authentication) { TrustedManufacturerKey = manufacturerKey };
        var owner = new FdoOwnerRendezvousSession(new FdoOwnerRendezvousOptions
        {
            EncodedVoucherHeaderTag = voucher.EncodedVoucherHeaderTag,
            EncodedVoucherHeaderHmac = voucher.EncodedVoucherHeaderHmac,
            EncodedVoucherEntries = voucher.EncodedVoucherEntries,
            EncodedDeviceCertificateChain = voucher.EncodedDeviceCertificateChain,
            TrustedManufacturerKey = manufacturerKey,
            DeviceTrustAnchor = authentication.RootCertificate.RawData,
            DeviceRevocationMode = X509RevocationMode.NoCheck,
            OwnerSigningKey = ownerKey,
            OwnerAddress = fixture.Address,
            WaitSeconds = 120,
            MaxMessageSize = 8192,
            UseProvisionalPairedProfile = true,
        });
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);

        uint accepted = await owner.RunAsync(fixture.CreateTransport(server));
        FdoDeviceRendezvousResult result = await fixture.LookupAsync();
        ReadOnlyMemory<byte> encodedOwner = keys.EncodeRsa(ownerKey, restricted);
        FdoRendezvousAddress authenticated = fixture.Codec.VerifyRedirect(result.SignedRedirect, encodedOwner);

        await Assert.That(accepted).IsEqualTo(120U);
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);
        await Assert.That(fixture.Store.LastWritten!.EncodedOwnerKey.Span.SequenceEqual(encodedOwner.Span)).IsTrue();
        await Assert.That(authenticated.DnsName).IsEqualTo(fixture.Address.DnsName);
        await Assert.That(Throws<CryptographicException>(() =>
            fixture.Codec.VerifyRedirect(result.SignedRedirect, keys.EncodeRsa(wrongOwner, restricted)))).IsTrue();
    }

    [Test]
    public async Task HttpBindingRequiresItsOwnTokenAndConfirmedHandoff()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        using var binding = FdoHttpServerSession.ForRendezvous(server, 8192);
        ReadOnlyMemory<byte> helloBody = fixture.Codec.EncodeInitial(20);

        FdoTransportException initialToken = await CatchAsync<FdoTransportException>(async () =>
            await binding.ProcessAsync(HttpRequest("/fdo/200/msg/20", helloBody, ["Bearer unexpected"])));
        await Assert.That(initialToken.Failure).IsEqualTo(FdoTransportFailure.Authorization);
        FdoHttpServerResponse hello = await binding.ProcessAsync(HttpRequest("/fdo/200/msg/20", helloBody));
        await CatchAsync<InvalidOperationException>(async () =>
            await binding.ProcessAsync(HttpRequest("/fdo/200/msg/22", helloBody, [hello.Authorization])));
        binding.ConfirmResponseSent();

        ReadOnlyMemory<byte> nonce = fixture.Codec.ReadInitial(21, hello.EncodedBody).GuidOrNonce!.Value;
        ReadOnlyMemory<byte> ownerSign = fixture.OwnerSign(nonce);
        foreach (string[] values in new[]
        {
            Array.Empty<string>(), new[] { "Bearer wrong" }, new[] { hello.Authorization, hello.Authorization },
        })
        {
            FdoTransportException error = await CatchAsync<FdoTransportException>(async () =>
                await binding.ProcessAsync(HttpRequest("/fdo/200/msg/22", ownerSign, values)));
            await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.Authorization);
        }

        FdoHttpServerResponse accepted = await binding.ProcessAsync(
            HttpRequest("/fdo/200/msg/22", ownerSign, [hello.Authorization]));
        await Assert.That(accepted.MessageType).IsEqualTo((ushort)23);
        await Assert.That(accepted.Authorization).IsEqualTo(hello.Authorization);
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);
        await Assert.That(server.FinalResponseHandoffConfirmed).IsFalse();
        await Assert.That(binding.IsComplete).IsFalse();
        binding.ConfirmResponseSent();
        await Assert.That(server.FinalResponseHandoffConfirmed).IsTrue();
        await Assert.That(binding.IsComplete).IsTrue();
        await CatchAsync<InvalidOperationException>(async () =>
            await binding.ProcessAsync(HttpRequest("/fdo/200/msg/22", ownerSign, [hello.Authorization])));
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);
    }

    [Test]
    public async Task HttpBindingRejectsAnotherRunsTokenWithoutAdvancing()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using var first = FdoHttpServerSession.ForRendezvous(
            fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration), 8192);
        using var second = FdoHttpServerSession.ForRendezvous(
            fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration), 8192);
        ReadOnlyMemory<byte> helloBody = fixture.Codec.EncodeInitial(20);
        FdoHttpServerResponse firstHello = await first.ProcessAsync(HttpRequest("/fdo/200/msg/20", helloBody));
        FdoHttpServerResponse secondHello = await second.ProcessAsync(HttpRequest("/fdo/200/msg/20", helloBody));
        first.ConfirmResponseSent();
        second.ConfirmResponseSent();
        ReadOnlyMemory<byte> nonce = fixture.Codec.ReadInitial(21, firstHello.EncodedBody).GuidOrNonce!.Value;
        ReadOnlyMemory<byte> ownerSign = fixture.OwnerSign(nonce);

        FdoTransportException error = await CatchAsync<FdoTransportException>(async () =>
            await first.ProcessAsync(HttpRequest("/fdo/200/msg/22", ownerSign, [secondHello.Authorization])));

        await Assert.That(firstHello.Authorization).IsNotEqualTo(secondHello.Authorization);
        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.Authorization);
        await Assert.That(fixture.Store.Writes).IsEqualTo(0);
        FdoHttpServerResponse accepted = await first.ProcessAsync(
            HttpRequest("/fdo/200/msg/22", ownerSign, [firstHello.Authorization]));
        await Assert.That(accepted.MessageType).IsEqualTo((ushort)23);
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);
        first.ConfirmResponseSent();
    }

    [Test]
    [Arguments("GET", "/fdo/200/msg/20", "application/cbor")]
    [Arguments("POST", "/fdo/201/msg/20", "application/cbor")]
    [Arguments("POST", "/fdo/200/msg/020", "application/cbor")]
    [Arguments("POST", "/fdo/200/msg/30", "application/cbor")]
    [Arguments("POST", "/fdo/200/msg/20?x=1", "application/cbor")]
    [Arguments("POST", "/fdo/200/msg/20", "application/json")]
    public async Task HttpBindingRejectsNoncanonicalRoutesAndContentTypes(
        string method, string target, string contentType)
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        using var binding = FdoHttpServerSession.ForRendezvous(server, 8192);
        ReadOnlyMemory<byte> body = fixture.Codec.EncodeInitial(20);

        FdoTransportException error = await CatchAsync<FdoTransportException>(async () =>
            await binding.ProcessAsync(HttpRequest(target, body, method: method, contentTypes: [contentType])));
        FdoHttpServerResponse response = await binding.ProcessAsync(HttpRequest("/fdo/200/msg/20", body));

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.InvalidRequest);
        await Assert.That(response.MessageType).IsEqualTo((ushort)21);
        binding.ConfirmResponseSent();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task HttpBindingBoundsDeclaredAndUnknownLengthBodies(bool unknownLength)
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        using var binding = FdoHttpServerSession.ForRendezvous(server, 4);
        using var body = new MemoryStream(new byte[10], writable: false);
        var request = new FdoHttpServerRequest
        {
            Method = "POST",
            Target = "/fdo/200/msg/20",
            ContentTypeValues = ["application/cbor"],
            ContentLength = unknownLength ? null : 10,
            Body = body,
        };

        FdoTransportException error = await CatchAsync<FdoTransportException>(async () =>
            await binding.ProcessAsync(request));

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.RequestTooLarge);
        await Assert.That(body.Position).IsEqualTo(unknownLength ? 5L : 0L);
        await CatchAsync<ObjectDisposedException>(async () =>
            await binding.ProcessAsync(HttpRequest("/fdo/200/msg/20", fixture.Codec.EncodeInitial(20))));
        await Assert.That(fixture.Store.Writes).IsEqualTo(0);
    }

    [Test]
    public async Task HttpBindingAcceptsUnknownLengthBodyAtItsLimit()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        ReadOnlyMemory<byte> encoded = fixture.Codec.EncodeInitial(20);
        using var binding = FdoHttpServerSession.ForRendezvous(
            fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration), encoded.Length);
        using var body = new MemoryStream(encoded.ToArray(), writable: false);

        FdoHttpServerResponse response = await binding.ProcessAsync(new FdoHttpServerRequest
        {
            Method = "POST",
            Target = "/fdo/200/msg/20",
            ContentTypeValues = ["application/cbor"],
            Body = body,
        });

        await Assert.That(response.MessageType).IsEqualTo((ushort)21);
        await Assert.That(body.Position).IsEqualTo((long)encoded.Length);
        binding.ConfirmResponseSent();
    }

    [Test]
    [Arguments("302 Found", HttpStatusCode.Found)]
    [Arguments("307 Temporary Redirect", HttpStatusCode.TemporaryRedirect)]
    public async Task HttpDeviceLookupExposesRedirectWithoutFollowingIt(
        string status, HttpStatusCode expectedStatus)
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        await fixture.RegisterAsync();
        using var origin = new LoopbackHttpServer();
        using var target = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Uri targetBase = new(target.Address, "onboarding/");
        Uri targetUri = new(targetBase, "fdo/200/msg/30");
        FdoDeviceRendezvousSession device = fixture.CreateDevice();
        Task<RecordedRequest> received = origin.RespondOnceAsync(
            $"{status}\r\nLocation: {targetUri.AbsoluteUri}\r\nAuthorization: Bearer untrusted", [], timeout.Token);

        FdoTransportException error = await CatchAsync<FdoTransportException>(() =>
            FdoHttp.RunDeviceRendezvousAsync(device, origin.Address, 8192, timeout.Token).AsTask());
        RecordedRequest request = await received;

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.RendezvousRedirect);
        await Assert.That(error.StatusCode).IsEqualTo(expectedStatus);
        await Assert.That(error.RedirectLocation).IsEqualTo(targetUri);
        await Assert.That(error.Message.Contains(targetUri.AbsoluteUri, StringComparison.Ordinal)).IsFalse();
        await Assert.That(request.Uri!.AbsolutePath).IsEqualTo("/fdo/200/msg/30");
        await Assert.That(request.Authorization).IsNull();
        await Assert.That(target.HasPendingConnection).IsFalse();
        await CatchAsync<InvalidOperationException>(() =>
            FdoHttp.RunDeviceRendezvousAsync(device, targetBase, 8192, timeout.Token).AsTask());
        await Assert.That(target.HasPendingConnection).IsFalse();

        using var binding = FdoHttpServerSession.ForRendezvous(
            fixture.CreateServer(FdoRendezvousProtocol.DeviceLookup), 8192, "/onboarding");
        Task<IReadOnlyList<RecordedRequest>> serving = target.ServeSessionAsync(binding, timeout.Token);
        FdoDeviceRendezvousResult result =
            await FdoHttp.RunDeviceRendezvousAsync(fixture.CreateDevice(), targetBase, 8192, timeout.Token);
        IReadOnlyList<RecordedRequest> requests = await serving;

        await Assert.That(requests.Count).IsEqualTo(2);
        await Assert.That(requests[0].Uri).IsEqualTo(targetUri);
        await Assert.That(requests[0].Authorization).IsNull();
        await Assert.That(requests[1].Authorization!.StartsWith("Bearer ", StringComparison.Ordinal)).IsTrue();
        await Assert.That(result.SignedRedirect.Span.SequenceEqual(fixture.Store.LastWritten!.SignedRedirect.Span)).IsTrue();
    }

    [Test]
    public async Task HttpDeviceLookupResolvesRelativeRedirectWithoutFollowingIt()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using var origin = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<RecordedRequest> received = origin.RespondOnceAsync(
            "307 Temporary Redirect\r\nLocation: /alternate/fdo/200/msg/30", [], timeout.Token);

        FdoTransportException error = await CatchAsync<FdoTransportException>(() =>
            FdoHttp.RunDeviceRendezvousAsync(fixture.CreateDevice(), origin.Address, 8192, timeout.Token).AsTask());
        await received;

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.RendezvousRedirect);
        await Assert.That(error.RedirectLocation).IsEqualTo(new Uri(origin.Address, "alternate/fdo/200/msg/30"));
        await Assert.That(origin.HasPendingConnection).IsFalse();
    }

    [Test]
    [Arguments("")]
    [Arguments("Location: ftp://rv.example/")]
    [Arguments("Location: https://first.example/\r\nLocation: https://second.example/")]
    public async Task HttpDeviceLookupRejectsInvalidRedirectLocations(string headers)
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using var origin = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        string response = "307 Temporary Redirect" + (headers.Length == 0 ? "" : "\r\n" + headers);
        Task<RecordedRequest> received = origin.RespondOnceAsync(response, [], timeout.Token);

        FdoTransportException error = await CatchAsync<FdoTransportException>(() =>
            FdoHttp.RunDeviceRendezvousAsync(fixture.CreateDevice(), origin.Address, 8192, timeout.Token).AsTask());
        await received;

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.InvalidResponse);
        await Assert.That(error.RedirectLocation).IsNull();
        await Assert.That(origin.HasPendingConnection).IsFalse();
    }

    [Test]
    public async Task HttpBindingRejectsTruncatedAndDuplicateHeaderRequests()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        using var binding = FdoHttpServerSession.ForRendezvous(server, 8192);
        ReadOnlyMemory<byte> body = fixture.Codec.EncodeInitial(20);
        FdoTransportException duplicate = await CatchAsync<FdoTransportException>(async () =>
            await binding.ProcessAsync(HttpRequest(
                "/fdo/200/msg/20", body, contentTypes: ["application/cbor", "application/cbor"])));
        using var shortBody = new MemoryStream(body.ToArray(), writable: false);
        var truncated = new FdoHttpServerRequest
        {
            Method = "POST",
            Target = "/fdo/200/msg/20",
            ContentTypeValues = ["application/cbor"],
            ContentLength = body.Length + 1,
            Body = shortBody,
        };
        FdoTransportException missing = await CatchAsync<FdoTransportException>(async () =>
            await binding.ProcessAsync(truncated));

        await Assert.That(duplicate.Failure).IsEqualTo(FdoTransportFailure.InvalidRequest);
        await Assert.That(missing.Failure).IsEqualTo(FdoTransportFailure.InvalidRequest);
        await CatchAsync<ObjectDisposedException>(async () =>
            await binding.ProcessAsync(HttpRequest("/fdo/200/msg/20", body)));
    }

    [Test]
    [Arguments(256)]
    [Arguments(384)]
    public async Task OwnerRegistersAndDeviceReceivesTheExactSignedBlob(int curveSize)
    {
        using var authentication = new AuthenticationFixture(curveSize);
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession ownerServer = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        RendezvousFixture.TestTransport ownerTransport = fixture.CreateTransport(ownerServer);

        uint accepted = await fixture.CreateOwner().RunAsync(ownerTransport);

        await Assert.That(accepted).IsEqualTo(120U);
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);
        await Assert.That(ownerServer.RegistrationWriteStarted).IsTrue();
        await Assert.That(ownerServer.StoredRegistration).IsNotNull();
        await Assert.That(ownerServer.FinalResponseHandoffConfirmed).IsTrue();
        await Assert.That(ownerTransport.Messages.Select(message => (ushort)message.Type)
            .SequenceEqual(new ushort[] { 20, 21, 22, 23 })).IsTrue();
        FdoRendezvousCodec.OwnerSubmission submitted =
            fixture.Codec.ReadOwnerSign(ownerTransport.Messages[2].Body, 10);
        await Assert.That(fixture.Store.LastWritten!.SignedRedirect.Span
            .SequenceEqual(submitted.SignedRedirect.Span)).IsTrue();
        await Assert.That(fixture.Store.LastWritten.EncodedOwnerKey.Span
            .SequenceEqual(authentication.Voucher.FinalOwnerKey)).IsTrue();

        using FdoRendezvousServerSession deviceServer = fixture.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        RendezvousFixture.TestTransport deviceTransport = fixture.CreateTransport(deviceServer);
        FdoDeviceRendezvousResult result = await fixture.CreateDevice().RunAsync(deviceTransport);

        await Assert.That(deviceTransport.Messages.Select(message => (ushort)message.Type)
            .SequenceEqual(new ushort[] { 30, 31, 32, 33 })).IsTrue();
        await Assert.That(result.SignedRedirect.Span.SequenceEqual(submitted.SignedRedirect.Span)).IsTrue();
        await Assert.That(result.CandidateAddress.DnsName).IsEqualTo("owner.example.test");
        await Assert.That(result.CandidateAddress.IpAddress!.Value.Span
            .SequenceEqual(new byte[] { 192, 0, 2, 1 })).IsTrue();
        await Assert.That(result.CandidateAddress.Port).IsEqualTo((ushort)8443);
        await Assert.That(result.CandidateAddress.Protocol).IsEqualTo(FdoRendezvousTransportProtocol.Https);
        await Assert.That(deviceServer.FinalResponseHandoffConfirmed).IsTrue();
        await Assert.That(fixture.Store.Reads).IsEqualTo(2);
    }

    [Test]
    public async Task ReplayedOwnerSignCannotReuseAnotherSessionsNonce()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession first = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        RendezvousFixture.TestTransport transport = fixture.CreateTransport(first);
        await fixture.CreateOwner().RunAsync(transport);
        ReadOnlyMemory<byte> replay = transport.Messages.Single(
            message => message.Type == FdoRendezvousMessageType.OwnerSign).Body;
        using FdoRendezvousServerSession second = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        await fixture.BeginOwnerAsync(second);

        await CatchAsync<CryptographicException>(async () =>
            await second.ProcessAsync(200, FdoRendezvousMessageType.OwnerSign, replay));
        await CatchAsync<InvalidOperationException>(async () =>
            await second.ProcessAsync(200, FdoRendezvousMessageType.OwnerSign, replay));
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);
        await Assert.That(second.RegistrationWriteStarted).IsFalse();
    }

    [Test]
    public async Task OwnerSignBindsTo0ByteStringContentsNotItsWrapper()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        ReadOnlyMemory<byte> nonce = await fixture.BeginOwnerAsync(server);
        FdoRendezvousCodec.OwnerSubmission submission =
            fixture.Codec.ReadOwnerSign(fixture.OwnerSign(nonce), 10);
        fixture.Codec.VerifyRedirect(
            submission.SignedRedirect, authentication.Voucher.FinalOwnerKey,
            submission.To0Data, FdoHashAlgorithm.Sha256);
        var wrapper = new CborWriter(CborConformanceMode.Canonical);
        wrapper.WriteByteString(submission.To0Data.Span);
        FdoHashValue wrongHash = FdoHashValue.ComputeDigest(FdoHashAlgorithm.Sha256, wrapper.Encode());
        ReadOnlyMemory<byte> wrongBlob = MakeBlob(
            wrongHash, authentication.Voucher.FinalOwner, "valid", FdoSignatureOperation.TO0OwnerSign);

        await CatchAsync<CryptographicException>(async () =>
            await server.ProcessAsync(
                200, FdoRendezvousMessageType.OwnerSign, MakeOwnerSign(submission.To0Data, wrongBlob)));
        await Assert.That(fixture.Store.Writes).IsEqualTo(0);
    }

    [Test]
    [Arguments("entry")]
    [Arguments("certificate")]
    [Arguments("manufacturer")]
    [Arguments("anchor")]
    public async Task ServerRejectsInvalidVoucherOrUntrustedDeviceBeforeStorage(string failure)
    {
        using var authentication = new AuthenticationFixture();
        using var other = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        byte[] entry = (byte[])authentication.Voucher.SecondEntry.Clone();
        if (failure == "entry")
        {
            entry[^1] ^= 1;
        }

        if (failure == "manufacturer")
        {
            fixture.TrustedManufacturerKey = other.Voucher.ManufacturerKey;
        }

        if (failure == "anchor")
        {
            fixture.DeviceTrustAnchor = other.RootCertificate.RawData;
        }

        ReadOnlyMemory<byte> voucher = fixture.EncodeVoucher(
            [authentication.Voucher.FirstEntry, entry],
            failure == "certificate" ? other.EncodedChain : authentication.EncodedChain);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        ReadOnlyMemory<byte> nonce = await fixture.BeginOwnerAsync(server);

        await CatchAsync<CryptographicException>(async () =>
            await server.ProcessAsync(200, FdoRendezvousMessageType.OwnerSign, fixture.OwnerSign(nonce, voucher)));
        await Assert.That(server.RegistrationWriteStarted).IsFalse();
        await Assert.That(fixture.Store.Writes).IsEqualTo(0);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    public async Task ServerRejectsZeroOrExcessVoucherEntriesBeforeStorage(int maximumEntries)
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        ReadOnlyMemory<byte> voucher = maximumEntries == 0 ? fixture.EncodeVoucher([]) : fixture.EncodeVoucher();
        if (maximumEntries == 1)
        {
            fixture.MaxVoucherEntries = 1;
        }

        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        ReadOnlyMemory<byte> nonce = await fixture.BeginOwnerAsync(server);
        await CatchAsync<CborContentException>(async () =>
            await server.ProcessAsync(200, FdoRendezvousMessageType.OwnerSign, fixture.OwnerSign(nonce, voucher)));
        await Assert.That(fixture.Store.Writes).IsEqualTo(0);
    }

    [Test]
    [Arguments("key")]
    [Arguments("domain")]
    [Arguments("tamper")]
    public async Task ServerRequiresTheFinalOwnerSignatureInTheTo0Domain(string failure)
    {
        using var authentication = new AuthenticationFixture();
        using ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        ReadOnlyMemory<byte> nonce = await fixture.BeginOwnerAsync(server);
        FdoRendezvousCodec.OwnerSubmission submission =
            fixture.Codec.ReadOwnerSign(fixture.OwnerSign(nonce), 10);
        FdoHashValue hash = FdoHashValue.ComputeDigest(FdoHashAlgorithm.Sha256, submission.To0Data.Span);
        byte[] blob = MakeBlob(
            hash, failure == "key" ? otherKey : authentication.Voucher.FinalOwner, "valid",
            failure == "domain" ? FdoSignatureOperation.TO2ProveOVHdr : FdoSignatureOperation.TO0OwnerSign);
        if (failure == "tamper")
        {
            blob[^1] ^= 1;
        }

        await CatchAsync<CryptographicException>(async () =>
            await server.ProcessAsync(
                200, FdoRendezvousMessageType.OwnerSign, MakeOwnerSign(submission.To0Data, blob)));
        await Assert.That(fixture.Store.Writes).IsEqualTo(0);
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("guid")]
    [Arguments("key")]
    [Arguments("domain")]
    public async Task DeviceProofRequiresCurrentNonceGuidCertificateKeyAndTo1Domain(string failure)
    {
        using var authentication = new AuthenticationFixture();
        using ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var fixture = new RendezvousFixture(authentication);
        await fixture.RegisterAsync();
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        byte[] nonce = (await fixture.BeginDeviceAsync(server)).ToArray();
        byte[] guid = (byte[])authentication.Voucher.Guid.Clone();
        if (failure == "nonce")
        {
            nonce[0] ^= 1;
        }

        if (failure == "guid")
        {
            guid[0] ^= 1;
        }

        ECDsa key = failure == "key" ? otherKey : authentication.DeviceSigningKey;
        ReadOnlyMemory<byte> proof = failure == "domain"
            ? MakeDeviceProof(guid, nonce, key, FdoSignatureOperation.TO2ProveDevice)
            : fixture.Codec.SignDeviceProof(guid, nonce, key);
        await CatchAsync<CryptographicException>(async () =>
            await server.ProcessAsync(200, FdoRendezvousMessageType.ProveToRendezvous, proof));
        await CatchAsync<InvalidOperationException>(async () =>
            await server.ProcessAsync(200, FdoRendezvousMessageType.ProveToRendezvous, proof));
        await Assert.That(server.FinalResponseHandoffConfirmed).IsFalse();
    }

    [Test]
    [Arguments(-1, true)]
    [Arguments(0, false)]
    [Arguments(1, false)]
    public async Task RegistrationExpiryIsExclusiveAtTheClockBoundary(long ticksAfterExpiry, bool accepted)
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        await fixture.RegisterAsync();
        fixture.Clock.Now = fixture.Store.LastWritten!.ExpiresAt.AddTicks(ticksAfterExpiry);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.DeviceLookup);

        if (accepted)
        {
            ReadOnlyMemory<byte> nonce = await fixture.BeginDeviceAsync(server);
            await Assert.That(nonce.Length).IsEqualTo(16);
        }
        else
        {
            await CatchAsync<InvalidOperationException>(async () => await fixture.BeginDeviceAsync(server));
        }
    }

    [Test]
    public async Task RegistrationExpiringBetweenHelloAndProofDoesNotReturnRedirect()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        await fixture.RegisterAsync();
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        ReadOnlyMemory<byte> nonce = await fixture.BeginDeviceAsync(server);
        fixture.Clock.Now = fixture.Store.LastWritten!.ExpiresAt;
        ReadOnlyMemory<byte> proof =
            fixture.Codec.SignDeviceProof(authentication.Voucher.Guid, nonce, authentication.DeviceSigningKey);

        await CatchAsync<InvalidOperationException>(async () =>
            await server.ProcessAsync(200, FdoRendezvousMessageType.ProveToRendezvous, proof));
        await Assert.That(server.FinalResponseHandoffConfirmed).IsFalse();
    }

    [Test]
    public async Task ReplacingRegistrationDuringTo1RejectsTheOldChallenge()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        await fixture.RegisterAsync();
        Guid firstRegistration = fixture.Store.LastWritten!.RegistrationId;
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        ReadOnlyMemory<byte> nonce = await fixture.BeginDeviceAsync(server);
        fixture.Address = new FdoRendezvousAddress(null, "new-owner.example.test", 443, FdoRendezvousTransportProtocol.Https);
        await fixture.RegisterAsync();
        ReadOnlyMemory<byte> proof =
            fixture.Codec.SignDeviceProof(authentication.Voucher.Guid, nonce, authentication.DeviceSigningKey);

        await CatchAsync<InvalidOperationException>(async () =>
            await server.ProcessAsync(200, FdoRendezvousMessageType.ProveToRendezvous, proof));
        await Assert.That(fixture.Store.LastWritten!.RegistrationId).IsNotEqualTo(firstRegistration);
        FdoDeviceRendezvousResult latest = await fixture.LookupAsync();
        await Assert.That(latest.CandidateAddress.DnsName).IsEqualTo("new-owner.example.test");
    }

    [Test]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task OwnerAddressRoundTripsIpDnsAndCombinedForms(bool includeIp, bool includeDns)
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        byte[] ip = [192, 0, 2, 42];
        fixture.Address = new FdoRendezvousAddress(
            includeIp ? new ReadOnlyMemory<byte>(ip) : (ReadOnlyMemory<byte>?)null,
            includeDns ? "owner.example.test" : null,
            443, FdoRendezvousTransportProtocol.Https);

        await fixture.RegisterAsync();
        FdoRendezvousAddress result = (await fixture.LookupAsync()).CandidateAddress;

        await Assert.That(result.IpAddress.HasValue).IsEqualTo(includeIp);
        if (includeIp)
        {
            await Assert.That(result.IpAddress!.Value.Span.SequenceEqual(ip)).IsTrue();
        }

        await Assert.That(result.DnsName).IsEqualTo(includeDns ? "owner.example.test" : null);
    }

    [Test]
    public async Task AcceptedWaitExcludesTimeSpentInDurableStorage()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        fixture.Store.AfterWrite = () => fixture.Clock.Now = fixture.Clock.Now.AddSeconds(5.2);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);

        uint accepted = await fixture.CreateOwner().RunAsync(fixture.CreateTransport(server));

        await Assert.That(accepted).IsEqualTo(114U);
        await Assert.That(fixture.Store.LastWritten!.ExpiresAt - fixture.Clock.Now)
            .IsEqualTo(TimeSpan.FromSeconds(114.8));
        await Assert.That(server.FinalResponseHandoffConfirmed).IsTrue();
    }

    [Test]
    public async Task StoreDelayPastExpiryProducesNoAcceptanceButReportsStoredRecord()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        fixture.Store.AfterWrite = () => fixture.Clock.Now = fixture.Clock.Now.AddSeconds(120);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        RendezvousFixture.TestTransport transport = fixture.CreateTransport(server);

        await CatchAsync<InvalidOperationException>(async () => await fixture.CreateOwner().RunAsync(transport));

        await Assert.That(server.RegistrationWriteStarted).IsTrue();
        await Assert.That(server.StoredRegistration).IsNotNull();
        await Assert.That(server.FinalResponseHandoffConfirmed).IsFalse();
        await Assert.That(transport.Messages.Any(message => message.Type == FdoRendezvousMessageType.AcceptOwner)).IsFalse();
    }

    [Test]
    public async Task MissingRegistrationStopsTo1BeforeADeviceProof()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        RendezvousFixture.TestTransport transport = fixture.CreateTransport(server);
        FdoDeviceRendezvousSession device = fixture.CreateDevice();

        await CatchAsync<InvalidOperationException>(async () => await device.RunAsync(transport));
        await CatchAsync<InvalidOperationException>(async () => await device.RunAsync(transport));

        await Assert.That(transport.Messages.Select(message => (ushort)message.Type)
            .SequenceEqual(new ushort[] { 30 })).IsTrue();
        await Assert.That(fixture.Store.Reads).IsEqualTo(1);
    }

    [Test]
    public async Task AnUncertainStoreWriteDoesNotProduceAcceptanceOrRetry()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        fixture.Store.ThrowAfterWrite = true;
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        ReadOnlyMemory<byte> nonce = await fixture.BeginOwnerAsync(server);
        ReadOnlyMemory<byte> request = fixture.OwnerSign(nonce);

        await CatchAsync<InvalidOperationException>(async () =>
            await server.ProcessAsync(200, FdoRendezvousMessageType.OwnerSign, request));
        await CatchAsync<InvalidOperationException>(async () =>
            await server.ProcessAsync(200, FdoRendezvousMessageType.OwnerSign, request));
        await Assert.That(server.RegistrationWriteStarted).IsTrue();
        await Assert.That(server.StoredRegistration).IsNull();
        await Assert.That(fixture.Store.LastWritten).IsNotNull();
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);
        await Assert.That(server.FinalResponseHandoffConfirmed).IsFalse();
    }

    [Test]
    public async Task LookupRevalidatesStoredManufacturerAndCertificateTrust()
    {
        using var authentication = new AuthenticationFixture();
        using var other = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        await fixture.RegisterAsync();
        fixture.TrustedManufacturerKey = other.Voucher.ManufacturerKey;
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.DeviceLookup);

        await CatchAsync<CryptographicException>(async () => await fixture.BeginDeviceAsync(server));
        await Assert.That(fixture.Store.Reads).IsEqualTo(1);
        await Assert.That(server.FinalResponseHandoffConfirmed).IsFalse();
    }

    [Test]
    [Arguments("four-fields")]
    [Arguments("null-port")]
    [Arguments("missing-address")]
    [Arguments("preference")]
    [Arguments("bare-null")]
    [Arguments("delegate")]
    [Arguments("protocol")]
    public async Task RejectsAmbiguousOrDelegatedRedirectShapes(string shape)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var codec = new FdoRendezvousCodec();
        FdoHashValue hash = FdoHashValue.ComputeDigest(FdoHashAlgorithm.Sha256, new byte[] { 0x80 });
        byte[] blob = MakeBlob(hash, key, shape, FdoSignatureOperation.TO0OwnerSign);

        bool rejected = shape is "preference" or "delegate"
            ? Throws<NotSupportedException>(() => codec.ReadUntrustedRedirectAddress(blob))
            : Throws<CborContentException>(() => codec.ReadUntrustedRedirectAddress(blob));
        await Assert.That(rejected).IsTrue();
    }

    [Test]
    public async Task RejectsUnexpectedRedirectCountAndMessageLimits()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        await fixture.RegisterAsync();
        byte[] blob = fixture.Store.LastWritten!.SignedRedirect.ToArray();
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteUInt32(2);
        writer.WriteUInt32(0);
        writer.WriteStartArray(1);
        writer.WriteEncodedValue(blob);
        writer.WriteEndArray();
        writer.WriteEndArray();
        await Assert.That(Throws<NotSupportedException>(() => fixture.Codec.ReadRedirect(writer.Encode()))).IsTrue();

        fixture.MaxMessageSize = 10;
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        await CatchAsync<CborContentException>(async () =>
            await server.ProcessAsync(200, FdoRendezvousMessageType.OwnerHello, new byte[11]));
        await Assert.That(server.RegistrationWriteStarted).IsFalse();
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);
    }

    [Test]
    public async Task ServerAcceptsAnExactMessageLimitAndRejectsOneByteLess()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        int size = fixture.OwnerSign(new byte[16]).Length;
        fixture.MaxMessageSize = checked((ushort)size);
        using FdoRendezvousServerSession accepted = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        ReadOnlyMemory<byte> acceptedNonce = await fixture.BeginOwnerAsync(accepted);
        ReadOnlyMemory<byte> acceptedRequest = fixture.OwnerSign(acceptedNonce);
        await Assert.That(acceptedRequest.Length).IsEqualTo(size);

        FdoRendezvousResponse response = await accepted.ProcessAsync(
            200, FdoRendezvousMessageType.OwnerSign, acceptedRequest);
        await Assert.That(response.MessageType).IsEqualTo(FdoRendezvousMessageType.AcceptOwner);
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);

        fixture.MaxMessageSize = checked((ushort)(size - 1));
        using FdoRendezvousServerSession rejected = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        ReadOnlyMemory<byte> rejectedNonce = await fixture.BeginOwnerAsync(rejected);
        ReadOnlyMemory<byte> rejectedRequest = fixture.OwnerSign(rejectedNonce);
        await Assert.That(rejectedRequest.Length).IsEqualTo(size);
        await CatchAsync<CborContentException>(async () =>
            await rejected.ProcessAsync(200, FdoRendezvousMessageType.OwnerSign, rejectedRequest));
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);
    }

    [Test]
    public async Task ServerRequiresHandoffAndTerminatesOnUnexpectedSequence()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        await server.ProcessAsync(200, FdoRendezvousMessageType.OwnerHello, fixture.Codec.EncodeInitial(20));

        await CatchAsync<InvalidOperationException>(async () =>
            await server.ProcessAsync(200, FdoRendezvousMessageType.OwnerSign, new byte[] { 0x80 }));

        await Assert.That(Throws<InvalidOperationException>(server.ConfirmResponseSent)).IsTrue();
        await Assert.That(fixture.Store.Writes).IsEqualTo(0);
    }

    [Test]
    public async Task OwnerRejectsAnAcceptedWaitGreaterThanRequested()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        RendezvousFixture.TestTransport transport = fixture.CreateTransport(server);
        transport.Change = message => message.Type == FdoRendezvousMessageType.AcceptOwner
            ? message with { Body = fixture.Codec.EncodeAcceptOwner(301) } : message;

        await CatchAsync<CborContentException>(async () => await fixture.CreateOwner(300).RunAsync(transport));
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);
        await Assert.That(server.FinalResponseHandoffConfirmed).IsTrue();
    }

    [Test]
    public async Task CancellationEndsTheOwnerRunWithoutSendingOrRetrying()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        RendezvousFixture.TestTransport transport = fixture.CreateTransport(server);
        FdoOwnerRendezvousSession owner = fixture.CreateOwner();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await CatchAsync<OperationCanceledException>(async () => await owner.RunAsync(transport, cancellation.Token));
        await CatchAsync<InvalidOperationException>(async () => await owner.RunAsync(transport));
        await Assert.That(transport.Messages.Count).IsEqualTo(0);
        await Assert.That(fixture.Store.Writes).IsEqualTo(0);
    }

    private static byte[] MakeOwnerSign(ReadOnlyMemory<byte> to0, ReadOnlyMemory<byte> blob)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(4);
        writer.WriteByteString(new byte[] { 4 });
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteByteString(to0.Span);
        writer.WriteEncodedValue(blob.Span);
        writer.WriteEndArray();
        return writer.Encode();
    }

    private static byte[] MakeBlob(
        FdoHashValue hash, ECDsa signer, string shape, FdoSignatureOperation operation)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteStartArray(1);
        writer.WriteStartArray(shape == "four-fields" ? 4 : 5);
        writer.WriteNull();
        if (shape == "missing-address")
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteTextString("owner.example.test");
        }

        if (shape == "null-port")
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteUInt32(443);
        }

        writer.WriteUInt32(shape == "protocol" ? 2U : 5U);
        if (shape != "four-fields")
        {
            if (shape == "preference")
            {
                writer.WriteStartMap(0);
                writer.WriteEndMap();
            }
            else
            {
                writer.WriteNull();
            }
        }

        writer.WriteEndArray();
        writer.WriteEndArray();
        writer.WriteEncodedValue(hash.Encode().Span);
        if (shape == "bare-null")
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteByteString(shape == "delegate" ? new byte[] { 0x80 } : new byte[] { 0xf6 });
        }

        writer.WriteEndArray();
        return new FdoCoseSign1Codec().Sign(
            operation, signer.KeySize == 384 ? FdoCoseSignatureAlgorithm.ES384 : FdoCoseSignatureAlgorithm.ES256,
            signer, writer.Encode()).ToArray();
    }

    private static ReadOnlyMemory<byte> MakeDeviceProof(
        ReadOnlyMemory<byte> guid,
        ReadOnlyMemory<byte> nonce,
        ECDsa key,
        FdoSignatureOperation operation)
    {
        byte[] ueid = new byte[17];
        ueid[0] = 1;
        guid.Span.CopyTo(ueid.AsSpan(1));
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(10);
        writer.WriteByteString(nonce.Span);
        writer.WriteInt32(256);
        writer.WriteByteString(ueid);
        writer.WriteEndMap();
        return new FdoCoseSign1Codec().Sign(
            operation, FdoCoseSignatureAlgorithm.ES256, key, writer.Encode());
    }

    private static FdoHttpServerRequest HttpRequest(
        string target,
        ReadOnlyMemory<byte> body,
        IReadOnlyList<string>? authorization = null,
        string method = "POST",
        IReadOnlyList<string>? contentTypes = null) => new()
    {
        Method = method,
        Target = target,
        AuthorizationValues = authorization ?? [],
        ContentTypeValues = contentTypes ?? ["application/cbor"],
        ContentLength = body.Length,
        Body = new MemoryStream(body.ToArray(), writable: false),
    };

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

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }
}
