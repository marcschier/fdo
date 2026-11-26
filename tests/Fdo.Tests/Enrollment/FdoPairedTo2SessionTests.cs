// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Formats.Cbor;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using Fdo.Cryptography;
using Fdo.Enrollment;
using Fdo.Initialization;
using Fdo.Ownership;
using Fdo.Rendezvous;
using Fdo.Serialization;
using Fdo.ServiceInfo;
using Fdo.Tests.Cryptography;
using Fdo.Tests.Recovery;
using Fdo.Tests.Rendezvous;
using Fdo.Tests.Transport;
using Fdo.Transport;
using Fdo.Transport.Http;
using AuthenticationFixture = Fdo.Tests.Cryptography.FdoTo2OwnerDeviceAuthenticatorTests.Fixture;

namespace Fdo.Tests.Enrollment;

[UnsupportedOSPlatform("browser")]
public sealed class FdoPairedTo2SessionTests
{
    [Test]
    public Task RunsDiTransferTo0To1AndProtectedTo2OverHttp() =>
        RunInitializedHttpCompositionAsync(forgeRedirect: false);

    [Test]
    public Task RejectsAnInitialOwnerSignedTo1RedirectBeforeProtectedTo2OverHttp() =>
        RunInitializedHttpCompositionAsync(forgeRedirect: true);

    private static async Task RunInitializedHttpCompositionAsync(bool forgeRedirect)
    {
        using var fixture = new Fixture();
        using var secret = new RecordingVoucherHmacSecret(FdoDeviceHmacAlgorithm.HmacSha256);
        using var initialization = new InitializationFixture(fixture, secret);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var lookupListener = new LoopbackHttpServer();
        initialization.EncodedRendezvousInfo = EncodeLoopbackRendezvousInfo((ushort)lookupListener.Address.Port);
        using var manufacturingListener = new LoopbackHttpServer();
        Uri manufacturingAddress = new(manufacturingListener.Address, "manufacturing/");
        initialization.AuthorizedHttpAddress = manufacturingAddress;
        using var manufacturingBinding = FdoHttpServerSession.ForManufacturer(
            initialization.Manufacturer, 8192, "/manufacturing");
        Task<IReadOnlyList<RecordedRequest>> manufacturingServing =
            manufacturingListener.ServeSessionAsync(manufacturingBinding, timeout.Token);

        FdoDeviceInitializeCredential credential = await FdoHttp.RunDeviceInitializeAsync(
            initialization.Device, manufacturingAddress, 8192, timeout.Token);
        IReadOnlyList<RecordedRequest> manufacturingRequests = await manufacturingServing;
        FdoManufacturerInitializeVoucher voucher = initialization.Voucher!;
        await Assert.That(manufacturingRequests.Select(request => request.Uri!.AbsolutePath).SequenceEqual(
            new[] { "/manufacturing/fdo/200/msg/10", "/manufacturing/fdo/200/msg/12" })).IsTrue();
        await Assert.That(manufacturingRequests[0].Authorization).IsNull();
        await Assert.That(manufacturingRequests[1].Authorization!.StartsWith(
            "Bearer ", StringComparison.Ordinal)).IsTrue();
        await Assert.That(ReferenceEquals(initialization.InstalledCredential, credential)).IsTrue();
        await Assert.That(ReferenceEquals(credential.VoucherHmacSecret, secret)).IsTrue();
        await Assert.That(voucher.DeviceGuid.Span.SequenceEqual(credential.DeviceGuid.Span)).IsTrue();
        await Assert.That(initialization.Manufacturer.DoneHandoffConfirmed).IsTrue();
        await Assert.That(initialization.Device.DoneReceived).IsTrue();
        await Assert.That(manufacturingBinding.IsComplete).IsTrue();

        using ECDsa approvedOwner = ECDsa.Create(fixture.Auth.Voucher.FinalOwner.ExportParameters(false));
        FdoTransferredOwnershipVoucher transferred = FdoOwnershipVoucherTransfer.Extend(
            voucher.EncodedVoucher, fixture.Auth.Voucher.Manufacturer, approvedOwner);
        await Assert.That(secret.Inputs.Count).IsEqualTo(1);
        await Assert.That(transferred.EncodedVoucherHeaderTag.Span
            .SequenceEqual(voucher.EncodedVoucherHeaderTag.Span)).IsTrue();
        await Assert.That(transferred.EncodedVoucherHeaderHmac.Span
            .SequenceEqual(voucher.EncodedVoucherHeaderHmac.Span)).IsTrue();
        await Assert.That(transferred.EncodedDeviceCertificateChain.Span
            .SequenceEqual(voucher.EncodedDeviceCertificateChain.Span)).IsTrue();
        await Assert.That(transferred.EncodedVoucherEntries.Count).IsEqualTo(1);
        IReadOnlyList<FdoRendezvousServerCandidate> ownerCandidates = FdoRendezvousInfo.ParseVoucherHeader(
            transferred.EncodedVoucherHeaderTag, FdoRendezvousProtocol.OwnerRegistration);
        await Assert.That(ownerCandidates.Count).IsEqualTo(1);
        await Assert.That(ownerCandidates[0].BaseAddress.AbsoluteUri).IsEqualTo("https://rvserver.local/");

        using var ownerListener = new LoopbackHttpServer();
        var rendezvous = new RendezvousFixture(fixture.Auth)
        {
            Address = new FdoRendezvousAddress(
                new byte[] { 127, 0, 0, 1 }, null, (ushort)ownerListener.Address.Port,
                FdoRendezvousTransportProtocol.Http),
        };
        var registrationOwner = new FdoOwnerRendezvousSession(new FdoOwnerRendezvousOptions
        {
            EncodedVoucherHeaderTag = transferred.EncodedVoucherHeaderTag,
            EncodedVoucherHeaderHmac = transferred.EncodedVoucherHeaderHmac,
            EncodedVoucherEntries = transferred.EncodedVoucherEntries,
            EncodedDeviceCertificateChain = transferred.EncodedDeviceCertificateChain,
            TrustedManufacturerKey = fixture.Auth.Voucher.ManufacturerKey,
            DeviceTrustAnchor = fixture.Auth.RootCertificate.RawData,
            DeviceRevocationMode = X509RevocationMode.NoCheck,
            OwnerSigningKey = fixture.Auth.Voucher.FinalOwner,
            OwnerAddress = rendezvous.Address,
            WaitSeconds = 300,
            MaxMessageSize = 8192,
            UseProvisionalPairedProfile = true,
        });
        using var registrationListener = new LoopbackHttpServer();
        using FdoRendezvousServerSession registrationServer =
            rendezvous.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        using var registrationBinding = FdoHttpServerSession.ForRendezvous(registrationServer, 8192);
        Task<IReadOnlyList<RecordedRequest>> registrationServing =
            registrationListener.ServeSessionAsync(registrationBinding, timeout.Token);

        uint accepted = await FdoHttp.RunOwnerRendezvousAsync(
            registrationOwner, registrationListener.Address, 8192, timeout.Token);
        IReadOnlyList<RecordedRequest> registrationRequests = await registrationServing;
        FdoRendezvousCodec.OwnerSubmission submitted =
            rendezvous.Codec.ReadOwnerSign(registrationRequests[1].Body, 10);
        FdoRendezvousRegistration stored = rendezvous.Store.LastWritten!;
        ReadOnlyMemory<byte> submittedVoucher = rendezvous.Codec.EncodeVoucher(
            submitted.Voucher.Header, submitted.Voucher.Hmac,
            submitted.Voucher.CertificateChain, submitted.Voucher.Entries);
        ReadOnlyMemory<byte> finalOwnerKey = new FdoPublicKeyCodec().Encode(fixture.Auth.Voucher.FinalOwner);
        await Assert.That(accepted).IsEqualTo(120U);
        await Assert.That(registrationRequests.Select(request => request.Uri!.AbsolutePath).SequenceEqual(
            new[] { "/fdo/200/msg/20", "/fdo/200/msg/22" })).IsTrue();
        await Assert.That(submittedVoucher.Span.SequenceEqual(transferred.EncodedVoucher.Span)).IsTrue();
        await Assert.That(stored.DeviceGuid.Span.SequenceEqual(credential.DeviceGuid.Span)).IsTrue();
        await Assert.That(stored.EncodedOwnerKey.Span.SequenceEqual(finalOwnerKey.Span)).IsTrue();
        await Assert.That(stored.EncodedOwnerKey.Span
            .SequenceEqual(fixture.Auth.Voucher.ManufacturerKey.AsSpan())).IsFalse();
        await Assert.That(stored.SignedRedirect.Span.SequenceEqual(submitted.SignedRedirect.Span)).IsTrue();
        await Assert.That(registrationServer.FinalResponseHandoffConfirmed).IsTrue();
        await Assert.That(registrationBinding.IsComplete).IsTrue();

        ReadOnlyMemory<byte> deliveredRedirect = stored.SignedRedirect;
        if (forgeRedirect)
        {
            ReadOnlyMemory<byte> forgedSubmission = rendezvous.Codec.EncodeOwnerSign(
                transferred.EncodedVoucher, submitted.WaitSeconds, submitted.Nonce, rendezvous.Address,
                FdoHashAlgorithm.Sha256, fixture.Auth.Voucher.Manufacturer);
            FdoRendezvousCodec.OwnerSubmission forged = rendezvous.Codec.ReadOwnerSign(forgedSubmission, 10);
            await Assert.That(forged.To0Data.Span.SequenceEqual(submitted.To0Data.Span)).IsTrue();
            rendezvous.Codec.VerifyRedirect(
                forged.SignedRedirect, fixture.Auth.Voucher.ManufacturerKey,
                submitted.To0Data, FdoHashAlgorithm.Sha256);
            await Assert.That(Throws<CryptographicException>(() =>
                rendezvous.Codec.VerifyRedirect(forged.SignedRedirect, finalOwnerKey))).IsTrue();
            deliveredRedirect = forged.SignedRedirect;
        }

        var lookupDevice = new FdoDeviceRendezvousSession(new FdoDeviceRendezvousOptions
        {
            DeviceGuid = credential.DeviceGuid,
            AttestationKey = fixture.Auth.DeviceSigningKey,
            MaxMessageSize = 8192,
            UseProvisionalPairedProfile = true,
        });
        IReadOnlyList<FdoRendezvousServerCandidate> discovery = FdoRendezvousInfo.Parse(
            credential.EncodedRendezvousInfo, FdoRendezvousProtocol.DeviceLookup);
        await Assert.That(discovery.Count).IsEqualTo(2);
        await Assert.That(discovery[0].BaseAddress.AbsoluteUri).IsEqualTo("https://rvserver.local/");
        await Assert.That(discovery[1].BaseAddress).IsEqualTo(lookupListener.Address);
        using FdoRendezvousServerSession lookupServer =
            rendezvous.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        using var lookupBinding = FdoHttpServerSession.ForRendezvous(lookupServer, 8192);
        Task<IReadOnlyList<RecordedRequest>> lookupServing = lookupListener.ServeSessionAsync(
            lookupBinding, timeout.Token,
            transformResponse: response => forgeRedirect && response.MessageType == (ushort)FdoRendezvousMessageType.Redirect
                ? rendezvous.Codec.EncodeRedirect(deliveredRedirect)
                : response.EncodedBody);

        FdoDeviceRendezvousResult lookup = await FdoHttp.RunDeviceRendezvousAsync(
            lookupDevice, discovery[1].BaseAddress, 8192, timeout.Token);
        IReadOnlyList<RecordedRequest> lookupRequests = await lookupServing;
        await Assert.That(lookupRequests.Select(request => request.Uri!.AbsolutePath).SequenceEqual(
            new[] { "/fdo/200/msg/30", "/fdo/200/msg/32" })).IsTrue();
        await Assert.That(lookup.SignedRedirect.Span.SequenceEqual(deliveredRedirect.Span)).IsTrue();
        if (!forgeRedirect)
        {
            await Assert.That(lookup.SignedRedirect.Span.SequenceEqual(stored.SignedRedirect.Span)).IsTrue();
        }

        FdoRendezvousAddress candidate = lookup.CandidateAddress;
        ReadOnlyMemory<byte> candidateIp = candidate.IpAddress
            ?? throw new InvalidOperationException("The loopback Owner candidate has no IP address.");
        await Assert.That(candidate.Protocol).IsEqualTo(FdoRendezvousTransportProtocol.Http);
        await Assert.That(candidateIp.Span.SequenceEqual(new byte[] { 127, 0, 0, 1 })).IsTrue();
        await Assert.That(candidate.DnsName).IsNull();
        await Assert.That((int)candidate.Port).IsEqualTo(ownerListener.Address.Port);
        var ownerAddress = new UriBuilder(
            Uri.UriSchemeHttp, new IPAddress(candidateIp.Span).ToString(), candidate.Port).Uri;
        await Assert.That(ownerAddress).IsEqualTo(ownerListener.Address);
        await Assert.That(lookupServer.FinalResponseHandoffConfirmed).IsTrue();
        await Assert.That(lookupBinding.IsComplete).IsTrue();

        fixture.InitializedCredential = credential;
        fixture.TransferredVoucher = transferred;
        fixture.OpaqueVoucherSecret = credential.VoucherHmacSecret;
        fixture.IncludeRawVoucherSecret = false;
        fixture.Device = fixture.Device with { AllowRendezvousBypass = false };
        fixture.DeviceRendezvous = lookup;
        fixture.OwnerBypass = false;
        fixture.OwnerRendezvous = true;
        using FdoOwnerSession owner = fixture.CreateSession();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var ownerBinding = FdoHttpServerSession.ForOwner(owner, 8192);
        using var ownerCancellation = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
        var observedRequests = new List<RecordedRequest>();
        Task<IReadOnlyList<RecordedRequest>> ownerServing = ownerListener.ServeSessionAsync(
            ownerBinding, ownerCancellation.Token, onRequest: observedRequests.Add);

        if (forgeRedirect)
        {
            try
            {
                await CatchAsync<CryptographicException>(() =>
                    FdoHttp.RunDeviceAsync(device, ownerAddress, 8192, timeout.Token).AsTask());
            }
            finally
            {
                ownerCancellation.Cancel();
                try
                {
                    await ownerServing;
                }
                catch (OperationCanceledException) when (ownerCancellation.IsCancellationRequested)
                {
                }
            }

            await Assert.That(observedRequests.Select(request => request.Uri!.AbsolutePath).SequenceEqual(
                new[] { "/fdo/200/msg/80", "/fdo/200/msg/82", "/fdo/200/msg/84" })).IsTrue();
            await Assert.That(ownerListener.HasPendingConnection).IsFalse();
            await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
            await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
            await Assert.That(fixture.ValidationCalls).IsEqualTo(0);
            await Assert.That(fixture.InstallCalls).IsEqualTo(0);
            await Assert.That(owner.DoneAckHandoffConfirmed).IsFalse();
            await Assert.That(device.DoneAckAuthenticated).IsFalse();
        }
        else
        {
            FdoDeviceEnrollment result = await FdoHttp.RunDeviceAsync(
                device, ownerAddress, 8192, timeout.Token);
            IReadOnlyList<RecordedRequest> ownerRequests = await ownerServing;
            await Assert.That(ownerRequests.Select(request => request.Uri!.AbsolutePath).SequenceEqual(
                new[]
                {
                    "/fdo/200/msg/80", "/fdo/200/msg/82", "/fdo/200/msg/84",
                    "/fdo/200/msg/86", "/fdo/200/msg/88", "/fdo/200/msg/88", "/fdo/200/msg/90",
                })).IsTrue();
            await Assert.That(ownerRequests[0].Authorization).IsNull();
            string token = ownerRequests[1].Authorization!;
            await Assert.That(token.StartsWith("Bearer ", StringComparison.Ordinal)).IsTrue();
            await Assert.That(ownerRequests.Skip(1).All(request => request.Authorization == token)).IsTrue();
            await Assert.That(ownerRequests.Skip(3).All(request => request.Body[0] == 0xD0)).IsTrue();
            await Assert.That(result.DeviceGuid.Span.SequenceEqual(credential.DeviceGuid.Span)).IsTrue();
            await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
            await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
            await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
            await Assert.That(fixture.InstallCalls).IsEqualTo(1);
            await Assert.That(owner.DoneAckHandoffConfirmed).IsTrue();
            await Assert.That(device.DoneAckAuthenticated).IsTrue();
            await Assert.That(ownerBinding.IsComplete).IsTrue();
        }

        ReadOnlyMemory<byte> header = new FdoCborCodec().ReadByteStringPayload(voucher.EncodedVoucherHeaderTag);
        await Assert.That(secret.Inputs.Count).IsEqualTo(2);
        await Assert.That(secret.Inputs.All(input => input.AsSpan().SequenceEqual(header.Span))).IsTrue();
    }

    private static byte[] EncodeLoopbackRendezvousInfo(ushort port)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(2);
        writer.WriteStartArray(1);
        WriteInstruction(5, value => value.WriteTextString("rvserver.local"));
        writer.WriteEndArray();
        writer.WriteStartArray(4);
        WriteInstruction(0, value => value.WriteNull());
        WriteInstruction(2, value => value.WriteByteString(new byte[] { 127, 0, 0, 1 }));
        WriteInstruction(3, value => value.WriteUInt32(port));
        WriteInstruction(12, value => value.WriteUInt32(1));
        writer.WriteEndArray();
        writer.WriteEndArray();
        return writer.Encode();

        void WriteInstruction(int variable, Action<CborWriter> writeValue)
        {
            var value = new CborWriter(CborConformanceMode.Canonical);
            writeValue(value);
            writer.WriteStartArray(2);
            writer.WriteInt32(variable);
            writer.WriteByteString(value.Encode());
            writer.WriteEndArray();
        }
    }

    [Test]
    public async Task RunsProtectedEnrollmentOverHttpWithOneCorrelatedOwnerSession()
    {
        using var fixture = new Fixture();
        using var listener = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var rendezvous = new RendezvousFixture(fixture.Auth)
        {
            Address = new FdoRendezvousAddress(
                new byte[] { 127, 0, 0, 1 }, null, (ushort)listener.Address.Port, FdoRendezvousTransportProtocol.Http),
        };
        using var registrationListener = new LoopbackHttpServer();
        using FdoRendezvousServerSession registrationServer =
            rendezvous.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        using var registrationBinding = FdoHttpServerSession.ForRendezvous(registrationServer, 8192);
        Task<IReadOnlyList<RecordedRequest>> registrationServing =
            registrationListener.ServeSessionAsync(registrationBinding, timeout.Token);
        uint accepted = await FdoHttp.RunOwnerRendezvousAsync(
            rendezvous.CreateOwner(), registrationListener.Address, 8192, timeout.Token);
        IReadOnlyList<RecordedRequest> registrationRequests = await registrationServing;
        using var lookupListener = new LoopbackHttpServer();
        using FdoRendezvousServerSession lookupServer =
            rendezvous.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        using var lookupBinding = FdoHttpServerSession.ForRendezvous(lookupServer, 8192);
        Task<IReadOnlyList<RecordedRequest>> lookupServing =
            lookupListener.ServeSessionAsync(lookupBinding, timeout.Token);
        fixture.DeviceRendezvous = await FdoHttp.RunDeviceRendezvousAsync(
            rendezvous.CreateDevice(), lookupListener.Address, 8192, timeout.Token);
        IReadOnlyList<RecordedRequest> lookupRequests = await lookupServing;
        fixture.Device = fixture.Device with { AllowRendezvousBypass = false };
        fixture.OwnerBypass = false;
        fixture.OwnerRendezvous = true;
        using FdoOwnerSession owner = fixture.CreateSession();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var binding = FdoHttpServerSession.ForOwner(owner, 8192, "/onboarding");
        Uri address = new(listener.Address, "onboarding/");
        Task<IReadOnlyList<RecordedRequest>> serving = listener.ServeSessionAsync(binding, timeout.Token);

        FdoDeviceEnrollment result = await FdoHttp.RunDeviceAsync(device, address, 8192, timeout.Token);
        IReadOnlyList<RecordedRequest> requests = await serving;

        await Assert.That(accepted).IsEqualTo(120U);
        await Assert.That(registrationRequests.Select(request => request.Uri!.AbsolutePath).SequenceEqual(
            new[] { "/fdo/200/msg/20", "/fdo/200/msg/22" })).IsTrue();
        await Assert.That(lookupRequests.Select(request => request.Uri!.AbsolutePath).SequenceEqual(
            new[] { "/fdo/200/msg/30", "/fdo/200/msg/32" })).IsTrue();
        await Assert.That(registrationRequests[0].Authorization).IsNull();
        await Assert.That(lookupRequests[0].Authorization).IsNull();
        await Assert.That(registrationRequests[1].Authorization).IsNotEqualTo(lookupRequests[1].Authorization);
        await Assert.That(fixture.DeviceRendezvous.SignedRedirect.Span
            .SequenceEqual(rendezvous.Store.LastWritten!.SignedRedirect.Span)).IsTrue();
        await Assert.That(registrationServer.FinalResponseHandoffConfirmed).IsTrue();
        await Assert.That(lookupServer.FinalResponseHandoffConfirmed).IsTrue();
        await Assert.That(requests.Select(request => request.Uri!.AbsolutePath).SequenceEqual(
            new[]
            {
                "/onboarding/fdo/200/msg/80", "/onboarding/fdo/200/msg/82",
                "/onboarding/fdo/200/msg/84", "/onboarding/fdo/200/msg/84",
                "/onboarding/fdo/200/msg/86", "/onboarding/fdo/200/msg/88",
                "/onboarding/fdo/200/msg/88", "/onboarding/fdo/200/msg/90",
            })).IsTrue();
        await Assert.That(requests[0].Authorization).IsNull();
        string token = requests[1].Authorization!;
        await Assert.That(token.StartsWith("Bearer ", StringComparison.Ordinal)).IsTrue();
        await Assert.That(requests.Skip(1).All(request => request.Authorization == token)).IsTrue();
        await Assert.That(requests.All(request => request.ContentType == "application/cbor")).IsTrue();
        await Assert.That(requests.Skip(4).All(request => request.Body[0] == 0xD0)).IsTrue();
        await Assert.That(requests.Skip(4).All(request =>
            request.Body.AsSpan().IndexOf(Encoding.UTF8.GetBytes("fdo.csr")) < 0)).IsTrue();
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
        await Assert.That(owner.DoneAckHandoffConfirmed).IsTrue();
        await Assert.That(device.DoneAckAuthenticated).IsTrue();
        await Assert.That(binding.IsComplete).IsTrue();
    }

    [Test]
    public async Task LostHttpDoneAckDoesNotRetryOrInstallAfterOwnerCommit()
    {
        using var fixture = new Fixture();
        using FdoOwnerSession owner = fixture.CreateSession();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var listener = new LoopbackHttpServer();
        using var binding = FdoHttpServerSession.ForOwner(owner, 8192);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<IReadOnlyList<RecordedRequest>> serving = listener.ServeSessionAsync(binding, timeout.Token, 90);

        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => FdoHttp.RunDeviceAsync(device, listener.Address, 8192, timeout.Token).AsTask());
        IReadOnlyList<RecordedRequest> requests = await serving;

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.Network);
        await Assert.That(requests.Count(request => request.Uri!.AbsolutePath.EndsWith("/msg/90", StringComparison.Ordinal)))
            .IsEqualTo(1);
        await Assert.That(listener.HasPendingConnection).IsFalse();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(owner.CommittedEnrollment).IsNotNull();
        await Assert.That(owner.DoneAckProduced).IsTrue();
        await Assert.That(owner.DoneAckHandoffConfirmed).IsFalse();
        await Assert.That(device.DoneAckAuthenticated).IsFalse();
        await Assert.That(device.InstallationStarted).IsFalse();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task HttpClientDoesNotFollowCrossOriginRedirect()
    {
        using var fixture = new Fixture();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var origin = new LoopbackHttpServer();
        using var target = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<RecordedRequest> received = origin.RespondOnceAsync(
            $"307 Temporary Redirect\r\nLocation: {target.Address.AbsoluteUri}", [], timeout.Token);

        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => FdoHttp.RunDeviceAsync(device, origin.Address, 8192, timeout.Token).AsTask());
        RecordedRequest request = await received;

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.UnexpectedStatus);
        await Assert.That(error.RedirectLocation).IsNull();
        await Assert.That(request.Uri!.AbsolutePath).IsEqualTo("/fdo/200/msg/80");
        await Assert.That(target.HasPendingConnection).IsFalse();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task HttpClientRejectsOversizedResponseBeforeReadingItsBody()
    {
        using var fixture = new Fixture();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var listener = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<RecordedRequest> received = listener.RespondOnceAsync(
            "200 OK\r\nMessage-Type: 81\r\nAuthorization: Bearer test\r\nContent-Type: application/cbor",
            [0x84, 0x01, 0x02, 0x03, 0x04], timeout.Token);

        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => FdoHttp.RunDeviceAsync(device, listener.Address, 4, timeout.Token).AsTask());
        await received;

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.ResponseTooLarge);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task HttpClientRejectsAResponseFromTheWrongProtocolStep()
    {
        using var fixture = new Fixture();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var listener = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<RecordedRequest> received = listener.RespondOnceAsync(
            "200 OK\r\nMessage-Type: 85\r\nAuthorization: Bearer test\r\nContent-Type: application/cbor",
            [0x81, 0x01], timeout.Token);

        await CatchAsync<CborContentException>(
            () => FdoHttp.RunDeviceAsync(device, listener.Address, 8192, timeout.Token).AsTask());
        await received;

        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task HttpClientRequiresCborResponseContentType()
    {
        using var fixture = new Fixture();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var listener = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<RecordedRequest> received = listener.RespondOnceAsync(
            "200 OK\r\nMessage-Type: 81\r\nAuthorization: Bearer test\r\nContent-Type: application/json",
            [0x81, 0x01], timeout.Token);

        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => FdoHttp.RunDeviceAsync(device, listener.Address, 8192, timeout.Token).AsTask());
        await received;

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.InvalidResponse);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [TUnit.Core.RunOn(TUnit.Core.Enums.OS.Linux)]
    public async Task RunsProtectedEnrollmentOverHttpsWithTrustedMatchingPeer()
    {
        using var fixture = new Fixture();
        using var tls = new TlsCertificateFixture(matchingName: true);
        using var listener = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using FdoOwnerSession owner = fixture.CreateSession();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var binding = FdoHttpServerSession.ForOwner(owner, 8192);
        var validationErrors = new ConcurrentQueue<SslPolicyErrors>();
        using FdoHttpClient client = CreateTrustedHttpsClient(tls.RootCertificate, validationErrors.Enqueue);
        Uri address = new UriBuilder(listener.Address) { Scheme = Uri.UriSchemeHttps }.Uri;
        var session = new FdoHttpClientSession(
            client, address, FdoProtocolKind.TransferOwnership2, FdoProtocolVersion.V20);
        Task<IReadOnlyList<RecordedRequest>> serving = listener.ServeSessionAsync(
            binding, timeout.Token, serverCertificate: tls.ServerCertificate);

        FdoDeviceEnrollment result;
        try
        {
            result = await device.RunAsync(session.CreateDeviceTransport(), timeout.Token);
        }
        catch (FdoTransportException clientError)
        {
            await ((Task)serving).WaitAsync(TimeSpan.FromSeconds(2))
                .ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            if (!serving.IsCompleted)
            {
                await timeout.CancelAsync();
            }

            throw new InvalidOperationException(
                $"TLS client: {clientError}\nTLS server: {serving.Exception?.ToString() ?? "not completed"}",
                clientError);
        }

        IReadOnlyList<RecordedRequest> requests = await serving;

        await Assert.That(validationErrors.IsEmpty).IsFalse();
        await Assert.That(validationErrors.All(errors => errors == SslPolicyErrors.None)).IsTrue();
        await Assert.That(requests.Count).IsEqualTo(8);
        await Assert.That(requests.All(request => request.Uri!.Scheme == Uri.UriSchemeHttps &&
            request.Uri.Host == address.Host)).IsTrue();
        await Assert.That(requests[0].Uri!.AbsolutePath).IsEqualTo("/fdo/200/msg/80");
        await Assert.That(requests[^1].Uri!.AbsolutePath).IsEqualTo("/fdo/200/msg/90");
        await Assert.That(requests.Skip(4).All(request => request.Body.Length > 0 && request.Body[0] == 0xD0)).IsTrue();
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
        await Assert.That(owner.DoneAckHandoffConfirmed).IsTrue();
        await Assert.That(device.DoneAckAuthenticated).IsTrue();
    }

    [Test]
    [TUnit.Core.RunOn(TUnit.Core.Enums.OS.Linux)]
    public async Task HttpsClientRejectsTrustedCertificateForDifferentPeer()
    {
        using var fixture = new Fixture();
        using var tls = new TlsCertificateFixture(matchingName: false);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(tls.RootCertificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        await Assert.That(chain.Build(tls.ServerCertificate)).IsTrue();

        using var listener = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        var validationErrors = new ConcurrentQueue<SslPolicyErrors>();
        using FdoHttpClient client = CreateTrustedHttpsClient(tls.RootCertificate, validationErrors.Enqueue);
        Uri address = new UriBuilder(listener.Address) { Scheme = Uri.UriSchemeHttps }.Uri;
        var session = new FdoHttpClientSession(
            client, address, FdoProtocolKind.TransferOwnership2, FdoProtocolVersion.V20);
        Task<bool> received = listener.AcceptTlsOnceAsync(tls.ServerCertificate, timeout.Token);

        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => device.RunAsync(session.CreateDeviceTransport(), timeout.Token).AsTask());

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.Network);
        await Assert.That(error.InnerException is HttpRequestException requestError &&
            requestError.HttpRequestError == HttpRequestError.SecureConnectionError).IsTrue();
        await Assert.That(await received).IsFalse();
        await Assert.That(validationErrors.IsEmpty).IsFalse();
        await Assert.That(validationErrors.All(errors =>
            errors == SslPolicyErrors.RemoteCertificateNameMismatch)).IsTrue();
        await Assert.That(session.IsTerminated).IsTrue();
        await Assert.That(device.DoneAckAuthenticated).IsFalse();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task HttpsClientRejectsAnUntrustedLoopbackCertificate()
    {
        using var fixture = new Fixture();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var listener = new LoopbackHttpServer();
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=FDO loopback", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<bool> accepted = listener.AcceptTlsOnceAsync(certificate, timeout.Token);
        Uri address = new UriBuilder(listener.Address) { Scheme = Uri.UriSchemeHttps }.Uri;

        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => FdoHttp.RunDeviceAsync(device, address, 8192, timeout.Token).AsTask());

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.Network);
        await Assert.That(await accepted).IsFalse();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [TUnit.Core.RunOn(TUnit.Core.Enums.OS.Linux)]
    public async Task HttpsClientRejectsMatchingPeerWithUntrustedChain()
    {
        using var fixture = new Fixture();
        using var tls = new TlsCertificateFixture(matchingName: true);
        using var unrelatedTrust = new TlsCertificateFixture(matchingName: true);
        using var listener = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        var validationErrors = new ConcurrentQueue<SslPolicyErrors>();
        using FdoHttpClient client = CreateTrustedHttpsClient(
            unrelatedTrust.RootCertificate, validationErrors.Enqueue);
        Uri address = new UriBuilder(listener.Address) { Scheme = Uri.UriSchemeHttps }.Uri;
        var session = new FdoHttpClientSession(
            client, address, FdoProtocolKind.TransferOwnership2, FdoProtocolVersion.V20);
        Task<bool> received = listener.AcceptTlsOnceAsync(tls.ServerCertificate, timeout.Token);

        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => device.RunAsync(session.CreateDeviceTransport(), timeout.Token).AsTask());

        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.Network);
        await Assert.That(error.InnerException is HttpRequestException requestError &&
            requestError.HttpRequestError == HttpRequestError.SecureConnectionError).IsTrue();
        await Assert.That(await received).IsFalse();
        await Assert.That(validationErrors.IsEmpty).IsFalse();
        await Assert.That(validationErrors.All(errors =>
            errors == SslPolicyErrors.RemoteCertificateChainErrors)).IsTrue();
        await Assert.That(session.IsTerminated).IsTrue();
        await Assert.That(device.DoneAckAuthenticated).IsFalse();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [TUnit.Core.RunOn(TUnit.Core.Enums.OS.Linux)]
    public async Task PublicHttpsRunnerUsesThePrivateCaOnlyForTheConfiguredRun()
    {
        using var fixture = new Fixture();
        using var tls = new TlsCertificateFixture(matchingName: true);
        using var listener = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using FdoOwnerSession owner = fixture.CreateSession();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var binding = FdoHttpServerSession.ForOwner(owner, 8192);
        byte[] anchor = tls.RootCertificate.RawData;
        var trust = new FdoHttpPrivateTrust(anchor);
        Array.Clear(anchor);
        Uri address = new UriBuilder(listener.Address) { Scheme = Uri.UriSchemeHttps }.Uri;
        Task<IReadOnlyList<RecordedRequest>> serving = listener.ServeSessionAsync(
            binding, timeout.Token, serverCertificate: tls.ServerCertificate);
        FdoDeviceEnrollment result = await FdoHttp.RunDeviceAsync(device, address, 8192, timeout.Token, trust);
        await Assert.That((await serving).Count).IsEqualTo(8);
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);

        using var unrelated = new Fixture();
        using FdoDeviceSession defaultDevice = unrelated.CreateDeviceSession();
        using var defaultListener = new LoopbackHttpServer();
        Task<bool> accepted = defaultListener.AcceptTlsOnceAsync(tls.ServerCertificate, timeout.Token);
        Uri defaultAddress = new UriBuilder(defaultListener.Address) { Scheme = Uri.UriSchemeHttps }.Uri;
        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => FdoHttp.RunDeviceAsync(defaultDevice, defaultAddress, 8192, timeout.Token).AsTask());
        await Assert.That(error.InnerException is HttpRequestException requestError &&
            requestError.HttpRequestError == HttpRequestError.SecureConnectionError).IsTrue();
        await Assert.That(await accepted).IsFalse();
        await Assert.That(unrelated.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    [TUnit.Core.RunOn(TUnit.Core.Enums.OS.Linux)]
    public async Task PublicHttpsRunnerRejectsWrongNameOrPrivateChain(bool wrongName)
    {
        using var fixture = new Fixture();
        using var tls = new TlsCertificateFixture(matchingName: !wrongName);
        using var unrelated = new TlsCertificateFixture(matchingName: true);
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var listener = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        X509Certificate2 anchor = wrongName ? tls.RootCertificate : unrelated.RootCertificate;
        var trust = new FdoHttpPrivateTrust(anchor.RawData);
        Task<bool> accepted = listener.AcceptTlsOnceAsync(tls.ServerCertificate, timeout.Token);
        Uri address = new UriBuilder(listener.Address) { Scheme = Uri.UriSchemeHttps }.Uri;
        FdoTransportException error = await CatchAsync<FdoTransportException>(
            () => FdoHttp.RunDeviceAsync(device, address, 8192, timeout.Token, trust).AsTask());
        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.Network);
        await Assert.That(error.InnerException is HttpRequestException requestError &&
            requestError.HttpRequestError == HttpRequestError.SecureConnectionError).IsTrue();
        await Assert.That(await accepted).IsFalse();
        await Assert.That(device.DoneAckAuthenticated).IsFalse();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task PrivateCaConfigurationCannotBeUsedWithPlainHttpOrALeafAnchor()
    {
        using var tls = new TlsCertificateFixture(matchingName: true);
        await Assert.That(Throws<ArgumentException>(() => new FdoHttpPrivateTrust(tls.ServerCertificate.RawData))).IsTrue();
        using var fixture = new Fixture();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        var trust = new FdoHttpPrivateTrust(tls.RootCertificate.RawData);
        await CatchAsync<ArgumentException>(() =>
            FdoHttp.RunDeviceAsync(device, new Uri("http://127.0.0.1:1/"), 8192, default, trust).AsTask());
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [TUnit.Core.RunOn(TUnit.Core.Enums.OS.Linux)]
    public async Task PublicRendezvousRunnersUsePrivateCaTrustForTo0AndTo1()
    {
        using var authentication = new AuthenticationFixture();
        var rendezvous = new RendezvousFixture(authentication);
        using var tls = new TlsCertificateFixture(matchingName: true);
        var trust = new FdoHttpPrivateTrust(tls.RootCertificate.RawData);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var ownerListener = new LoopbackHttpServer();
        using FdoRendezvousServerSession owner = rendezvous.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        using var ownerBinding = FdoHttpServerSession.ForRendezvous(owner);
        Task<IReadOnlyList<RecordedRequest>> registration = ownerListener.ServeSessionAsync(
            ownerBinding, timeout.Token, serverCertificate: tls.ServerCertificate);
        Uri to0 = new UriBuilder(ownerListener.Address) { Scheme = Uri.UriSchemeHttps }.Uri;
        uint wait = await FdoHttp.RunOwnerRendezvousAsync(
            rendezvous.CreateOwner(), to0, 8192, timeout.Token, trust);
        await Assert.That(wait).IsEqualTo(120U);
        await Assert.That((await registration).Count).IsEqualTo(2);

        using var deviceListener = new LoopbackHttpServer();
        using FdoRendezvousServerSession device = rendezvous.CreateServer(FdoRendezvousProtocol.DeviceLookup);
        using var deviceBinding = FdoHttpServerSession.ForRendezvous(device);
        Task<IReadOnlyList<RecordedRequest>> discovery = deviceListener.ServeSessionAsync(
            deviceBinding, timeout.Token, serverCertificate: tls.ServerCertificate);
        Uri to1 = new UriBuilder(deviceListener.Address) { Scheme = Uri.UriSchemeHttps }.Uri;
        FdoDeviceRendezvousResult result = await FdoHttp.RunDeviceRendezvousAsync(
            rendezvous.CreateDevice(), to1, 8192, timeout.Token, trust);
        await Assert.That((await discovery).Count).IsEqualTo(2);
        await Assert.That(result.SignedRedirect.Span.SequenceEqual(owner.StoredRegistration!.SignedRedirect.Span)).IsTrue();
    }

    private static FdoHttpClient CreateTrustedHttpsClient(
        X509Certificate2 trustAnchor, Action<SslPolicyErrors> recordErrors)
    {
        var policy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
        };
        policy.CustomTrustStore.Add(trustAnchor);
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
        };
        handler.SslOptions.CertificateChainPolicy = policy;
        handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, errors) =>
        {
            recordErrors(errors);
            return errors == SslPolicyErrors.None;
        };
        return new FdoHttpClient(handler);
    }

    [Test]
    [Arguments(256, 0, 1)]
    [Arguments(384, 1, 3)]
    public async Task RunsTo2AfterTo1AndVerifiesTheOwnerRedirectBeforeEnrollment(
        int curveSize, int exchangeValue, int cipherValue)
    {
        using var fixture = new Fixture(
            curveSize, (FdoKeyExchangeSuite)exchangeValue, (FdoCoseAeadAlgorithm)cipherValue);
        var rendezvous = new RendezvousFixture(fixture.Auth);
        await rendezvous.RegisterAsync();
        fixture.DeviceRendezvous = await rendezvous.LookupAsync();
        byte[] expectedRedirect = fixture.DeviceRendezvous.SignedRedirect.ToArray();
        ClearExposedMemory(fixture.DeviceRendezvous.SignedRedirect);
        await Assert.That(fixture.DeviceRendezvous.SignedRedirect.Span.SequenceEqual(expectedRedirect)).IsTrue();
        fixture.Device = fixture.Device with { AllowRendezvousBypass = false };
        fixture.OwnerBypass = false;
        fixture.OwnerRendezvous = true;

        FdoDeviceEnrollment result = await fixture.RunAsync();

        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 86)).IsTrue();
    }

    [Test]
    [Arguments("tamper")]
    [Arguments("other-owner")]
    public async Task RejectsAnUntrustedTo1BlobBeforeAnyProtectedTo2Message(string failure)
    {
        using var fixture = new Fixture();
        using ECDsa otherOwner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rendezvous = new RendezvousFixture(fixture.Auth);
        await rendezvous.RegisterAsync();
        byte[] blob = rendezvous.Store.LastWritten!.SignedRedirect.ToArray();
        if (failure == "tamper")
        {
            blob[^1] ^= 1;
        }
        else
        {
            blob = rendezvous.Codec.ReadOwnerSign(
                rendezvous.OwnerSign(new byte[16], key: otherOwner), 10).SignedRedirect.ToArray();
        }

        fixture.DeviceRendezvous = await rendezvous.LookupAsync(message =>
            message.Type == FdoRendezvousMessageType.Redirect
                ? message with { Body = rendezvous.Codec.EncodeRedirect(blob) }
                : message);
        fixture.Device = fixture.Device with { AllowRendezvousBypass = false };
        fixture.OwnerBypass = false;
        fixture.OwnerRendezvous = true;

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.Transport.Messages.Any(message => message.Type >= 86)).IsFalse();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.ValidationCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task DeviceRequiresOneRouteAndConsumesEachTo1ResultOnce()
    {
        using var fixture = new Fixture();
        var rendezvous = new RendezvousFixture(fixture.Auth);
        await rendezvous.RegisterAsync();
        fixture.DeviceRendezvous = await rendezvous.LookupAsync();

        await Assert.That(Throws<InvalidOperationException>(() => fixture.CreateDeviceSession())).IsTrue();
        fixture.Device = fixture.Device with { AllowRendezvousBypass = false };
        using var selected = new FdoDeviceSession(fixture.CreateDeviceOptions());
        await Assert.That(Throws<InvalidOperationException>(() => fixture.CreateDeviceSession())).IsTrue();
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
    }

    [Test]
    public async Task DeviceRejectsTo1ResultForAnotherGuidWithoutSendingTo2()
    {
        using var fixture = new Fixture();
        var rendezvous = new RendezvousFixture(fixture.Auth);
        await rendezvous.RegisterAsync();
        FdoDeviceRendezvousResult result = await rendezvous.LookupAsync();
        fixture.DeviceRendezvous = new FdoDeviceRendezvousResult(
            new byte[16], result.SignedRedirect, result.CandidateAddress);
        fixture.Device = fixture.Device with { AllowRendezvousBypass = false };

        await Assert.That(Throws<CryptographicException>(() => fixture.CreateDeviceSession())).IsTrue();
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(2, 2048, false, 1)]
    [Arguments(2, 2048, true, -17760704)]
    [Arguments(2, 2048, false, -17760703)]
    [Arguments(3, 3072, false, 3)]
    [Arguments(3, 3072, false, -17760706)]
    [Arguments(3, 3072, false, -17760705)]
    [Arguments(4, 2048, false, 1)]
    [Arguments(4, 2048, true, -17760704)]
    [Arguments(4, 2048, false, -17760703)]
    [Arguments(5, 3072, false, 3)]
    [Arguments(5, 3072, false, -17760706)]
    [Arguments(5, 3072, false, -17760705)]
    public async Task PairedRsaExchangeRunsWithAuthenticatedVoucher(
        int suiteValue, int keySize, bool restricted, int cipherValue)
    {
        var suite = (FdoKeyExchangeSuite)suiteValue;
        using var fixture = new Fixture(cipher: (FdoCoseAeadAlgorithm)cipherValue);
        fixture.Exchange = suite;
        fixture.OwnerPairedDh = fixture.DevicePairedDh = FdoKeyExchangeSuites.IsDh(suite);
        fixture.OwnerPairedAsym = fixture.DevicePairedAsym = FdoKeyExchangeSuites.IsAsym(suite);
        if (FdoKeyExchangeSuites.IsDh(suite) && !OperatingSystem.IsLinux())
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() => fixture.CreateSession())).IsTrue();
            await Assert.That(Throws<PlatformNotSupportedException>(() => fixture.CreateDeviceSession())).IsTrue();
            return;
        }

        using RSA manufacturer = RSA.Create(keySize);
        using RSA ownerKey = RSA.Create(keySize);
        ConfigureRsaVoucher(fixture, manufacturer, ownerKey, restricted);

        FdoDeviceEnrollment result = await fixture.RunAsync();

        ushort[] expected = [80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 88, 89, 90, 91];
        await Assert.That(fixture.Transport.Messages.Select(message => message.Type).SequenceEqual(expected)).IsTrue();
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.Session!.DoneAckHandoffConfirmed).IsTrue();
    }

    [Test]
    [Arguments(2048, false)]
    [Arguments(2048, true)]
    [Arguments(3072, false)]
    [Arguments(3072, true)]
    public async Task DirectRsaDualOfferUsesTheDeviceChoiceOrRejectsUnavailableDh(int keySize, bool selectDh)
    {
        using var fixture = new Fixture();
        using RSA manufacturer = RSA.Create(keySize);
        using RSA ownerKey = RSA.Create(keySize);
        var dh = keySize == 2048 ? FdoKeyExchangeSuite.DhkexId14 : FdoKeyExchangeSuite.DhkexId15;
        var asym = keySize == 2048 ? FdoKeyExchangeSuite.Asymkex2048 : FdoKeyExchangeSuite.Asymkex3072;
        fixture.Exchange = selectDh ? dh : asym;
        ConfigureRsaVoucher(fixture, manufacturer, ownerKey, restricted: keySize == 2048);
        fixture.OwnerPrimaryExchange = keySize == 2048
            ? FdoPairedKeyExchangeSuite.Asymkex2048 : FdoPairedKeyExchangeSuite.Asymkex3072;
        fixture.OwnerAdditionalExchange = keySize == 2048
            ? FdoPairedKeyExchangeSuite.DhkexId14 : FdoPairedKeyExchangeSuite.DhkexId15;
        fixture.OwnerPairedDh = fixture.OwnerPairedAsym = true;
        fixture.DevicePairedDh = selectDh;
        fixture.DevicePairedAsym = !selectDh;
        if (!OperatingSystem.IsLinux())
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() => fixture.CreateSession())).IsTrue();
            await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
            return;
        }

        await fixture.RunAsync();

        var acknowledgment = new FdoTo2InitialCodec().DecodeAcknowledgement(
            fixture.Transport.Messages.Single(message => message.Type == 81).Body);
        await Assert.That(acknowledgment.KeyExchangeSuites.SequenceEqual(new[]
        {
            FdoKeyExchangeSuites.GetName(asym), FdoKeyExchangeSuites.GetName(dh),
        })).IsTrue();
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
    }

    [Test]
    [Arguments("signer")]
    [Arguments("voucher")]
    [Arguments("size")]
    [Arguments("dh-opt-in")]
    [Arguments("asym-opt-in")]
    [Arguments("pair")]
    [Arguments("delegate")]
    public async Task DirectRsaDualOfferRejectsInvalidConfigurationBeforeAcknowledging(string invalid)
    {
        using var fixture = new Fixture();
        using RSA manufacturer = RSA.Create(2048);
        using RSA owner = RSA.Create(2048);
        using RSA unrelated = RSA.Create(2048);
        ConfigureRsaVoucher(fixture, manufacturer, owner, restricted: false);
        fixture.OwnerPrimaryExchange = invalid == "size"
            ? FdoPairedKeyExchangeSuite.Asymkex3072 : FdoPairedKeyExchangeSuite.Asymkex2048;
        fixture.OwnerAdditionalExchange = invalid is "size" or "pair"
            ? FdoPairedKeyExchangeSuite.DhkexId15 : FdoPairedKeyExchangeSuite.DhkexId14;
        fixture.OwnerPairedDh = invalid != "dh-opt-in";
        fixture.OwnerPairedAsym = invalid != "asym-opt-in";
        fixture.OwnerDelegated = invalid == "delegate";
        if (invalid == "signer")
        {
            fixture.OwnerSigningKeyOverride = unrelated;
        }
        else if (invalid == "voucher")
        {
            byte[] entry = fixture.TransferredVoucher!.EncodedVoucherEntries[0].ToArray();
            entry[^1] ^= 1;
            fixture.OwnerEntriesOverride = [entry];
        }

        bool rejected = invalid switch
        {
            "dh-opt-in" or "asym-opt-in" => Throws<InvalidOperationException>(() => fixture.CreateSession()),
            "pair" or "delegate" => Throws<ArgumentException>(() => fixture.CreateSession()),
            _ when !OperatingSystem.IsLinux() => Throws<PlatformNotSupportedException>(() => fixture.CreateSession()),
            _ => Throws<CryptographicException>(() => fixture.CreateSession()),
        };
        await Assert.That(rejected).IsTrue();
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    public async Task PairedRsaSuitesRequireSeparateOptIns(int suiteValue)
    {
        using var fixture = new Fixture();
        fixture.Exchange = (FdoKeyExchangeSuite)suiteValue;
        fixture.OwnerPairedDh = fixture.DevicePairedDh = FdoKeyExchangeSuites.IsAsym(fixture.Exchange);
        fixture.OwnerPairedAsym = fixture.DevicePairedAsym = FdoKeyExchangeSuites.IsDh(fixture.Exchange);

        await Assert.That(Throws<InvalidOperationException>(() => fixture.CreateSession())).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => fixture.CreateDeviceSession())).IsTrue();
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
    }

    [Test]
    public async Task PairedRsaComparesProvisionedOwnerKeyTypeModulusAndExponent()
    {
        using RSA ownerKey = RSA.Create(2048);
        using RSA wrongModulus = RSA.Create(2048);
        RSAParameters parameters = ownerKey.ExportParameters(false);
        parameters.Exponent = [3];
        using RSA wrongExponent = RSA.Create();
        wrongExponent.ImportParameters(parameters);
        var codec = new FdoPublicKeyCodec();
        ReadOnlyMemory<byte> expected = codec.EncodeRsa(ownerKey);

        FdoPairedProtocol.RequireProvisionedAsymOwner(expected, codec.EncodeRsa(ownerKey));

        await Assert.That(Throws<CryptographicException>(() =>
            FdoPairedProtocol.RequireProvisionedAsymOwner(expected, codec.EncodeRsa(wrongModulus)))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            FdoPairedProtocol.RequireProvisionedAsymOwner(expected, codec.EncodeRsa(wrongExponent)))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            FdoPairedProtocol.RequireProvisionedAsymOwner(expected, codec.EncodeRsa(ownerKey, restricted: true)))).IsTrue();
    }

    [Test]
    public async Task PairedRsaSnapshotsProvisionedOwnerKeyBeforeTheExchange()
    {
        using var fixture = new Fixture();
        using RSA manufacturer = RSA.Create(2048);
        using RSA ownerKey = RSA.Create(2048);
        fixture.Exchange = FdoKeyExchangeSuite.Asymkex2048;
        fixture.OwnerPairedAsym = fixture.DevicePairedAsym = true;
        ConfigureRsaVoucher(fixture, manufacturer, ownerKey, restricted: false);
        byte[] provisioned = fixture.ProvisionedAsymOwnerKey.ToArray();
        fixture.ProvisionedAsymOwnerKey = provisioned;
        FdoDeviceSession device = fixture.CreateDeviceSession();
        Array.Clear(provisioned);

        await fixture.RunAsync(fixture.CreateSession(), device);

        await Assert.That(device.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
    }

    [Test]
    public async Task PairedRsaAsymRequiresAProvisionedOwnerKeyMatchingTheSuite()
    {
        using var fixture = new Fixture();
        fixture.Exchange = FdoKeyExchangeSuite.Asymkex2048;
        fixture.DevicePairedAsym = true;
        var codec = new FdoPublicKeyCodec();
        using RSA wrongSize = RSA.Create(3072);

        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        fixture.ProvisionedAsymOwnerKey = codec.EncodeRsa(wrongSize);
        await Assert.That(Throws<CryptographicException>(() => fixture.CreateDeviceSession())).IsTrue();
        fixture.ProvisionedAsymOwnerKey = codec.Encode(fixture.Auth.Voucher.FinalOwner);
        await Assert.That(Throws<CryptographicException>(() => fixture.CreateDeviceSession())).IsTrue();
        fixture.Exchange = FdoKeyExchangeSuite.Ecdh256;
        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
    }

    [Test]
    public async Task PairedRsaRejectsOwnerKeyTypeMismatchAfterVoucherVerification()
    {
        using var fixture = new Fixture();
        using RSA manufacturer = RSA.Create(2048);
        using RSA ownerKey = RSA.Create(2048);
        fixture.Exchange = FdoKeyExchangeSuite.Asymkex2048;
        fixture.OwnerPairedAsym = fixture.DevicePairedAsym = true;
        ConfigureRsaVoucher(fixture, manufacturer, ownerKey, restricted: true);
        fixture.ProvisionedAsymOwnerKey = new FdoPublicKeyCodec().EncodeRsa(ownerKey, restricted: false);

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 85)).IsTrue();
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type >= 86)).IsFalse();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task PairedRsaRejectsCiphertextForADifferentOwner()
    {
        using var fixture = new Fixture();
        using RSA manufacturer = RSA.Create(2048);
        using RSA ownerKey = RSA.Create(2048);
        using RSA wrongKey = RSA.Create(2048);
        fixture.Exchange = FdoKeyExchangeSuite.Asymkex2048;
        fixture.OwnerPairedAsym = fixture.DevicePairedAsym = true;
        ConfigureRsaVoucher(fixture, manufacturer, ownerKey, restricted: false);
        fixture.ProvisionedAsymOwnerKey = new FdoPublicKeyCodec().EncodeRsa(wrongKey);

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 82)).IsTrue();
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type >= 83)).IsFalse();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task PairedRsaAuthenticatesDeviceProofBeforeDecryption()
    {
        using var fixture = new Fixture();
        using RSA manufacturer = RSA.Create(2048);
        using RSA ownerKey = RSA.Create(2048);
        using var observedOwner = new ObservedRsa(ownerKey);
        fixture.Exchange = FdoKeyExchangeSuite.Asymkex2048;
        fixture.OwnerPairedAsym = fixture.DevicePairedAsym = true;
        ConfigureRsaVoucher(fixture, manufacturer, observedOwner, restricted: false);
        fixture.Transport.Change = (message, _) =>
        {
            if (message.Type != 82)
            {
                return message;
            }

            byte[] changed = message.Body.ToArray();
            changed[^1] ^= 1;
            return message with { Body = changed };
        };

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(observedOwner.DecryptCalls).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type >= 83)).IsFalse();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        fixture.Transport = fixture.CreateTransport();
        await fixture.RunAsync();
        await Assert.That(observedOwner.DecryptCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
    }

    [Test]
    [Arguments(83)]
    [Arguments(85)]
    public async Task PairedRsaRejectsTamperedOwnerProofOrVoucherBeforeProtectedData(ushort messageType)
    {
        using var fixture = new Fixture();
        using RSA manufacturer = RSA.Create(2048);
        using RSA ownerKey = RSA.Create(2048);
        fixture.Exchange = FdoKeyExchangeSuite.Asymkex2048;
        fixture.OwnerPairedAsym = fixture.DevicePairedAsym = true;
        ConfigureRsaVoucher(fixture, manufacturer, ownerKey, restricted: false);
        fixture.Transport.Change = (message, _) =>
        {
            if (message.Type != messageType)
            {
                return message;
            }

            byte[] changed = message.Body.ToArray();
            changed[^1] ^= 1;
            return message with { Body = changed };
        };

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.Transport.Messages.Any(message => message.Type >= 86)).IsFalse();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    private static void ConfigureRsaVoucher(Fixture fixture, RSA manufacturer, RSA owner, bool restricted)
    {
        var keys = new FdoPublicKeyCodec();
        ReadOnlyMemory<byte> manufacturerKey = keys.EncodeRsa(manufacturer, restricted);
        fixture.TransferredVoucher = fixture.Auth.CreateRsaVoucher(manufacturer, owner, restricted);
        fixture.TrustedManufacturerKey = manufacturerKey;
        fixture.DeviceManufacturerHash = FdoHashValue.ComputeDigest(
            FdoHashAlgorithm.Sha256, manufacturerKey.Span).Encode();
        fixture.OwnerSigningKeyOverride = owner;
        fixture.ProvisionedAsymOwnerKey = FdoKeyExchangeSuites.IsAsym(fixture.Exchange)
            ? keys.EncodeRsa(owner, restricted) : ReadOnlyMemory<byte>.Empty;
    }

    [Test]
    [Arguments(256, 0, 1)]
    [Arguments(384, 1, 3)]
    [Arguments(256, 0, 30)]
    [Arguments(384, 1, 31)]
    [Arguments(256, 0, 32)]
    [Arguments(384, 1, 33)]
    [Arguments(256, 0, -17760704)]
    [Arguments(384, 1, -17760706)]
    [Arguments(256, 0, -17760703)]
    [Arguments(384, 1, -17760705)]
    public async Task RunsTheAuthenticatedExchangeAndCommitsBeforeDoneAck(
        int curveSize, int exchangeValue, int cipherValue)
    {
        using var fixture = new Fixture(
            curveSize, (FdoKeyExchangeSuite)exchangeValue, (FdoCoseAeadAlgorithm)cipherValue);
        if (!FdoTo2CipherSuites.IsSupported((FdoCoseAeadAlgorithm)cipherValue))
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() => fixture.CreateSession())).IsTrue();
            await Assert.That(Throws<PlatformNotSupportedException>(() => fixture.CreateDeviceSession())).IsTrue();
            return;
        }

        fixture.ProvideReenrollmentHandler = true;
        FdoDeviceEnrollment result = await fixture.RunAsync();

        ushort[] expected =
        [
            80, 81, 82, 83, 84, 85, 84, 85, 86, 87, 88, 89, 88, 89, 90, 91,
        ];
        await Assert.That(fixture.Transport.Messages.Select(message => message.Type).SequenceEqual(expected)).IsTrue();
        await Assert.That(fixture.Transport.Messages.All(message => message.Version == 200)).IsTrue();
        byte protectedTag = FdoTo2CipherSuites.IsEncryptThenMac(fixture.Cipher) ? (byte)0xD1 : (byte)0xD0;
        await Assert.That(fixture.Transport.Messages.Where(message => message.Type >= 86)
            .All(message => message.Body.Span[0] == protectedTag)).IsTrue();
        await Assert.That(fixture.Events.IndexOf("issue") > fixture.Events.LastIndexOf("wire:88")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("validate") > fixture.Events.LastIndexOf("wire:89")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("commit") > fixture.Events.IndexOf("wire:90")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("commit") < fixture.Events.IndexOf("wire:91")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("install") > fixture.Events.IndexOf("wire:91")).IsTrue();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.ValidationCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
        await Assert.That(result.RunId).IsEqualTo(fixture.DeviceSession!.RunId);
        await Assert.That(fixture.Handler.Request!.RunId).IsEqualTo(fixture.Session!.RunId);
        await Assert.That(fixture.Handler.Committed!.Request.RunId).IsEqualTo(fixture.Session.RunId);
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(result.CertificateSigningRequest.Span.SequenceEqual(fixture.Request)).IsTrue();
        await Assert.That(result.DeviceGuid.Span.SequenceEqual(fixture.Auth.Voucher.Guid)).IsTrue();
        await Assert.That(fixture.Handler.Committed.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Handler.Request.DeviceGuid.Span.SequenceEqual(fixture.Auth.Voucher.Guid)).IsTrue();
        await Assert.That(fixture.Handler.Request.DeviceAttestationCertificate.Span
            .SequenceEqual(fixture.Auth.DeviceCertificate.RawData)).IsTrue();
        await Assert.That(fixture.Handler.Request.CertificateSigningRequest.Span.SequenceEqual(fixture.Request)).IsTrue();
        await Assert.That(fixture.Session.CommittedEnrollment!.Request.RunId).IsEqualTo(fixture.Session.RunId);
        await Assert.That(fixture.Session.DoneAckProduced).IsTrue();
        await Assert.That(fixture.Session.DoneAckHandoffConfirmed).IsTrue();
        await Assert.That(fixture.DeviceSession.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.DeviceSession.InstallationStarted).IsTrue();
        await Assert.That(fixture.DeviceSession.InstalledEnrollment!.RunId).IsEqualTo(result.RunId);
        await Assert.That(result.CaCertificates).IsNull();
        await Assert.That(result.CsrAttributes).IsNull();
        await Assert.That(result.IsReenrollment).IsFalse();
        await Assert.That(result.IsServerKeyGeneration).IsFalse();
        await Assert.That(fixture.Handler.Request.IsReenrollment).IsFalse();
        await Assert.That(fixture.Handler.Request.IsServerKeyGeneration).IsFalse();
        await Assert.That(fixture.Handler.Request.Reenrollment).IsNull();
        await Assert.That(fixture.Handler.Request.CsrAttributes).IsNull();
        await Assert.That(fixture.ReenrollmentHandler.LookupCalls).IsEqualTo(0);
        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(0);
        await Assert.That(fixture.CaHandler.Calls).IsEqualTo(0);
    }

    [Test]
    [Arguments(256, 0, 1)]
    [Arguments(384, 1, 3)]
    public async Task UsesTheInitializedOpaqueHmacHandleForPairedTo2(
        int curveSize, int exchangeValue, int cipherValue)
    {
        using var fixture = new Fixture(
            curveSize, (FdoKeyExchangeSuite)exchangeValue, (FdoCoseAeadAlgorithm)cipherValue);
        FdoDeviceHmacAlgorithm algorithm = curveSize == 256
            ? FdoDeviceHmacAlgorithm.HmacSha256 : FdoDeviceHmacAlgorithm.HmacSha384;
        using var secret = new RecordingVoucherHmacSecret(algorithm);
        using var initialization = new InitializationFixture(fixture, secret);
        FdoDeviceInitializeCredential credential = await initialization.RunAsync();
        FdoManufacturerInitializeVoucher voucher = initialization.Voucher!;
        ReadOnlyMemory<byte> header = new FdoCborCodec().ReadByteStringPayload(voucher.EncodedVoucherHeaderTag);
        using ECDsa approvedOwner = ECDsa.Create(fixture.Auth.Voucher.FinalOwner.ExportParameters(false));
        FdoTransferredOwnershipVoucher transferred = FdoOwnershipVoucherTransfer.Extend(
            voucher.EncodedVoucher, fixture.Auth.Voucher.Manufacturer, approvedOwner);
        await Assert.That(secret.Inputs.Count).IsEqualTo(1);
        await Assert.That(transferred.EncodedVoucherHeaderTag.Span
            .SequenceEqual(voucher.EncodedVoucherHeaderTag.Span)).IsTrue();
        await Assert.That(transferred.EncodedVoucherHeaderHmac.Span
            .SequenceEqual(voucher.EncodedVoucherHeaderHmac.Span)).IsTrue();
        await Assert.That(transferred.EncodedDeviceCertificateChain.Span
            .SequenceEqual(voucher.EncodedDeviceCertificateChain.Span)).IsTrue();
        fixture.InitializedCredential = credential;
        fixture.TransferredVoucher = transferred;
        fixture.OpaqueVoucherSecret = credential.VoucherHmacSecret;
        fixture.IncludeRawVoucherSecret = false;
        secret.MutateInput = true;

        FdoDeviceEnrollment result = await fixture.RunAsync();

        await Assert.That(ReferenceEquals(initialization.InstalledCredential, credential)).IsTrue();
        await Assert.That(ReferenceEquals(credential.VoucherHmacSecret, secret)).IsTrue();
        await Assert.That(secret.Inputs.Count).IsEqualTo(2);
        await Assert.That(secret.Inputs[0].AsSpan().SequenceEqual(header.Span)).IsTrue();
        await Assert.That(secret.Inputs[1].AsSpan().SequenceEqual(header.Span)).IsTrue();
        await Assert.That(result.DeviceGuid.Span.SequenceEqual(credential.DeviceGuid.Span)).IsTrue();
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
        fixture.DeviceSession.Dispose();
        await Assert.That(secret.Disposed).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OwnerOffersBothCiphersAndUsesTheDeviceSelection(bool selectCbc)
    {
        using var fixture = new Fixture(256, FdoKeyExchangeSuite.Ecdh256, selectCbc
            ? FdoCoseAeadAlgorithm.AesCbc128HmacSha256 : FdoCoseAeadAlgorithm.A128Gcm);
        FdoPairedCipherSuite[] additional = [FdoPairedCipherSuite.AesCbc128HmacSha256];
        fixture.OwnerPrimaryCipher = FdoPairedCipherSuite.A128Gcm;
        fixture.OwnerAdditionalCiphers = additional;
        using FdoOwnerSession owner = fixture.CreateSession();
        additional[0] = FdoPairedCipherSuite.A256Gcm;

        await fixture.RunAsync(owner);

        var ack = new FdoTo2InitialCodec().DecodeAcknowledgement(
            fixture.Transport.Messages.Single(message => message.Type == 81).Body);
        await Assert.That(ack.CipherSuites.SequenceEqual(new long[]
        {
            (long)FdoCoseAeadAlgorithm.A128Gcm, (long)FdoCoseAeadAlgorithm.AesCbc128HmacSha256,
        })).IsTrue();
        await Assert.That(ack.KeyExchangeSuites.Count).IsEqualTo(1);
        byte tag = selectCbc ? (byte)0xd1 : (byte)0xd0;
        await Assert.That(fixture.Transport.Messages.First(message => message.Type == 86).Body.Span[0])
            .IsEqualTo(tag);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task UnofferedCipherCannotProceedWithOrWithoutTampering(bool tamperAck)
    {
        using var fixture = new Fixture();
        fixture.OwnerPrimaryCipher = FdoPairedCipherSuite.A256Gcm;
        fixture.OwnerAdditionalCiphers = [FdoPairedCipherSuite.AesCbc128HmacSha256];
        if (tamperAck)
        {
            var codec = new FdoTo2InitialCodec();
            fixture.Transport.Change = (message, _) => message.Type == 81
                ? message with
                {
                    Body = codec.EncodeAcknowledgement(codec.DecodeAcknowledgement(message.Body) with
                    {
                        CipherSuites = [(long)FdoCoseAeadAlgorithm.A128Gcm, (long)FdoCoseAeadAlgorithm.AesCbc128HmacSha256],
                    }),
                }
                : message;
        }

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 82)).IsEqualTo(tamperAck);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type >= 83)).IsFalse();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments("primary")]
    [Arguments("duplicate")]
    [Arguments("unknown")]
    [Arguments("oversized")]
    public async Task RejectsInvalidAdditionalCipherOffersBeforeTheExchange(string invalid)
    {
        using var fixture = new Fixture();
        fixture.OwnerAdditionalCiphers = invalid switch
        {
            "primary" => [FdoPairedCipherSuite.A128Gcm],
            "duplicate" => [FdoPairedCipherSuite.A256Gcm, FdoPairedCipherSuite.A256Gcm],
            "unknown" => [(FdoPairedCipherSuite)int.MaxValue],
            _ => new FdoPairedCipherSuite[10],
        };
        await Assert.That(invalid is "oversized" or "unknown"
            ? Throws<ArgumentOutOfRangeException>(() => fixture.CreateSession())
            : Throws<ArgumentException>(() => fixture.CreateSession())).IsTrue();
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
    }

    [Test]
    public async Task MultiHopTransferredVoucherEnrollsWithFinalOwner()
    {
        using var fixture = new Fixture();
        using ECDsa finalOwner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ReadOnlyMemory<byte> original = FdoInitializationFields.CreateVoucher(
            fixture.Auth.Voucher.HeaderTag, fixture.Auth.Voucher.HeaderHmac, fixture.Auth.EncodedChain);
        FdoTransferredOwnershipVoucher first = FdoOwnershipVoucherTransfer.Extend(
            original, fixture.Auth.Voucher.Manufacturer, fixture.Auth.Voucher.FirstOwner);
        FdoTransferredOwnershipVoucher second = FdoOwnershipVoucherTransfer.Extend(
            first.EncodedVoucher, fixture.Auth.Voucher.FirstOwner, fixture.Auth.Voucher.FinalOwner);
        fixture.TransferredVoucher = FdoOwnershipVoucherTransfer.Extend(
            second.EncodedVoucher, fixture.Auth.Voucher.FinalOwner, finalOwner);
        fixture.OwnerSigningKeyOverride = finalOwner;

        FdoDeviceEnrollment result = await fixture.RunAsync();

        await Assert.That(fixture.TransferredVoucher.EncodedVoucherEntries.Count).IsEqualTo(3);
        FdoPairedMessage[] entries = fixture.Transport.Messages.Where(message => message.Type == 85).ToArray();
        await Assert.That(entries.Length).IsEqualTo(3);
        for (int i = 0; i < entries.Length; i++)
        {
            await Assert.That(FdoPairedProtocol.DecodeEntryResponse(new FdoCborCodec(), entries[i].Body, i).Span
                .SequenceEqual(fixture.TransferredVoucher.EncodedVoucherEntries[i].Span)).IsTrue();
        }
        await Assert.That(result.DeviceGuid.Span.SequenceEqual(fixture.Auth.Voucher.Guid)).IsTrue();
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
        await Assert.That(fixture.Session!.DoneAckHandoffConfirmed).IsTrue();
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task VoucherX5ChainKeepsExactManufacturerDigestAndFinalOwnerBytes(bool normalizedHash)
    {
        using var fixture = new Fixture();
        var keys = new FdoPublicKeyCodec();
        using X509Certificate2 manufacturer = CreateVoucherKeyCertificate(fixture.Auth.Voucher.Manufacturer);
        using X509Certificate2 intermediate = CreateVoucherKeyCertificate(fixture.Auth.Voucher.FirstOwner);
        using X509Certificate2 finalOwner = CreateVoucherKeyCertificate(fixture.Auth.Voucher.FinalOwner);
        ReadOnlyMemory<byte> exactManufacturer = keys.EncodeCertificateChain([manufacturer.RawData]);
        ReadOnlyMemory<byte> exactOwner = keys.EncodeCertificateChain([finalOwner.RawData, intermediate.RawData]);
        byte[] header = fixture.Auth.Voucher.CreateHeaderTag(manufacturerKey: exactManufacturer);
        ReadOnlyMemory<byte> headerContents = new FdoCborCodec().ReadByteStringPayload(header);
        FdoHashValue hmac = FdoHashValue.ComputeHmac(
            fixture.Auth.Voucher.HmacAlgorithm, fixture.Auth.Voucher.Secret, headerContents.Span);
        ReadOnlyMemory<byte> original = FdoInitializationFields.CreateVoucher(header, hmac, fixture.Auth.EncodedChain);
        FdoTransferredOwnershipVoucher first = FdoOwnershipVoucherTransfer.ExtendWithCertificateChain(
            original, fixture.Auth.Voucher.Manufacturer, [intermediate.RawData]);
        FdoTransferredOwnershipVoucher second = FdoOwnershipVoucherTransfer.ExtendWithCertificateChain(
            first.EncodedVoucher, fixture.Auth.Voucher.FirstOwner, [finalOwner.RawData, intermediate.RawData]);
        fixture.TransferredVoucher = second;
        fixture.DeviceManufacturerHash = FdoHashValue.ComputeDigest(FdoHashAlgorithm.Sha256,
            normalizedHash ? keys.Encode(fixture.Auth.Voucher.Manufacturer).Span : exactManufacturer.Span).Encode();

        var rendezvous = new RendezvousFixture(fixture.Auth);
        var owner = new FdoOwnerRendezvousSession(new FdoOwnerRendezvousOptions
        {
            EncodedVoucherHeaderTag = second.EncodedVoucherHeaderTag,
            EncodedVoucherHeaderHmac = second.EncodedVoucherHeaderHmac,
            EncodedVoucherEntries = second.EncodedVoucherEntries,
            EncodedDeviceCertificateChain = second.EncodedDeviceCertificateChain,
            TrustedManufacturerKey = fixture.Auth.Voucher.ManufacturerKey,
            DeviceTrustAnchor = fixture.Auth.RootCertificate.RawData,
            DeviceRevocationMode = X509RevocationMode.NoCheck,
            OwnerSigningKey = fixture.Auth.Voucher.FinalOwner,
            OwnerAddress = rendezvous.Address,
            WaitSeconds = 120,
            UseProvisionalPairedProfile = true,
        });
        using FdoRendezvousServerSession server = rendezvous.CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        await owner.RunAsync(rendezvous.CreateTransport(server));
        fixture.DeviceRendezvous = await rendezvous.LookupAsync();
        fixture.Device = fixture.Device with { AllowRendezvousBypass = false };
        fixture.OwnerBypass = false;
        fixture.OwnerRendezvous = true;
        await Assert.That(server.StoredRegistration!.EncodedOwnerKey.Span.SequenceEqual(exactOwner.Span)).IsTrue();
        if (normalizedHash)
        {
            await CatchAsync<CryptographicException>(fixture.RunAsync);
            await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
            await Assert.That(fixture.InstallCalls).IsEqualTo(0);
            return;
        }

        await fixture.RunAsync();
        using FdoPublicKeyCodec.DecodedKey signingKey = keys.Decode(exactOwner);
        ReadOnlyMemory<byte> proof = fixture.Transport.Messages.Single(message => message.Type == 83).Body;
        var payload = new CborReader(signingKey.VerifySignature(
            new FdoCoseSign1Codec(), FdoSignatureOperation.TO2ProveOVHdr, proof));
        payload.ReadStartArray();
        for (int i = 0; i < 6; i++)
        {
            payload.SkipValue();
        }

        await Assert.That(payload.ReadEncodedValue().Span.SequenceEqual(exactOwner.Span)).IsTrue();
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
    }

    private static X509Certificate2 CreateVoucherKeyCertificate(ECDsa key)
    {
        var request = new CertificateRequest("CN=FDO voucher key", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RequiresExactlyOneVoucherHmacSecretSource(bool provideBoth)
    {
        using var fixture = new Fixture();
        using var secret = new RecordingVoucherHmacSecret(
            FdoDeviceHmacAlgorithm.HmacSha256, fixture.Auth.Voucher.Secret);
        fixture.IncludeRawVoucherSecret = provideBoth;
        fixture.OpaqueVoucherSecret = provideBoth ? secret : null;

        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("algorithm", false)]
    [Arguments("size", false)]
    [Arguments("algorithm", true)]
    [Arguments("size", true)]
    public async Task RejectsInvalidOrChangedOpaqueHmacMetadata(string field, bool changeAfterConstruction)
    {
        using var fixture = new Fixture();
        using var secret = new RecordingVoucherHmacSecret(
            FdoDeviceHmacAlgorithm.HmacSha256, fixture.Auth.Voucher.Secret);
        fixture.IncludeRawVoucherSecret = false;
        fixture.OpaqueVoucherSecret = secret;
        FdoDeviceSession? device = changeAfterConstruction ? fixture.CreateDeviceSession() : null;
        if (field == "algorithm")
        {
            secret.Algorithm = FdoDeviceHmacAlgorithm.HmacSha384;
        }
        else
        {
            secret.KeySizeInBytes--;
        }

        if (!changeAfterConstruction)
        {
            bool rejected = field == "algorithm"
                ? Throws<CryptographicException>(() => fixture.CreateDeviceSession())
                : Throws<ArgumentException>(() => fixture.CreateDeviceSession());
            await Assert.That(rejected).IsTrue();
            await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
        }
        else
        {
            FdoOwnerSession owner = fixture.CreateSession();
            if (field == "algorithm")
            {
                await CatchAsync<CryptographicException>(() => fixture.RunAsync(owner, device!));
            }
            else
            {
                await CatchAsync<ArgumentException>(() => fixture.RunAsync(owner, device!));
            }

            await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 84)).IsFalse();
        }

        await Assert.That(secret.Inputs.Count).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments("signature")]
    [Arguments("manufacturer")]
    public async Task ChecksTheEarlyProofAndManufacturerBeforeUsingTheOpaqueHandle(string scenario)
    {
        using var fixture = new Fixture();
        using var secret = new RecordingVoucherHmacSecret(
            FdoDeviceHmacAlgorithm.HmacSha256, fixture.Auth.Voucher.Secret);
        fixture.IncludeRawVoucherSecret = false;
        fixture.OpaqueVoucherSecret = secret;
        if (scenario == "signature")
        {
            fixture.Transport.Change = (message, _) =>
            {
                if (message.Type == 83)
                {
                    byte[] changed = message.Body.ToArray();
                    changed[^1] ^= 1;
                    return message with { Body = changed };
                }

                return message;
            };
        }
        else
        {
            byte[] wrongHash = fixture.Auth.Voucher.ManufacturerHash.Value;
            wrongHash[0] ^= 1;
            fixture.DeviceManufacturerHash = new FdoHashValue(
                fixture.Auth.Voucher.ManufacturerHash.Algorithm, wrongHash).Encode();
        }

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(secret.Inputs.Count).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 84)).IsFalse();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments("wrong")]
    [Arguments("short")]
    [Arguments("throws")]
    [Arguments("cancel")]
    public async Task OpaqueHmacFailuresStopBeforeVoucherEntryRequests(string scenario)
    {
        using var fixture = new Fixture();
        using var secret = new RecordingVoucherHmacSecret(
            FdoDeviceHmacAlgorithm.HmacSha256, fixture.Auth.Voucher.Secret);
        using var cancellation = new CancellationTokenSource();
        fixture.IncludeRawVoucherSecret = false;
        fixture.OpaqueVoucherSecret = secret;
        secret.CorruptResult = scenario == "wrong";
        secret.ShortResult = scenario == "short";
        secret.ThrowOnCompute = scenario == "throws";
        secret.AfterCompute = scenario == "cancel" ? cancellation.Cancel : null;

        if (scenario == "throws")
        {
            await CatchAsync<InvalidOperationException>(() => fixture.RunAsync(cancellation.Token));
        }
        else if (scenario == "cancel")
        {
            await CatchAsync<OperationCanceledException>(() => fixture.RunAsync(cancellation.Token));
        }
        else
        {
            await CatchAsync<CryptographicException>(() => fixture.RunAsync(cancellation.Token));
        }

        await Assert.That(secret.Inputs.Count).IsEqualTo(1);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 84)).IsFalse();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task OpaqueHmacDoesNotReplaceVoucherEntryVerification()
    {
        using var fixture = new Fixture();
        using var secret = new RecordingVoucherHmacSecret(
            FdoDeviceHmacAlgorithm.HmacSha256, fixture.Auth.Voucher.Secret);
        fixture.IncludeRawVoucherSecret = false;
        fixture.OpaqueVoucherSecret = secret;
        fixture.Transport.Change = (message, count) =>
        {
            if (message.Type == 85 && count == 1)
            {
                byte[] changed = message.Body.ToArray();
                changed[^1] ^= 1;
                return message with { Body = changed };
            }

            return message;
        };

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(secret.Inputs.Count).IsEqualTo(1);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type >= 86)).IsFalse();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task ServerKeyGenerationUsesIndependentAuthorizationAndInstallsOnlyAfterDoneAck(
        bool withCaCertificates, bool withAttributes)
    {
        using var fixture = new Fixture();
        fixture.RequestServerKeyGeneration = true;
        fixture.ProvideServerKeyGeneration = true;
        fixture.RequestCaCertificates = withCaCertificates;
        fixture.ProvideCaCertificates = withCaCertificates;
        fixture.RequestCsrAttributes = withAttributes;
        fixture.ProvideCsrAttributes = withAttributes;
        fixture.Request[^1] ^= 1;
        ReadOnlyMemory<byte> deliveredKey = default;
        fixture.OnServerKeyInstall = value => deliveredKey = value;

        FdoDeviceEnrollment result = await fixture.RunAsync();

        using X509Certificate2 certificate = FdoDerEncoding.LoadCertificate(result.Certificate);
        await Assert.That(certificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan()
            .SequenceEqual(fixture.EnrollmentKey.ExportSubjectPublicKeyInfo())).IsFalse();
        await Assert.That(result.IsServerKeyGeneration).IsTrue();
        await Assert.That(result.IsReenrollment).IsFalse();
        await Assert.That(result.CertificateSigningRequest.Span.SequenceEqual(fixture.Request)).IsTrue();
        await Assert.That(fixture.ServerKeygenHandler.Request!.IsServerKeyGeneration).IsTrue();
        await Assert.That(fixture.ServerKeygenHandler.Request.DeviceGuid.Span
            .SequenceEqual(fixture.Auth.Voucher.Guid)).IsTrue();
        await Assert.That(fixture.ServerKeygenHandler.Request.DeviceAttestationCertificate.Span
            .SequenceEqual(fixture.Auth.DeviceCertificate.RawData)).IsTrue();
        await Assert.That(fixture.ServerKeygenHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.Committed!.Request.IsServerKeyGeneration).IsTrue();
        await Assert.That(fixture.ValidationCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
        await Assert.That(fixture.ServerKeyInstallCalls).IsEqualTo(1);
        await Assert.That(fixture.Events.IndexOf("validate") < fixture.Events.IndexOf("commit")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("commit") < fixture.Events.IndexOf("wire:91")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("wire:91") < fixture.Events.IndexOf("install-server-key")).IsTrue();
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.DeviceSession.InstalledEnrollment!.IsServerKeyGeneration).IsTrue();
        await Assert.That(deliveredKey.IsEmpty).IsFalse();
        await Assert.That(deliveredKey.Span.IndexOfAnyExcept((byte)0)).IsEqualTo(-1);
        if (withAttributes)
        {
            await Assert.That(fixture.DeviceAttributesHandler.Request!.IsServerKeyGeneration).IsTrue();
            await Assert.That(fixture.ServerKeygenHandler.Request.CsrAttributes).IsNotNull();
        }
    }

    [Test]
    public async Task UnsupportedServerKeyGenerationReturnsErrorWithoutIssuance()
    {
        using var fixture = new Fixture();
        fixture.RequestServerKeyGeneration = true;

        FdoCsrModuleException error = await CatchAsync<FdoCsrModuleException>(fixture.RunAsync);

        await Assert.That(error.ErrorCode).IsEqualTo(3UL);
        await Assert.That(fixture.ServerKeygenHandler.Calls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.ServerKeyInstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task ServerKeyAuthorizationAndDeviceTrustAreRequiredIndependently()
    {
        using var rejected = new Fixture();
        rejected.RequestServerKeyGeneration = true;
        rejected.ProvideServerKeyGeneration = true;
        rejected.ServerKeygenHandler.Reject = true;
        FdoPeerErrorException rejection = await CatchAsync<FdoPeerErrorException>(rejected.RunAsync);
        await Assert.That(rejection.ErrorCode).IsEqualTo((ushort)500);
        await Assert.That(rejected.Session!.SentErrorCode).IsEqualTo((ushort)500);

        using var untrusted = new Fixture();
        using var other = new Fixture();
        untrusted.RequestServerKeyGeneration = true;
        untrusted.ProvideServerKeyGeneration = true;
        untrusted.TrustedManufacturerKey = other.Auth.Voucher.ManufacturerKey;
        untrusted.DeviceTrustAnchor = other.Auth.RootCertificate.RawData;
        await CatchAsync<CryptographicException>(untrusted.RunAsync);

        await Assert.That(rejected.ServerKeygenHandler.Calls).IsEqualTo(1);
        await Assert.That(rejected.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(rejected.ServerKeyInstallCalls).IsEqualTo(0);
        await Assert.That(untrusted.ServerKeygenHandler.Calls).IsEqualTo(0);
        await Assert.That(untrusted.ServerKeyInstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task ServerKeyMismatchAndOversizeResponseStopBeforeValidationOrCommit()
    {
        using var mismatch = new Fixture();
        mismatch.RequestServerKeyGeneration = true;
        mismatch.ProvideServerKeyGeneration = true;
        mismatch.ServerKeygenHandler.Mismatch = true;
        await ExpectPeerErrorAsync(mismatch.RunAsync, 101, FdoTo2MessageType.DeviceSvcInfo20);

        using var oversized = new Fixture();
        oversized.RequestServerKeyGeneration = true;
        oversized.ProvideServerKeyGeneration = true;
        oversized.Device = new TestDeviceSettings(true, true, 8192, 300);
        await ExpectPeerErrorAsync(oversized.RunAsync, 100, FdoTo2MessageType.DeviceSvcInfo20);

        foreach (Fixture fixture in new[] { mismatch, oversized })
        {
            await Assert.That(fixture.ServerKeygenHandler.Calls).IsEqualTo(1);
            await Assert.That(fixture.ValidationCalls).IsEqualTo(0);
            await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
            await Assert.That(fixture.ServerKeyInstallCalls).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments(89, 2, false)]
    [Arguments(91, 1, true)]
    public async Task TamperedServerKeyResponseOrDoneAckNeverInstalls(
        ushort messageType, int occurrence, bool committed)
    {
        using var fixture = new Fixture();
        fixture.RequestServerKeyGeneration = true;
        fixture.ProvideServerKeyGeneration = true;
        fixture.Transport.Change = (message, count) =>
        {
            if (message.Type == messageType && count == occurrence)
            {
                byte[] changed = message.Body.ToArray();
                changed[^1] ^= 1;
                return message with { Body = changed };
            }

            return message;
        };

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.ServerKeygenHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(committed ? 1 : 0);
        await Assert.That(fixture.ServerKeyInstallCalls).IsEqualTo(0);
        await Assert.That(fixture.DeviceSession!.InstalledEnrollment).IsNull();
    }

    [Test]
    public async Task CancellationAfterServerKeyIssuancePreventsCommitAndInstallation()
    {
        using var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        fixture.RequestServerKeyGeneration = true;
        fixture.ProvideServerKeyGeneration = true;
        fixture.ServerKeygenHandler.OnSucceeded = cancellation.Cancel;

        await CatchAsync<OperationCanceledException>(() => fixture.RunAsync(cancellation.Token));

        await Assert.That(fixture.ServerKeygenHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.ServerKeyInstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task FailedServerKeyInstallationLeavesNoReceiptAndClearsTheBorrowedKey()
    {
        using var fixture = new Fixture();
        fixture.RequestServerKeyGeneration = true;
        fixture.ProvideServerKeyGeneration = true;
        fixture.RejectInstallation = true;
        ReadOnlyMemory<byte> deliveredKey = default;
        fixture.OnServerKeyInstall = value => deliveredKey = value;

        await CatchAsync<InvalidOperationException>(fixture.RunAsync);

        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.DeviceSession.InstallationStarted).IsTrue();
        await Assert.That(fixture.DeviceSession.InstalledEnrollment).IsNull();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.ServerKeyInstallCalls).IsEqualTo(1);
        await Assert.That(deliveredKey.IsEmpty).IsFalse();
        await Assert.That(deliveredKey.Span.IndexOfAnyExcept((byte)0)).IsEqualTo(-1);
    }

    [Test]
    public async Task ServerKeyGenerationCannotSelectSimpleReenrollment()
    {
        using var fixture = new Fixture();
        fixture.RequestServerKeyGeneration = true;
        fixture.RequestReenrollment = true;

        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        await Assert.That(fixture.ServerKeygenHandler.Calls).IsEqualTo(0);
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task DiscoversAttributesBeforeHostCreatesCsrAndPreservesEvidence(
        bool withCaCertificates, bool isReenrollment)
    {
        using var fixture = new Fixture();
        byte[] originalCsr = (byte[])fixture.Request.Clone();
        fixture.RequestCsrAttributes = true;
        fixture.ProvideCsrAttributes = true;
        fixture.RequestCaCertificates = withCaCertificates;
        fixture.ProvideCaCertificates = withCaCertificates;
        fixture.RequestReenrollment = isReenrollment;
        fixture.ProvideReenrollmentHandler = isReenrollment;
        fixture.OwnerAttributesHandler.MutateSnapshots = true;
        fixture.DeviceAttributesHandler.MutateSnapshots = true;
        fixture.DeviceAttributesHandler.GenerateRequest = true;

        FdoDeviceEnrollment result = await fixture.RunAsync();

        await Assert.That(fixture.OwnerAttributesHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.DeviceAttributesHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
        await Assert.That(fixture.Events.IndexOf("owner-attributes") < fixture.Events.IndexOf("device-attributes")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("device-attributes") < fixture.Events.IndexOf("issue")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("commit") < fixture.Events.IndexOf("wire:91")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("install") > fixture.Events.IndexOf("wire:91")).IsTrue();
        if (withCaCertificates)
        {
            await Assert.That(fixture.Events.IndexOf("ca") < fixture.Events.IndexOf("owner-attributes")).IsTrue();
            await Assert.That(fixture.DeviceAttributesHandler.Request!.CaCertificates!.Certificates[0].Span
                .SequenceEqual(fixture.Auth.RootCertificate.RawData)).IsTrue();
        }
        else
        {
            await Assert.That(fixture.DeviceAttributesHandler.Request!.CaCertificates).IsNull();
        }

        if (isReenrollment)
        {
            await Assert.That(fixture.Events.IndexOf("device-attributes") < fixture.Events.IndexOf("lookup")).IsTrue();
            await Assert.That(fixture.ReenrollmentHandler.LookupRequest!.CsrAttributes!.EncodedValue.Span
                .SequenceEqual(fixture.OwnerAttributesHandler.EncodedAttributes)).IsTrue();
        }

        await Assert.That(fixture.DeviceAttributesHandler.Request!.RunId).IsEqualTo(fixture.DeviceSession!.RunId);
        await Assert.That(fixture.DeviceAttributesHandler.Request.IsReenrollment).IsEqualTo(isReenrollment);
        await Assert.That(fixture.DeviceAttributesHandler.Request.DeviceGuid.Span
            .SequenceEqual(fixture.Auth.Voucher.Guid)).IsTrue();
        await Assert.That(fixture.OwnerAttributesHandler.Request!.RunId).IsEqualTo(fixture.Session!.RunId);
        await Assert.That(fixture.OwnerAttributesHandler.Request.DeviceGuid.Span
            .SequenceEqual(fixture.Auth.Voucher.Guid)).IsTrue();
        await Assert.That(fixture.OwnerAttributesHandler.Request.DeviceAttestationCertificate.Span
            .SequenceEqual(fixture.Auth.DeviceCertificate.RawData)).IsTrue();
        await Assert.That(fixture.Request.AsSpan().SequenceEqual(originalCsr)).IsFalse();
        await Assert.That(result.CertificateSigningRequest.Span.SequenceEqual(fixture.Request)).IsTrue();
        await Assert.That(fixture.Handler.Request!.CertificateSigningRequest.Span
            .SequenceEqual(fixture.Request)).IsTrue();
        await Assert.That(result.CsrAttributes!.EncodedValue.Span
            .SequenceEqual(fixture.OwnerAttributesHandler.EncodedAttributes)).IsTrue();
        await Assert.That(fixture.Handler.Committed!.Request.CsrAttributes!.EncodedValue.Span
            .SequenceEqual(fixture.OwnerAttributesHandler.EncodedAttributes)).IsTrue();
        await Assert.That(result.CsrAttributes.Entries[1].ObjectIdentifier).IsEqualTo("1.2.840.10045.2.1");
        await Assert.That(fixture.DeviceSession.DoneAckAuthenticated).IsTrue();
    }

    [Test]
    public async Task UnsupportedAttributeDiscoveryReturnsErrorBeforeDeviceOrEnrollmentCallbacks()
    {
        using var fixture = new Fixture();
        fixture.RequestCsrAttributes = true;

        FdoCsrModuleException error = await CatchAsync<FdoCsrModuleException>(fixture.RunAsync);

        await Assert.That(error.ErrorCode).IsEqualTo(3UL);
        await Assert.That(fixture.OwnerAttributesHandler.Calls).IsEqualTo(0);
        await Assert.That(fixture.DeviceAttributesHandler.Calls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task RejectingAttributeCallbacksStopBeforeIssuance(bool rejectOwner)
    {
        using var fixture = new Fixture();
        fixture.RequestCsrAttributes = true;
        fixture.ProvideCsrAttributes = true;
        fixture.OwnerAttributesHandler.Reject = rejectOwner;
        fixture.DeviceAttributesHandler.Reject = !rejectOwner;

        if (rejectOwner)
        {
            await ExpectPeerErrorAsync(fixture.RunAsync, 500, FdoTo2MessageType.DeviceSvcInfo20);
        }
        else
        {
            await CatchAsync<InvalidOperationException>(fixture.RunAsync);
        }

        await Assert.That(fixture.OwnerAttributesHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.DeviceAttributesHandler.Calls).IsEqualTo(rejectOwner ? 0 : 1);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task AttributeDisclosureDoesNotAuthorizeIssuance()
    {
        using var fixture = new Fixture();
        fixture.RequestCsrAttributes = true;
        fixture.ProvideCsrAttributes = true;
        fixture.Handler.FailIssue = true;

        await ExpectPeerErrorAsync(fixture.RunAsync, 500, FdoTo2MessageType.DeviceSvcInfo20);

        await Assert.That(fixture.OwnerAttributesHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.DeviceAttributesHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task CancellationAfterAnAttributeCallbackPreventsTheNextCallback(bool cancelOwner)
    {
        using var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        fixture.RequestCsrAttributes = true;
        fixture.ProvideCsrAttributes = true;
        if (cancelOwner)
        {
            fixture.OwnerAttributesHandler.OnSucceeded = cancellation.Cancel;
        }
        else
        {
            fixture.DeviceAttributesHandler.OnSucceeded = cancellation.Cancel;
        }

        await CatchAsync<OperationCanceledException>(() => fixture.RunAsync(cancellation.Token));

        await Assert.That(fixture.OwnerAttributesHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.DeviceAttributesHandler.Calls).IsEqualTo(cancelOwner ? 0 : 1);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(88, 2, false)]
    [Arguments(89, 2, true)]
    public async Task TamperedAttributeMessagesStopBeforeDeviceCsrCreation(
        ushort messageType, int occurrence, bool ownerCalled)
    {
        using var fixture = new Fixture();
        fixture.RequestCsrAttributes = true;
        fixture.ProvideCsrAttributes = true;
        fixture.Transport.Change = (message, count) =>
        {
            if (message.Type == messageType && count == occurrence)
            {
                byte[] changed = message.Body.ToArray();
                changed[^1] ^= 1;
                return message with { Body = changed };
            }

            return message;
        };

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.OwnerAttributesHandler.Calls).IsEqualTo(ownerCalled ? 1 : 0);
        await Assert.That(fixture.DeviceAttributesHandler.Calls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task UntrustedDeviceCannotInvokeTheAttributeProvider()
    {
        using var fixture = new Fixture();
        using var other = new Fixture();
        fixture.RequestCsrAttributes = true;
        fixture.ProvideCsrAttributes = true;
        fixture.TrustedManufacturerKey = other.Auth.Voucher.ManufacturerKey;
        fixture.DeviceTrustAnchor = other.Auth.RootCertificate.RawData;

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.OwnerAttributesHandler.Calls).IsEqualTo(0);
        await Assert.That(fixture.DeviceAttributesHandler.Calls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task AttributeResponseHonorsTheExactNegotiatedPlaintextLimit()
    {
        using var accepted = new Fixture();
        accepted.RequestCsrAttributes = true;
        accepted.ProvideCsrAttributes = true;
        accepted.OwnerAttributesHandler.EncodedAttributes = AttributesWithOctets(1024);
        int exact = AttributesResponseSize(accepted);
        accepted.Device = accepted.Device with { MaxOwnerServiceInfoSize = (ushort)exact };

        FdoDeviceEnrollment result = await accepted.RunAsync();

        await Assert.That(result.CsrAttributes!.EncodedValue.Span
            .SequenceEqual(accepted.OwnerAttributesHandler.EncodedAttributes)).IsTrue();
        await Assert.That(accepted.Handler.CommitCalls).IsEqualTo(1);

        using var rejected = new Fixture();
        rejected.RequestCsrAttributes = true;
        rejected.ProvideCsrAttributes = true;
        rejected.OwnerAttributesHandler.EncodedAttributes = AttributesWithOctets(1024);
        rejected.Device = rejected.Device with { MaxOwnerServiceInfoSize = (ushort)(AttributesResponseSize(rejected) - 1) };

        await ExpectPeerErrorAsync(rejected.RunAsync, 100, FdoTo2MessageType.DeviceSvcInfo20);

        await Assert.That(rejected.OwnerAttributesHandler.Calls).IsEqualTo(1);
        await Assert.That(rejected.DeviceAttributesHandler.Calls).IsEqualTo(0);
        await Assert.That(rejected.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(rejected.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task InvalidOrConflictingCsrSourcesAreRejectedWithoutIssuance()
    {
        using var conflicting = new Fixture();
        conflicting.RequestCsrAttributes = true;
        conflicting.ConflictingDeviceCsr = true;
        await Assert.That(Throws<ArgumentException>(() => conflicting.CreateDeviceSession())).IsTrue();

        using var absent = new Fixture();
        absent.Request = [];
        await Assert.That(Throws<ArgumentException>(() => absent.CreateDeviceSession())).IsTrue();

        using var invalid = new Fixture();
        invalid.RequestCsrAttributes = true;
        invalid.ProvideCsrAttributes = true;
        invalid.DeviceAttributesHandler.RequestOverride = [0x30, 0x00];
        await CatchAsync<CryptographicException>(invalid.RunAsync);
        await Assert.That(invalid.DeviceAttributesHandler.Calls).IsEqualTo(1);
        await Assert.That(invalid.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(invalid.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task OwnerIgnoresTheAttributeRequestValueAndRejectsADuplicate()
    {
        using var fixture = new Fixture();
        fixture.ProvideCsrAttributes = true;
        FdoOwnerSession owner = fixture.CreateSession();
        using FdoTo2PairedAeadChannel channel = await ActivateOwnerAsync(fixture, owner);
        var info = new FdoTo2ServiceInfoCodec();
        var value = new CborWriter(CborConformanceMode.Canonical);
        value.WriteUInt64(ulong.MaxValue);
        var attributeRequest = new FdoServiceInfoCodec.Entry("fdo.csr:csrattrs-req", value.Encode());
        FdoOwnerResponse first = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false,
            [
                new FdoServiceInfoCodec.Entry("fdo.csr:active", new byte[] { 0xF5 }),
                attributeRequest,
            ])));
        FdoTo2ServiceInfoCodec.OwnerServiceInfo response = info.DecodeOwner(channel.Open(first.EncodedBody));

        await Assert.That(response.ServiceInfo.Single().Key).IsEqualTo("fdo.csr:csrattrs-res");
        await Assert.That(fixture.OwnerAttributesHandler.Calls).IsEqualTo(1);
        await ExpectOwnerErrorAsync(
            owner, channel, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false, [attributeRequest])), 100);
        await Assert.That(fixture.OwnerAttributesHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task OwnerRejectsCaDistributionAfterAttributeDiscovery()
    {
        using var fixture = new Fixture();
        fixture.ProvideCsrAttributes = true;
        fixture.ProvideCaCertificates = true;
        FdoOwnerSession owner = fixture.CreateSession();
        using FdoTo2PairedAeadChannel channel = await ActivateOwnerAsync(fixture, owner);
        var info = new FdoTo2ServiceInfoCodec();
        FdoOwnerResponse first = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false,
            [
                new FdoServiceInfoCodec.Entry("fdo.csr:active", new byte[] { 0xF5 }),
                FdoCsrAttributesRequestCodec.Encode(),
            ])));
        _ = channel.Open(first.EncodedBody);

        await ExpectOwnerErrorAsync(
            owner, channel, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false, [FdoCsrCaCertificatesCodec.EncodeRequest()])), 100);

        await Assert.That(fixture.OwnerAttributesHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.CaHandler.Calls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RenewalBindsThePriorCertificateThroughCommitAndInstallation(bool withCaCertificates)
    {
        using var fixture = new Fixture();
        fixture.RequestReenrollment = true;
        fixture.ProvideReenrollmentHandler = true;
        fixture.RequestCaCertificates = withCaCertificates;
        fixture.ProvideCaCertificates = withCaCertificates;
        byte[] prior = IssueCertificate(fixture, fixture.EnrollmentKey, "CN=FDO enrollment", null);
        fixture.ReenrollmentHandler.PriorCertificate = prior;

        FdoDeviceEnrollment result = await fixture.RunAsync();

        await Assert.That(fixture.ReenrollmentHandler.LookupCalls).IsEqualTo(1);
        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(0);
        await Assert.That(fixture.ReenrollmentHandler.LookupRequest!.IsReenrollment).IsTrue();
        await Assert.That(fixture.ReenrollmentHandler.LookupRequest.Reenrollment).IsNull();
        await Assert.That(fixture.Handler.Request!.Reenrollment!.Kind).IsEqualTo(FdoReenrollmentKind.Renewal);
        await Assert.That(fixture.Handler.Request.Reenrollment.PriorCertificate.Span.SequenceEqual(prior)).IsTrue();
        await Assert.That(fixture.Handler.Request.Reenrollment.IdentityChange).IsNull();
        await Assert.That(fixture.Handler.Committed!.Request.Reenrollment!.PriorCertificate.Span
            .SequenceEqual(prior)).IsTrue();
        await Assert.That(fixture.Events.IndexOf("lookup") > fixture.Events.IndexOf("wire:89")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("lookup") < fixture.Events.IndexOf("issue")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("issue") < fixture.Events.IndexOf("commit")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("commit") < fixture.Events.IndexOf("wire:91")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("install") > fixture.Events.IndexOf("wire:91")).IsTrue();
        await Assert.That(fixture.CaHandler.Calls).IsEqualTo(withCaCertificates ? 1 : 0);
        if (withCaCertificates)
        {
            await Assert.That(fixture.Events.IndexOf("ca") < fixture.Events.IndexOf("lookup")).IsTrue();
            await Assert.That(result.CaCertificates).IsNotNull();
        }

        await Assert.That(result.IsReenrollment).IsTrue();
        await Assert.That(fixture.ValidatedReenrollment).IsEqualTo(true);
        await Assert.That(fixture.InstalledReenrollment).IsEqualTo(true);
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Session!.DoneAckHandoffConfirmed).IsTrue();
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
    }

    [Test]
    public async Task RekeyIsClassifiedUsingTheHostSelectedPriorCertificateKey()
    {
        using var fixture = new Fixture();
        using ECDsa priorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] prior = IssueCertificate(fixture, priorKey, "CN=FDO enrollment", null);
        fixture.RequestReenrollment = true;
        fixture.ProvideReenrollmentHandler = true;
        fixture.ReenrollmentHandler.PriorCertificate = prior;

        await fixture.RunAsync();

        await Assert.That(fixture.Handler.Request!.Reenrollment!.Kind).IsEqualTo(FdoReenrollmentKind.Rekey);
        await Assert.That(fixture.Handler.Committed!.Request.Reenrollment!.PriorCertificate.Span
            .SequenceEqual(prior)).IsTrue();
        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task MissingOrRejectedPriorLookupStopsBeforeIssuance(bool configured)
    {
        using var fixture = new Fixture();
        fixture.RequestReenrollment = true;
        fixture.ProvideReenrollmentHandler = configured;
        fixture.ReenrollmentHandler.RejectLookup = configured;

        await ExpectPeerErrorAsync(fixture.RunAsync, 500, FdoTo2MessageType.DeviceSvcInfo20);

        await Assert.That(fixture.ReenrollmentHandler.LookupCalls).IsEqualTo(configured ? 1 : 0);
        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task InvalidOrOversizedPriorCertificateStopsBeforeIssuance(int scenario)
    {
        using var fixture = new Fixture();
        fixture.RequestReenrollment = true;
        fixture.ProvideReenrollmentHandler = true;
        fixture.ReenrollmentHandler.PriorCertificate = scenario switch
        {
            0 => [],
            1 => [0x30, 0x00],
            _ => new byte[ushort.MaxValue + 1],
        };

        await ExpectPeerErrorAsync(fixture.RunAsync, 101, FdoTo2MessageType.DeviceSvcInfo20);

        await Assert.That(fixture.ReenrollmentHandler.LookupCalls).IsEqualTo(1);
        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments("subject")]
    [Arguments("missing-san")]
    [Arguments("different-san")]
    [Arguments("unexpected-san")]
    public async Task OrdinaryCsrIdentityMustMatchThePriorCertificateBeforeApproval(string mismatch)
    {
        using var fixture = new Fixture();
        string? priorDns = mismatch == "unexpected-san" ? null : "prior.example.invalid";
        string? requestDns = mismatch switch
        {
            "missing-san" => null,
            "different-san" or "unexpected-san" => "different.example.invalid",
            _ => priorDns,
        };
        string requestSubject = mismatch == "subject" ? "CN=other" : "CN=FDO enrollment";
        fixture.RequestReenrollment = true;
        fixture.ProvideReenrollmentHandler = true;
        fixture.ReenrollmentHandler.PriorCertificate = IssueCertificate(
            fixture, fixture.EnrollmentKey, "CN=FDO enrollment", priorDns);
        fixture.Request = CreateCsr(fixture.EnrollmentKey, requestSubject, requestDns,
            IdentityChange("CN=approved", "approved.example.invalid"));

        await ExpectPeerErrorAsync(fixture.RunAsync, 101, FdoTo2MessageType.DeviceSvcInfo20);

        await Assert.That(fixture.ReenrollmentHandler.LookupCalls).IsEqualTo(1);
        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task ApprovedIdentityChangeRemainsDetachedAndBoundThroughCommit()
    {
        using var fixture = new Fixture();
        const string oldName = "prior.example.invalid";
        const string newName = "approved.example.invalid";
        byte[] prior = IssueCertificate(fixture, fixture.EnrollmentKey, "CN=FDO enrollment", oldName);
        byte[] change = IdentityChange("CN=approved", newName);
        byte[] expectedSubject = new X500DistinguishedName("CN=approved").RawData;
        byte[] expectedNames = DnsNames(newName).RawData;
        fixture.RequestReenrollment = true;
        fixture.ProvideReenrollmentHandler = true;
        fixture.ReenrollmentHandler.PriorCertificate = prior;
        fixture.ReenrollmentHandler.MutateSnapshots = true;
        fixture.Handler.MutateSnapshots = true;
        fixture.Request = CreateCsr(fixture.EnrollmentKey, "CN=FDO enrollment", oldName, change);
        fixture.Handler.CertificateOverride = IssueCertificate(fixture, fixture.EnrollmentKey, "CN=approved", newName);

        FdoDeviceEnrollment result = await fixture.RunAsync();

        FdoEnrollmentRequest approved = fixture.ReenrollmentHandler.ApprovalRequest!;
        FdoReenrollmentDetails details = fixture.Handler.Committed!.Request.Reenrollment!;
        await Assert.That(fixture.ReenrollmentHandler.LookupCalls).IsEqualTo(1);
        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(1);
        await Assert.That(fixture.Events.IndexOf("lookup") < fixture.Events.IndexOf("approve")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("approve") < fixture.Events.IndexOf("issue")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("issue") < fixture.Events.IndexOf("commit")).IsTrue();
        await Assert.That(approved.CertificateSigningRequest.Span.SequenceEqual(fixture.Request)).IsTrue();
        await Assert.That(details.Kind).IsEqualTo(FdoReenrollmentKind.Renewal);
        await Assert.That(details.PriorCertificate.Span.SequenceEqual(prior)).IsTrue();
        await Assert.That(details.IdentityChange!.EncodedValue.Span.SequenceEqual(change)).IsTrue();
        await Assert.That(details.IdentityChange.SubjectName.Span.SequenceEqual(expectedSubject)).IsTrue();
        await Assert.That(details.IdentityChange.SubjectAlternativeNames!.Value.Span
            .SequenceEqual(expectedNames)).IsTrue();
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Handler.CertificateOverride!)).IsTrue();
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
    }

    [Test]
    public async Task RejectedIdentityChangeStopsBeforeIssuance()
    {
        using var fixture = new Fixture();
        fixture.RequestReenrollment = true;
        fixture.ProvideReenrollmentHandler = true;
        fixture.ReenrollmentHandler.RejectChange = true;
        fixture.Request = CreateCsr(fixture.EnrollmentKey, "CN=FDO enrollment", null,
            IdentityChange("CN=unapproved", null));

        await ExpectPeerErrorAsync(fixture.RunAsync, 500, FdoTo2MessageType.DeviceSvcInfo20);

        await Assert.That(fixture.ReenrollmentHandler.LookupCalls).IsEqualTo(1);
        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task MalformedRequestedNameStopsBeforeIdentityApprovalAndIssuance()
    {
        using var fixture = new Fixture();
        fixture.RequestReenrollment = true;
        fixture.ProvideReenrollmentHandler = true;
        fixture.Request = CreateCsr(fixture.EnrollmentKey, "CN=FDO enrollment", null,
            [0x30, 0x04, 0x30, 0x02, 0xA4, 0x00]);

        await ExpectPeerErrorAsync(fixture.RunAsync, 101, FdoTo2MessageType.DeviceSvcInfo20);

        await Assert.That(fixture.ReenrollmentHandler.LookupCalls).IsEqualTo(1);
        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task IssuedIdentityMustMatchThePriorOrApprovedIdentity(bool hasApprovedChange)
    {
        using var fixture = new Fixture();
        fixture.RequestReenrollment = true;
        fixture.ProvideReenrollmentHandler = true;
        if (hasApprovedChange)
        {
            fixture.Request = CreateCsr(fixture.EnrollmentKey, "CN=FDO enrollment", null,
                IdentityChange("CN=approved", null));
        }

        fixture.Handler.CertificateOverride = IssueCertificate(
            fixture, fixture.EnrollmentKey, "CN=not approved", null);

        await ExpectPeerErrorAsync(fixture.RunAsync, 101, FdoTo2MessageType.DeviceSvcInfo20);

        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(hasApprovedChange ? 1 : 0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.ValidationCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CancellationAfterLookupOrApprovalStopsTheNextCallback(bool afterApproval)
    {
        using var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        fixture.RequestReenrollment = true;
        fixture.ProvideReenrollmentHandler = true;
        fixture.Request = CreateCsr(fixture.EnrollmentKey, "CN=FDO enrollment", null,
            IdentityChange("CN=approved", null));
        if (afterApproval)
        {
            fixture.ReenrollmentHandler.OnApprovalSucceeded = cancellation.Cancel;
        }
        else
        {
            fixture.ReenrollmentHandler.OnLookupSucceeded = cancellation.Cancel;
        }

        await CatchAsync<OperationCanceledException>(() => fixture.RunAsync(cancellation.Token));

        await Assert.That(fixture.ReenrollmentHandler.LookupCalls).IsEqualTo(1);
        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(afterApproval ? 1 : 0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(82, 1)]
    [Arguments(88, 1)]
    [Arguments(88, 2)]
    public async Task TamperingBeforeReenrollmentPreventsHostCallbacks(ushort messageType, int occurrence)
    {
        using var fixture = new Fixture();
        fixture.RequestReenrollment = true;
        fixture.ProvideReenrollmentHandler = true;
        fixture.Transport.Change = (message, count) =>
        {
            if (message.Type == messageType && count == occurrence)
            {
                byte[] changed = message.Body.ToArray();
                changed[^1] ^= 1;
                return message with { Body = changed };
            }

            return message;
        };

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.ReenrollmentHandler.LookupCalls).IsEqualTo(0);
        await Assert.That(fixture.ReenrollmentHandler.ApprovalCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task DistributesCaCertificatesAndCrlsBeforeEnrollmentAndInstallsOnlyAfterDoneAck()
    {
        using var fixture = new Fixture();
        fixture.RequestCaCertificates = true;
        fixture.ProvideCaCertificates = true;
        fixture.CaHandler.MutateSnapshots = true;
        fixture.MutateCaSnapshots = true;

        FdoDeviceEnrollment result = await fixture.RunAsync();

        ushort[] expected =
        [
            80, 81, 82, 83, 84, 85, 84, 85, 86, 87, 88, 89, 88, 89, 88, 89, 90, 91,
        ];
        await Assert.That(fixture.Transport.Messages.Select(message => message.Type).SequenceEqual(expected)).IsTrue();
        await Assert.That(fixture.Transport.Messages.Where(message => message.Type >= 86)
            .All(message => message.Body.Span[0] == 0xD0)).IsTrue();
        await Assert.That(fixture.Events.IndexOf("ca") > fixture.Events.IndexOf("wire:89")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("ca") < fixture.Events.IndexOf("issue")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("validate") > fixture.Events.IndexOf("issue")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("install") > fixture.Events.IndexOf("wire:91")).IsTrue();
        await Assert.That(fixture.CaHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.CaHandler.Request!.RunId).IsEqualTo(fixture.Session!.RunId);
        await Assert.That(fixture.CaHandler.Request.Format).IsEqualTo(281UL);
        await Assert.That(fixture.CaHandler.Request.DeviceGuid.Span.SequenceEqual(fixture.Auth.Voucher.Guid)).IsTrue();
        await Assert.That(fixture.CaHandler.Request.DeviceAttestationCertificate.Span
            .SequenceEqual(fixture.Auth.DeviceCertificate.RawData)).IsTrue();
        await Assert.That(fixture.ValidationCaCertificates).IsNotNull();
        await Assert.That(fixture.InstallationCaCertificates).IsNotNull();
        await Assert.That(result.CaCertificates!.Certificates[0].Span
            .SequenceEqual(fixture.Auth.RootCertificate.RawData)).IsTrue();
        await Assert.That(result.CaCertificates.CertificateRevocationLists[0].Span.SequenceEqual(fixture.CaCrl)).IsTrue();
        await Assert.That(fixture.InstallationCaCertificates!.Certificates[0].Span
            .SequenceEqual(fixture.Auth.RootCertificate.RawData)).IsTrue();
        await Assert.That(fixture.InstallationCaCertificates.CertificateRevocationLists[0].Span
            .SequenceEqual(fixture.CaCrl)).IsTrue();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
    }

    [Test]
    public async Task UntrustedDeviceCannotInvokeTheCaHandler()
    {
        using var fixture = new Fixture();
        using var other = new Fixture();
        fixture.RequestCaCertificates = true;
        fixture.ProvideCaCertificates = true;
        fixture.TrustedManufacturerKey = other.Auth.Voucher.ManufacturerKey;
        fixture.DeviceTrustAnchor = other.Auth.RootCertificate.RawData;

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.CaHandler.Calls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task TamperedCaResponseStopsBeforeEnrollmentOrInstallation()
    {
        using var fixture = new Fixture();
        fixture.RequestCaCertificates = true;
        fixture.ProvideCaCertificates = true;
        fixture.Transport.Change = (message, count) =>
        {
            if (message.Type == 89 && count == 2)
            {
                byte[] changed = message.Body.ToArray();
                changed[^1] ^= 1;
                return message with { Body = changed };
            }

            return message;
        };

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.CaHandler.Calls).IsEqualTo(1);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.ValidationCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task MissingOrRejectingCaHandlerStopsBeforeEnrollment(bool configured)
    {
        using var fixture = new Fixture();
        fixture.RequestCaCertificates = true;
        fixture.ProvideCaCertificates = configured;
        fixture.CaHandler.Reject = configured;

        await ExpectPeerErrorAsync(fixture.RunAsync, 500, FdoTo2MessageType.DeviceSvcInfo20);

        await Assert.That(fixture.CaHandler.Calls).IsEqualTo(configured ? 1 : 0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.ValidationCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(287)]
    [Arguments(999)]
    public async Task OwnerReturnsError5ForUnsupportedCaFormats(int format)
    {
        using var fixture = new Fixture();
        fixture.ProvideCaCertificates = true;
        using FdoOwnerSession owner = fixture.CreateSession();

        async Task<FdoOwnerResponse> Send(FdoTo2MessageType type, ReadOnlyMemory<byte> body)
        {
            FdoOwnerResponse response = await owner.ProcessAsync(200, type, body);
            owner.ConfirmResponseSent();
            return response;
        }

        var initial = new FdoTo2InitialCodec();
        ReadOnlyMemory<byte> probe = initial.EncodeProbe(new FdoTo2InitialCodec.Probe(
            new byte[] { 4 }, Array.Empty<string>(), fixture.Auth.Voucher.Guid, 8192,
            new long[] { (long)FdoHashAlgorithm.Sha256 }, RandomNumberGenerator.GetBytes(16)));
        FdoOwnerResponse acknowledgement = await Send(FdoTo2MessageType.HelloDeviceProbe, probe);
        initial.CheckAcknowledgement(probe, acknowledgement.EncodedBody);
        using var exchange = FdoEcdhKeyExchange.Create(fixture.Exchange, FdoEcdhParty.Device);
        byte[] nonce = RandomNumberGenerator.GetBytes(16);
        ReadOnlyMemory<byte> proof = new FdoTo2DeviceProofCodec().Sign(
            probe, acknowledgement.EncodedBody, fixture.Exchange, fixture.Cipher,
            exchange.ExportParameter(), nonce, fixture.Auth.DeviceSigningKey);
        FdoOwnerResponse ownerProof = await Send(FdoTo2MessageType.ProveDevice20, proof);
        using FdoTo2OwnerProofCodec.PendingOwnerProof pending = new FdoTo2OwnerProofCodec().BeginDeviceVerification(
            ownerProof.EncodedBody, nonce, fixture.Exchange, fixture.Auth.Voucher.Guid,
            fixture.Auth.Voucher.ManufacturerHash, fixture.Auth.Voucher.HmacAlgorithm, fixture.Auth.Voucher.Secret);
        var cbor = new FdoCborCodec();
        for (int i = 0; i < pending.EntryCount; i++)
        {
            FdoOwnerResponse entry = await Send(
                FdoTo2MessageType.GetOVNextEntry20, FdoPairedProtocol.EncodeEntryRequest(i));
            pending.AppendEntry(i, FdoPairedProtocol.DecodeEntryResponse(cbor, entry.EncodedBody, i));
        }

        FdoTo2OwnerProofCodec.OwnerProof verifiedOwner = pending.CompleteDeviceChecks();
        byte[] key = FdoPairedProtocol.DeriveSessionKey(exchange, verifiedOwner.OwnerParameter, fixture.Cipher);
        using var channel = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, fixture.Cipher, key);
        CryptographicOperations.ZeroMemory(key);
        var info = new FdoTo2ServiceInfoCodec();
        FdoOwnerResponse setup = await Send(FdoTo2MessageType.DeviceServiceInfoRdy20,
            channel.Seal(info.EncodeDeviceReady(4096, RandomNumberGenerator.GetBytes(16))));
        _ = new FdoTo2SetupDeviceCodec().Verify(verifiedOwner, channel.Open(setup.EncodedBody), true);

        FdoOwnerResponse activation = await Send(FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false, FdoPairedProtocol.EncodeInventory(
                new FdoDeviceMetadata("test-os", "test-arch", "1", "test-device", ":", "test-arch")))));
        FdoTo2ServiceInfoCodec.OwnerServiceInfo activated = info.DecodeOwner(channel.Open(activation.EncodedBody));
        await Assert.That(activated.ServiceInfo.Single().Key).IsEqualTo("fdo.csr:active");

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteUInt64((ulong)format);
        FdoOwnerResponse error = await Send(FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false,
            [
                new FdoServiceInfoCodec.Entry("fdo.csr:active", new byte[] { 0xF5 }),
                new FdoServiceInfoCodec.Entry("fdo.csr:cacerts-req", writer.Encode()),
            ])));
        FdoTo2ServiceInfoCodec.OwnerServiceInfo response = info.DecodeOwner(channel.Open(error.EncodedBody));

        await Assert.That(error.MessageType).IsEqualTo(FdoTo2MessageType.OwnerSvcInfo20);
        await Assert.That(response.IsDone).IsFalse();
        await Assert.That(response.IsMoreServiceInfo).IsFalse();
        await Assert.That(response.ServiceInfo.Single().Key).IsEqualTo("fdo.csr:error");
        await Assert.That(response.ServiceInfo.Single().EncodedValue.Span.SequenceEqual(new byte[] { 0x05 })).IsTrue();
        await Assert.That(fixture.CaHandler.Calls).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(owner.CommittedEnrollment).IsNull();
        await Assert.That(owner.DoneAckProduced).IsFalse();
    }

    [Test]
    public async Task RejectingDevicePolicyNeverInstallsDistributedCaMaterial()
    {
        using var fixture = new Fixture();
        fixture.RequestCaCertificates = true;
        fixture.ProvideCaCertificates = true;
        fixture.RejectCertificate = true;

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.ValidationCaCertificates).IsNotNull();
        await Assert.That(fixture.InstallationCaCertificates).IsNull();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 90)).IsFalse();
    }

    [Test]
    public async Task CaResponseRespectsTheExactNegotiatedOwnerPlaintextLimit()
    {
        using var accepted = new Fixture();
        accepted.RequestCaCertificates = true;
        accepted.ProvideCaCertificates = true;
        int exact = CaResponseSize(accepted);
        accepted.Device = accepted.Device with { MaxOwnerServiceInfoSize = (ushort)exact };

        FdoDeviceEnrollment result = await accepted.RunAsync();

        await Assert.That(result.CaCertificates!.CertificateRevocationLists[0].Span
            .SequenceEqual(accepted.CaCrl)).IsTrue();
        await Assert.That(accepted.Handler.CommitCalls).IsEqualTo(1);

        using var rejected = new Fixture();
        rejected.RequestCaCertificates = true;
        rejected.ProvideCaCertificates = true;
        rejected.Device = rejected.Device with { MaxOwnerServiceInfoSize = (ushort)(CaResponseSize(rejected) - 1) };

        await ExpectPeerErrorAsync(rejected.RunAsync, 100, FdoTo2MessageType.DeviceSvcInfo20);

        await Assert.That(rejected.CaHandler.Calls).IsEqualTo(1);
        await Assert.That(rejected.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(rejected.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task CallbackAndDeviceResultCannotMutateTheRunBinding()
    {
        using var fixture = new Fixture();
        fixture.Handler.MutateSnapshots = true;
        fixture.MutateDeviceSnapshots = true;
        FdoDeviceEnrollment result = await fixture.RunAsync();

        ClearExposedMemory(result.Certificate);
        ClearExposedMemory(result.DeviceGuid);
        ClearExposedMemory(result.CertificateSigningRequest);
        ClearExposedMemory(fixture.Handler.Committed!.Certificate);
        ClearExposedMemory(fixture.Handler.Committed.Request.DeviceGuid);
        ClearExposedMemory(fixture.Handler.Committed.Request.CertificateSigningRequest);
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(result.DeviceGuid.Span.SequenceEqual(fixture.Auth.Voucher.Guid)).IsTrue();
        await Assert.That(result.CertificateSigningRequest.Span.SequenceEqual(fixture.Request)).IsTrue();
        await Assert.That(fixture.DeviceSession!.InstalledEnrollment!.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Handler.Committed.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Handler.Committed.Request.DeviceGuid.Span.SequenceEqual(fixture.Auth.Voucher.Guid)).IsTrue();
        await Assert.That(fixture.Handler.Committed.Request.CertificateSigningRequest.Span.SequenceEqual(fixture.Request)).IsTrue();
    }

    [Test]
    [Arguments(82, 1, false, false)]
    [Arguments(88, 1, false, false)]
    [Arguments(89, 2, true, false)]
    [Arguments(90, 1, true, false)]
    [Arguments(91, 1, true, true)]
    public async Task TamperedMessagesStopTheRunAtTheirAuthenticationBoundary(
        ushort messageType, int occurrence, bool issued, bool committed)
    {
        using var fixture = new Fixture();
        fixture.Transport.Change = (message, count) =>
        {
            if (message.Type == messageType && count == occurrence)
            {
                byte[] changed = message.Body.ToArray();
                changed[^1] ^= 1;
                return message with { Body = changed };
            }

            return message;
        };

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(issued ? 1 : 0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(committed ? 1 : 0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsFalse();
        await Assert.That(fixture.DeviceSession.InstallationStarted).IsFalse();
        if (messageType == 91)
        {
            await Assert.That(fixture.ValidationCalls).IsEqualTo(1);
            await Assert.That(fixture.Session!.CommittedEnrollment).IsNotNull();
            await Assert.That(fixture.Session.DoneAckProduced).IsTrue();
            await Assert.That(fixture.Session.DoneAckHandoffConfirmed).IsTrue();
        }
    }

    [Test]
    public async Task RejectsADeviceProofReplayedFromAnotherRun()
    {
        using var fixture = new Fixture();
        await fixture.RunAsync();
        byte[] oldProof = fixture.Transport.Messages.Single(message => message.Type == 82).Body.ToArray();
        var next = fixture.CreateTransport();
        next.Change = (message, _) => message.Type == 82 ? message with { Body = oldProof } : message;
        fixture.Transport = next;
        int previousIssues = fixture.Handler.IssueCalls;
        int previousCommits = fixture.Handler.CommitCalls;

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(previousIssues);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(previousCommits);
    }

    [Test]
    public async Task RejectsAProtectedOwnerMessageReplayedWithinTheRun()
    {
        using var fixture = new Fixture();
        byte[]? first = null;
        fixture.Transport.Change = (message, count) =>
        {
            if (message.Type == 89 && count == 1)
            {
                first = message.Body.ToArray();
            }

            return message.Type == 89 && count == 2 ? message with { Body = first! } : message;
        };

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
    }

    [Test]
    public async Task LostDoneAckLeavesTheOwnerCommittedWithoutAConfirmedHandoff()
    {
        using var fixture = new Fixture();
        fixture.Transport.Change = (message, _) => message.Type == 91
            ? throw new IOException("The Owner response handoff failed.")
            : message;

        await CatchAsync<IOException>(fixture.RunAsync);

        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.Session!.CommittedEnrollment).IsNotNull();
        await Assert.That(fixture.Session.DoneAckProduced).IsTrue();
        await Assert.That(fixture.Session.DoneAckHandoffConfirmed).IsFalse();
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsFalse();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task CancellationAfterCommitPreservesTheCommittedEnrollment()
    {
        using var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        fixture.Handler.OnCommitSucceeded = cancellation.Cancel;

        await CatchAsync<OperationCanceledException>(() => fixture.RunAsync(cancellation.Token));

        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.Session!.CommittedEnrollment!.Request.RunId)
            .IsEqualTo(fixture.Handler.Committed!.Request.RunId);
        await Assert.That(fixture.Session.CommittedEnrollment.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Session.DoneAckProduced).IsFalse();
        await Assert.That(fixture.Session.DoneAckHandoffConfirmed).IsFalse();
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 91)).IsFalse();
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsFalse();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task InstallationFailurePreservesTheAuthenticatedCompletionObservation()
    {
        using var fixture = new Fixture();
        fixture.RejectInstallation = true;

        await CatchAsync<InvalidOperationException>(fixture.RunAsync);

        await Assert.That(fixture.Session!.CommittedEnrollment).IsNotNull();
        await Assert.That(fixture.Session.DoneAckHandoffConfirmed).IsTrue();
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.DeviceSession.InstallationStarted).IsTrue();
        await Assert.That(fixture.DeviceSession.InstalledEnrollment).IsNull();
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
    }

    [Test]
    public async Task SuccessfulInstallationRemainsObservableWhenCancellationArrivesDuringTheCallback()
    {
        using var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        fixture.OnInstallSucceeded = cancellation.Cancel;

        FdoDeviceEnrollment result = await fixture.RunAsync(cancellation.Token);

        await Assert.That(cancellation.IsCancellationRequested).IsTrue();
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.DeviceSession.InstallationStarted).IsTrue();
        await Assert.That(fixture.DeviceSession.InstalledEnrollment!.RunId).IsEqualTo(result.RunId);
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
    }

    [Test]
    public async Task OwnerRejectsAnIssuedCertificateForAnotherCsrKey()
    {
        using var fixture = new Fixture();
        using var other = new Fixture();
        fixture.Handler.CertificateOverride = other.Certificate;

        await ExpectPeerErrorAsync(fixture.RunAsync, 101, FdoTo2MessageType.DeviceSvcInfo20);

        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 90)).IsFalse();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task RejectsUntrustedDeviceBeforeInvokingTheEnrollmentHandler()
    {
        using var fixture = new Fixture();
        using var other = new Fixture();
        fixture.TrustedManufacturerKey = other.Auth.Voucher.ManufacturerKey;
        fixture.DeviceTrustAnchor = other.Auth.RootCertificate.RawData;

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
    }

    [Test]
    public async Task RejectsDeviceCertificatePolicyBeforeSendingDone()
    {
        using var fixture = new Fixture();
        fixture.RejectCertificate = true;

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 90)).IsFalse();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task EnrollmentCallbackFailureDoesNotProduceDoneAck(bool failCommit)
    {
        using var fixture = new Fixture();
        fixture.Handler.FailIssue = !failCommit;
        fixture.Handler.FailCommit = failCommit;

        FdoPeerErrorException error = await CatchAsync<FdoPeerErrorException>(fixture.RunAsync);

        await Assert.That(error.ErrorCode).IsEqualTo((ushort)500);
        await Assert.That(error.PreviousMessageType)
            .IsEqualTo(failCommit ? FdoTo2MessageType.Done20 : FdoTo2MessageType.DeviceSvcInfo20);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(1);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(failCommit ? 1 : 0);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 91)).IsFalse();
        await Assert.That(fixture.Session!.CommittedEnrollment).IsNull();
        await Assert.That(fixture.Session.DoneAckProduced).IsFalse();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task DeviceSendsOneProtectedErrorAfterRejectingAnAuthenticatedCertificate()
    {
        using var fixture = new Fixture();
        var transport = new ErrorRecordingTransport(fixture.Events);
        fixture.Transport = transport;
        fixture.RejectCertificate = true;

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(fixture.DeviceSession!.SentErrorCode).IsEqualTo((ushort?)101);
        await Assert.That(fixture.Session!.ReceivedErrorCode).IsEqualTo((ushort?)101);
        await Assert.That(fixture.Session.SentErrorCode).IsNull();
        await Assert.That(transport.ErrorReply!.MessageType).IsEqualTo(FdoTo2MessageType.Error);
        await Assert.That(transport.ErrorReply.EncodedBody.IsEmpty).IsTrue();
        FdoPairedMessage[] errors = transport.Messages.Where(message => message.Type == 255).ToArray();
        await Assert.That(errors.Length).IsEqualTo(1);
        await Assert.That(errors[0].Body.Span[0]).IsEqualTo((byte)0xD0);
        await Assert.That(transport.Messages[^2].Type).IsEqualTo((ushort)89);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
        await Assert.That(Throws<ObjectDisposedException>(() => fixture.Session.ConfirmResponseSent())).IsTrue();
    }

    [Test]
    public async Task OwnerDropsATamperedDeviceErrorWithoutReplying()
    {
        using var fixture = new Fixture();
        var transport = new ErrorRecordingTransport(fixture.Events)
        {
            Change = (message, _) => message.Type == 255 ? message with { Body = Flip(message.Body, ^1) } : message,
        };
        fixture.Transport = transport;
        fixture.RejectCertificate = true;

        await CatchAsync<CryptographicException>(fixture.RunAsync);

        await Assert.That(transport.Messages.Count(message => message.Type == 255)).IsEqualTo(1);
        await Assert.That(transport.ErrorReply).IsNull();
        await Assert.That(fixture.Session!.ReceivedErrorCode).IsNull();
        await Assert.That(fixture.Session.SentErrorCode).IsNull();
        await Assert.That(fixture.DeviceSession!.SentErrorCode).IsNull();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments((byte)89, true)]
    [Arguments((byte)87, false)]
    public async Task OwnerAcceptsOnlyAProtectedDeviceErrorNamingItsLastResponse(byte previous, bool accepted)
    {
        using var fixture = new Fixture();
        using FdoOwnerSession owner = fixture.CreateSession();
        using FdoTo2PairedAeadChannel channel = await ActivateOwnerAsync(fixture, owner);
        ReadOnlyMemory<byte> error = channel.Seal(new FdoErrorMessageCodec().Encode(101, previous, 7));

        if (accepted)
        {
            FdoOwnerResponse response = await owner.ProcessAsync(200, FdoTo2MessageType.Error, error);
            await Assert.That(response.MessageType).IsEqualTo(FdoTo2MessageType.Error);
            await Assert.That(response.EncodedBody.IsEmpty).IsTrue();
            await Assert.That(owner.ReceivedErrorCode).IsEqualTo((ushort?)101);
        }
        else
        {
            await CatchOwnerAsync<CborContentException>(
                () => owner.ProcessAsync(200, FdoTo2MessageType.Error, error).AsTask());
            await Assert.That(owner.ReceivedErrorCode).IsNull();
        }

        await Assert.That(owner.SentErrorCode).IsNull();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await CatchOwnerAsync<InvalidOperationException>(() => owner.ProcessAsync(
            200, FdoTo2MessageType.DeviceSvcInfo20, channel.Seal(new byte[] { 0x80 })).AsTask());
    }

    [Test]
    public async Task OwnerStaysSilentWhenAProtectedRequestDoesNotAuthenticate()
    {
        using var fixture = new Fixture();
        using FdoOwnerSession owner = fixture.CreateSession();
        using FdoTo2PairedAeadChannel channel = await ActivateOwnerAsync(fixture, owner);
        ReadOnlyMemory<byte> request = Flip(channel.Seal(new byte[] { 0x80 }), ^1);

        await CatchOwnerAsync<CryptographicException>(
            () => owner.ProcessAsync(200, FdoTo2MessageType.DeviceSvcInfo20, request).AsTask());

        await Assert.That(owner.SentErrorCode).IsNull();
        await Assert.That(owner.ReceivedErrorCode).IsNull();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task DeviceDoesNotAnswerAnOwnerErrorWithAnError()
    {
        using var fixture = new Fixture();
        var transport = new ErrorRecordingTransport(fixture.Events);
        fixture.Transport = transport;
        fixture.Handler.FailIssue = true;

        FdoPeerErrorException error = await CatchAsync<FdoPeerErrorException>(fixture.RunAsync);

        await Assert.That(error.ErrorCode).IsEqualTo((ushort)500);
        await Assert.That(error.Message.Contains("Issue", StringComparison.OrdinalIgnoreCase)).IsFalse();
        await Assert.That(transport.Messages.Count(message => message.Type == 255)).IsEqualTo(1);
        await Assert.That(transport.Messages[^1].Type).IsEqualTo((ushort)255);
        await Assert.That(transport.ErrorReply).IsNull();
        await Assert.That(fixture.DeviceSession!.SentErrorCode).IsNull();
        await Assert.That(fixture.Session!.SentErrorCode).IsEqualTo((ushort?)500);
        await Assert.That(fixture.Session.ReceivedErrorCode).IsNull();
    }

    [Test]
    public async Task DeviceDeniesAuthenticatedCredentialReuseWithError102()
    {
        using var run = new ReplacementFixture();
        var transport = new ErrorRecordingTransport(run.Fixture.Events);
        run.Fixture.Transport = transport;
        run.Fixture.Replacement = null;
        run.Fixture.OwnerReuse = true;

        await CatchAsync<InvalidOperationException>(run.Fixture.RunAsync);

        await Assert.That(run.Fixture.DeviceSession!.SentErrorCode).IsEqualTo((ushort?)102);
        await Assert.That(run.Fixture.Session!.ReceivedErrorCode).IsEqualTo((ushort?)102);
        await Assert.That(transport.Messages[^2].Type).IsEqualTo((ushort)87);
        await Assert.That(transport.Messages[^1].Type).IsEqualTo((ushort)255);
        await Assert.That(run.Fixture.Session.CommittedEnrollment).IsNull();
        await Assert.That(run.Handler.ReserveCalls).IsEqualTo(0);
        await Assert.That(run.Fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task HttpOwnerErrorUsesStatus500AndEndsTheBinding()
    {
        using var fixture = new Fixture();
        fixture.Handler.FailIssue = true;
        using FdoOwnerSession owner = fixture.CreateSession();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var listener = new LoopbackHttpServer();
        using var binding = FdoHttpServerSession.ForOwner(owner, 8192);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<IReadOnlyList<RecordedRequest>> serving = listener.ServeSessionAsync(binding, timeout.Token);

        FdoPeerErrorException error = await CatchAsync<FdoPeerErrorException>(
            () => FdoHttp.RunDeviceAsync(device, listener.Address, 8192, timeout.Token).AsTask());
        IReadOnlyList<RecordedRequest> requests = await serving;

        await Assert.That(error.ErrorCode).IsEqualTo((ushort)500);
        await Assert.That(error.PreviousMessageType).IsEqualTo(FdoTo2MessageType.DeviceSvcInfo20);
        await Assert.That(requests[^1].Uri!.AbsolutePath).IsEqualTo("/fdo/200/msg/88");
        await Assert.That(requests.Any(request => request.Uri!.AbsolutePath.EndsWith("/255", StringComparison.Ordinal)))
            .IsFalse();
        await Assert.That(owner.SentErrorCode).IsEqualTo((ushort?)500);
        await Assert.That(device.SentErrorCode).IsNull();
        await Assert.That(listener.HasPendingConnection).IsFalse();
    }

    [Test]
    public async Task HttpDeviceErrorUsesTheActiveTokenAndReceivesAnEmpty200()
    {
        using var fixture = new Fixture();
        fixture.RejectCertificate = true;
        using FdoOwnerSession owner = fixture.CreateSession();
        using FdoDeviceSession device = fixture.CreateDeviceSession();
        using var listener = new LoopbackHttpServer();
        using var binding = FdoHttpServerSession.ForOwner(owner, 8192);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<IReadOnlyList<RecordedRequest>> serving = listener.ServeSessionAsync(binding, timeout.Token);

        await CatchAsync<CryptographicException>(
            () => FdoHttp.RunDeviceAsync(device, listener.Address, 8192, timeout.Token).AsTask());
        IReadOnlyList<RecordedRequest> requests = await serving;

        RecordedRequest errorRequest = requests[^1];
        await Assert.That(errorRequest.Uri!.AbsolutePath).IsEqualTo("/fdo/200/msg/255");
        await Assert.That(errorRequest.Authorization).IsEqualTo(requests[1].Authorization);
        await Assert.That(errorRequest.ContentType).IsEqualTo("application/cbor");
        await Assert.That(errorRequest.Body[0]).IsEqualTo((byte)0xD0);
        await Assert.That(requests.Count(request => request.Uri!.AbsolutePath.EndsWith("/255", StringComparison.Ordinal)))
            .IsEqualTo(1);
        await Assert.That(device.SentErrorCode).IsEqualTo((ushort?)101);
        await Assert.That(owner.ReceivedErrorCode).IsEqualTo((ushort?)101);
        await Assert.That(owner.SentErrorCode).IsNull();
        await Assert.That(listener.HasPendingConnection).IsFalse();
    }

    [Test]
    public async Task HttpErrorRouteRequiresTheActiveTokenAndAnAuthenticatedBody()
    {
        using var fixture = new Fixture();
        using FdoOwnerSession owner = fixture.CreateSession();
        using var binding = FdoHttpServerSession.ForOwner(owner, 8192);
        byte[] body = [0xD0, 0x83, 0x40, 0xA0, 0x40];

        FdoTransportException beforeSession = await CatchOwnerAsync<FdoTransportException>(
            () => binding.ProcessAsync(ErrorRequest(body, null)).AsTask());
        await Assert.That(beforeSession.Failure).IsEqualTo(FdoTransportFailure.InvalidRequest);

        var initial = new FdoTo2InitialCodec();
        ReadOnlyMemory<byte> probe = initial.EncodeProbe(new FdoTo2InitialCodec.Probe(
            new byte[] { 4 }, Array.Empty<string>(), fixture.Auth.Voucher.Guid, 8192,
            new long[] { (long)FdoHashAlgorithm.Sha256 }, RandomNumberGenerator.GetBytes(16)));
        using var probeBody = new MemoryStream(probe.ToArray(), writable: false);
        FdoHttpServerResponse acknowledgement = await binding.ProcessAsync(new FdoHttpServerRequest
        {
            Method = "POST",
            Target = "/fdo/200/msg/80",
            ContentTypeValues = ["application/cbor"],
            ContentLength = probe.Length,
            Body = probeBody,
        });
        binding.ConfirmResponseSent();

        FdoTransportException withoutToken = await CatchOwnerAsync<FdoTransportException>(
            () => binding.ProcessAsync(ErrorRequest(body, null)).AsTask());
        await Assert.That(withoutToken.Failure).IsEqualTo(FdoTransportFailure.Authorization);

        await CatchOwnerAsync<CborContentException>(
            () => binding.ProcessAsync(ErrorRequest(body, acknowledgement.Authorization)).AsTask());
        await Assert.That(owner.ReceivedErrorCode).IsNull();
        await Assert.That(owner.SentErrorCode).IsNull();
        await CatchOwnerAsync<ObjectDisposedException>(
            () => binding.ProcessAsync(ErrorRequest(body, acknowledgement.Authorization)).AsTask());

        static FdoHttpServerRequest ErrorRequest(byte[] body, string? authorization) => new()
        {
            Method = "POST",
            Target = "/fdo/200/msg/255",
            AuthorizationValues = authorization is null ? [] : [authorization],
            ContentTypeValues = ["application/cbor"],
            ContentLength = body.Length,
            Body = new MemoryStream(body, writable: false),
        };
    }

    [Test]
    [Arguments(false, true, true, true)]
    [Arguments(true, false, true, true)]
    [Arguments(true, true, false, true)]
    [Arguments(true, true, true, false)]
    public async Task RequiresExplicitBypassAndCredentialReuseAtBothPeers(
        bool deviceBypass, bool ownerBypass, bool deviceReuse, bool ownerReuse)
    {
        using var fixture = new Fixture();
        fixture.Device = fixture.Device with
        {
            AllowRendezvousBypass = deviceBypass,
            AllowCredentialReuse = deviceReuse,
        };
        fixture.OwnerBypass = ownerBypass;
        fixture.OwnerReuse = ownerReuse;

        await CatchAsync<InvalidOperationException>(fixture.RunAsync);

        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task UsesIndependentServiceInfoLimitsForRequestAndResponse()
    {
        using var fixture = new Fixture();
        var csrCodec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        var info = new FdoTo2ServiceInfoCodec();
        int requestLimit = info.EncodeDevice(false,
        [
            new FdoServiceInfoCodec.Entry("fdo.csr:active", new byte[] { 0xF5 }),
            csrCodec.EncodeRequest(fixture.Request),
        ]).Length;
        int responseLimit = info.EncodeOwner(false, true,
            [csrCodec.EncodeResponse(fixture.Request, fixture.Certificate)]).Length;
        await Assert.That(responseLimit > requestLimit).IsTrue();
        fixture.Device = fixture.Device with { MaxOwnerServiceInfoSize = (ushort)responseLimit };
        fixture.OwnerDeviceServiceInfoSize = (ushort)requestLimit;

        FdoDeviceEnrollment result = await fixture.RunAsync();

        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
    }

    [Test]
    public async Task DeviceSendsAnInventoryLargerThanTheLimitInCompleteEntryRounds()
    {
        using var fixture = new Fixture();
        fixture.Metadata = new FdoDeviceMetadata(
            new string('o', 600), "test-arch", "1", new string('d', 600), ":", "test-arch");
        var info = new FdoTo2ServiceInfoCodec();
        IReadOnlyList<FdoServiceInfoCodec.Entry> inventory = FdoPairedProtocol.EncodeInventory(fixture.Metadata);
        int enrollmentSize = info.EncodeDevice(false,
        [
            new FdoServiceInfoCodec.Entry("fdo.csr:active", new byte[] { 0xF5 }),
            new FdoCsrBase64TextCodec(ushort.MaxValue).EncodeRequest(fixture.Request),
        ]).Length;
        int largestEntry = inventory.Max(entry => info.EncodeDevice(false, [entry]).Length);
        int limit = Math.Max(enrollmentSize, largestEntry) + 8;
        await Assert.That(info.EncodeDevice(false, inventory).Length > limit).IsTrue();
        fixture.OwnerDeviceServiceInfoSize = (ushort)limit;
        int inventoryRounds = FdoServiceInfoBatches.Split(inventory, limit, length => length, 8192).Count;
        await Assert.That(inventoryRounds > 1).IsTrue();

        FdoDeviceEnrollment result = await fixture.RunAsync();

        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(fixture.Transport.Messages.Count(
            message => message.Type == (ushort)FdoTo2MessageType.DeviceSvcInfo20)).IsEqualTo(inventoryRounds + 1);
    }

    [Test]
    public async Task DeviceRejectsAnInventoryEntryLargerThanTheLimitBeforeSendingIt()
    {
        using var fixture = new Fixture();
        var info = new FdoTo2ServiceInfoCodec();
        int limit = info.EncodeDevice(false,
        [
            new FdoServiceInfoCodec.Entry("fdo.csr:active", new byte[] { 0xF5 }),
            new FdoCsrBase64TextCodec(ushort.MaxValue).EncodeRequest(fixture.Request),
        ]).Length + 8;
        fixture.OwnerDeviceServiceInfoSize = (ushort)limit;
        fixture.Metadata = new FdoDeviceMetadata(
            "test-os", "test-arch", "1", new string('d', limit), ":", "test-arch");

        await CatchAsync<CborContentException>(fixture.RunAsync);

        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages.Any(
            message => message.Type == (ushort)FdoTo2MessageType.DeviceSvcInfo20)).IsFalse();
    }

    [Test]
    public async Task OwnerAnswersAPartialInventoryWithAnEmptyMessageAndAssemblesTheRest()
    {
        using var fixture = new Fixture();
        using FdoOwnerSession owner = fixture.CreateSession();
        OwnerServiceInfo opened = await OpenOwnerServiceInfoAsync(fixture, owner);
        using FdoTo2PairedAeadChannel channel = opened.Channel;
        var info = new FdoTo2ServiceInfoCodec();
        IReadOnlyList<FdoServiceInfoCodec.Entry> inventory = FdoPairedProtocol.EncodeInventory(fixture.Metadata);

        FdoOwnerResponse first = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(true, inventory.Take(4).ToArray())));
        FdoTo2ServiceInfoCodec.OwnerServiceInfo waiting = info.DecodeOwner(channel.Open(first.EncodedBody));
        await Assert.That(waiting.IsMoreServiceInfo).IsFalse();
        await Assert.That(waiting.IsDone).IsFalse();
        await Assert.That(waiting.ServiceInfo.Count).IsEqualTo(0);

        FdoOwnerResponse second = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false, inventory.Skip(4).ToArray())));
        FdoTo2ServiceInfoCodec.OwnerServiceInfo activated = info.DecodeOwner(channel.Open(second.EncodedBody));
        await Assert.That(activated.ServiceInfo.Single().Key).IsEqualTo("fdo.csr:active");
    }

    [Test]
    [Arguments(8)]
    [Arguments(0)]
    public async Task OwnerRejectsAnIncompleteOrWithheldInventory(int count)
    {
        using var fixture = new Fixture();
        using FdoOwnerSession owner = fixture.CreateSession();
        OwnerServiceInfo opened = await OpenOwnerServiceInfoAsync(fixture, owner);
        using FdoTo2PairedAeadChannel channel = opened.Channel;
        var info = new FdoTo2ServiceInfoCodec();
        IReadOnlyList<FdoServiceInfoCodec.Entry> inventory = FdoPairedProtocol.EncodeInventory(fixture.Metadata);

        await ExpectOwnerErrorAsync(owner, channel, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false, inventory.Take(count).ToArray())), 100);

        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task OwnerAnswersKeepalivesAfterItFinishesAndStillCompletes()
    {
        using var fixture = new Fixture();
        using FdoOwnerSession owner = fixture.CreateSession();
        OwnerServiceInfo opened = await OpenOwnerServiceInfoAsync(fixture, owner);
        using FdoTo2PairedAeadChannel channel = opened.Channel;
        var info = new FdoTo2ServiceInfoCodec();
        FdoOwnerResponse activation = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false, FdoPairedProtocol.EncodeInventory(fixture.Metadata))));
        _ = channel.Open(activation.EncodedBody);
        FdoOwnerResponse issued = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false,
            [
                new FdoServiceInfoCodec.Entry("fdo.csr:active", new byte[] { 0xF5 }),
                new FdoCsrBase64TextCodec(4096).EncodeRequest(fixture.Request),
            ])));
        await Assert.That(info.DecodeOwner(channel.Open(issued.EncodedBody)).IsDone).IsTrue();

        for (int i = 0; i < 2; i++)
        {
            FdoOwnerResponse keepalive = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
                channel.Seal(info.EncodeDevice(false, [])));
            FdoTo2ServiceInfoCodec.OwnerServiceInfo reply = info.DecodeOwner(channel.Open(keepalive.EncodedBody));
            await Assert.That(reply.IsDone).IsTrue();
            await Assert.That(reply.IsMoreServiceInfo).IsFalse();
            await Assert.That(reply.ServiceInfo.Count).IsEqualTo(0);
        }

        var completion = new FdoTo2CompletionCodec();
        FdoOwnerResponse ack = await SendOwnerAsync(owner, FdoTo2MessageType.Done20,
            channel.Seal(completion.EncodeDone(opened.DoneNonce, null)));
        await Assert.That(completion.DecodeDoneAck(channel.Open(ack.EncodedBody)).Span
            .SequenceEqual(opened.ReadyNonce)).IsTrue();
        await Assert.That(owner.CommittedEnrollment).IsNotNull();
    }

    [Test]
    public async Task OwnerRejectsServiceInfoInAKeepaliveAfterItFinishes()
    {
        using var fixture = new Fixture();
        using FdoOwnerSession owner = fixture.CreateSession();
        OwnerServiceInfo opened = await OpenOwnerServiceInfoAsync(fixture, owner);
        using FdoTo2PairedAeadChannel channel = opened.Channel;
        var info = new FdoTo2ServiceInfoCodec();
        FdoOwnerResponse activation = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false, FdoPairedProtocol.EncodeInventory(fixture.Metadata))));
        _ = channel.Open(activation.EncodedBody);
        FdoOwnerResponse issued = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false,
            [
                new FdoServiceInfoCodec.Entry("fdo.csr:active", new byte[] { 0xF5 }),
                new FdoCsrBase64TextCodec(4096).EncodeRequest(fixture.Request),
            ])));
        _ = channel.Open(issued.EncodedBody);

        await ExpectOwnerErrorAsync(owner, channel, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(true, [])), 100);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task OwnerDrainsAQueuedMultiRoundBatchThatTheDeviceAssembles(int activationBatch)
    {
        // The built-in CSR script never queues more than one Owner batch, so
        // this controlled peer replaces the Owner's activation response with
        // three batches before it handles the inventory. That skips the
        // inventory check; everything after it runs through both real roles.
        using var fixture = new Fixture();
        const System.Reflection.BindingFlags Private =
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic;
        System.Reflection.FieldInfo queueField = typeof(FdoOwnerSession).GetField("_ownerQueue", Private)
            ?? throw new InvalidOperationException("The Owner queue field is missing.");
        System.Reflection.FieldInfo phaseField = typeof(FdoOwnerSession).GetField("_phase", Private)
            ?? throw new InvalidOperationException("The Owner phase field is missing.");
        var batches = new Queue<IReadOnlyList<FdoServiceInfoCodec.Entry>>();
        for (int i = 0; i < 3; i++)
        {
            batches.Enqueue(i == activationBatch
                ? [new FdoServiceInfoCodec.Entry("fdo.csr:active", new byte[] { 0xF5 })]
                : Array.Empty<FdoServiceInfoCodec.Entry>());
        }

        fixture.Transport.Change = (message, count) =>
        {
            if (message.Type == (ushort)FdoTo2MessageType.DeviceSvcInfo20 && count == 1)
            {
                queueField.SetValue(fixture.Session, batches);
                phaseField.SetValue(fixture.Session, Enum.Parse(phaseField.FieldType, "Enrollment"));
            }

            return message;
        };

        FdoDeviceEnrollment result = await fixture.RunAsync();

        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(batches.Count).IsEqualTo(0);
        await Assert.That(queueField.GetValue(fixture.Session)).IsNull();
        // Inventory, two empty polls, and the CSR request; three batches and the certificate.
        await Assert.That(fixture.Transport.Messages.Count(
            message => message.Type == (ushort)FdoTo2MessageType.DeviceSvcInfo20)).IsEqualTo(4);
        await Assert.That(fixture.Transport.Messages.Count(
            message => message.Type == (ushort)FdoTo2MessageType.OwnerSvcInfo20)).IsEqualTo(4);
    }

    [Test]
    public async Task RejectsAnUnexpectedWireVersionBeforeAuthentication()
    {
        using var fixture = new Fixture();
        fixture.Transport.Change = (message, _) =>
            message.Type == 80 ? message with { Version = 101 } : message;

        await CatchAsync<CborContentException>(fixture.RunAsync);

        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task OwnerRequiresAResponseHandoffBeforeTheNextRequest()
    {
        using var fixture = new Fixture();
        FdoOwnerSession session = fixture.CreateSession();
        ReadOnlyMemory<byte> probe = new FdoTo2InitialCodec().EncodeProbe(new FdoTo2InitialCodec.Probe(
            new byte[] { 4 }, Array.Empty<string>(), fixture.Auth.Voucher.Guid, 8192,
            new long[] { (long)FdoHashAlgorithm.Sha256 }, RandomNumberGenerator.GetBytes(16)));
        FdoOwnerResponse response = await session.ProcessAsync(200, FdoTo2MessageType.HelloDeviceProbe, probe);
        byte[] expected = response.EncodedBody.ToArray();
        ClearExposedMemory(response.EncodedBody);
        await Assert.That(response.EncodedBody.Span.SequenceEqual(expected)).IsTrue();
        byte[] receivedBody = (byte[])expected.Clone();
        var receivedResponse = new FdoOwnerResponse(200, response.MessageType, receivedBody);
        Array.Clear(receivedBody);
        ClearExposedMemory(receivedResponse.EncodedBody);
        await Assert.That(receivedResponse.EncodedBody.Span.SequenceEqual(expected)).IsTrue();

        await CatchOwnerAsync<InvalidOperationException>(async () =>
            await session.ProcessAsync(200, FdoTo2MessageType.ProveDevice20, new byte[] { 0x80 }));

        await Assert.That(Throws<InvalidOperationException>(session.ConfirmResponseSent)).IsTrue();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task OwnerRejectsAnOversizedRequestAndEndsTheSession()
    {
        using var fixture = new Fixture();
        FdoOwnerSession session = fixture.CreateSession();

        await CatchOwnerAsync<CborContentException>(async () =>
            await session.ProcessAsync(200, FdoTo2MessageType.HelloDeviceProbe, new byte[8193]));
        await CatchOwnerAsync<InvalidOperationException>(async () =>
            await session.ProcessAsync(200, FdoTo2MessageType.HelloDeviceProbe, new byte[] { 0x80 }));

        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(session.CommittedEnrollment).IsNull();
        await Assert.That(session.DoneAckProduced).IsFalse();
    }

    [Test]
    public async Task OwnerSnapshotsVoucherMaterialBeforeProcessingTheRun()
    {
        using var fixture = new Fixture();
        FdoOwnerSession session = fixture.CreateSession();
        Array.Fill(fixture.Auth.Voucher.HeaderTag, (byte)0);
        Array.Fill(fixture.Auth.Voucher.EncodedHeaderHmac, (byte)0);
        Array.Fill(fixture.Auth.Voucher.FirstEntry, (byte)0);
        Array.Fill(fixture.Auth.Voucher.SecondEntry, (byte)0);
        Array.Fill(fixture.Auth.EncodedChain, (byte)0);
        Array.Fill(fixture.Auth.Voucher.ManufacturerKey, (byte)0);

        FdoDeviceEnrollment result = await fixture.RunAsync(session);

        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(session.CommittedEnrollment!.Request.RunId).IsEqualTo(session.RunId);
    }

    [Test]
    public async Task DeviceSnapshotsCredentialsAndRequestBeforeProcessingTheRun()
    {
        using var fixture = new Fixture();
        FdoDeviceSessionOptions options = fixture.CreateDeviceOptions();
        FdoDeviceSession device = fixture.CreateDeviceSession(options);
        FdoOwnerSession owner = fixture.CreateSession();
        ClearExposedMemory(options.DeviceGuid);
        ClearExposedMemory(options.EncodedManufacturerKeyHash);
        ClearExposedMemory(options.VoucherHmacSecret);
        ClearExposedMemory(options.CertificateSigningRequest);

        FdoDeviceEnrollment result = await fixture.RunAsync(owner, device);

        await Assert.That(result.DeviceGuid.Span.SequenceEqual(fixture.Auth.Voucher.Guid)).IsTrue();
        await Assert.That(result.CertificateSigningRequest.Span.SequenceEqual(fixture.Request)).IsTrue();
        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
    }

    [Test]
    public async Task DeviceCannotStartTheSameSessionTwice()
    {
        using var fixture = new Fixture();
        await fixture.RunAsync();
        int messageCount = fixture.Transport.Messages.Count;

        await CatchAsync<InvalidOperationException>(() =>
            fixture.DeviceSession!.RunAsync(fixture.Transport).AsTask());

        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(messageCount);
        await Assert.That(fixture.InstallCalls).IsEqualTo(1);
    }

    [Test]
    public async Task OwnerRequiresExplicitPairedProfileOptIn()
    {
        using var fixture = new Fixture();
        fixture.UsePairedProfile = false;

        await CatchAsync<InvalidOperationException>(fixture.RunAsync);

        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task DeviceRequiresExplicitPairedProfileOptIn()
    {
        using var fixture = new Fixture();
        fixture.DeviceUsePairedProfile = false;

        await CatchAsync<InvalidOperationException>(fixture.RunAsync);

        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(256)]
    [Arguments(384)]
    public async Task ReplacementRunCreatesExactHeaderVoucherAndHmac(int curveSize)
    {
        using var run = new ReplacementFixture(curveSize);
        Fixture fixture = run.Fixture;
        byte[] rendezvous = (byte[])run.Rendezvous.Clone();
        FdoOwnerSession owner = fixture.CreateSession();
        FdoDeviceSession device = fixture.CreateDeviceSession();
        Array.Clear(run.Rendezvous);
        run.Secret.MutateInput = true;

        FdoDeviceEnrollment enrollment = await fixture.RunAsync(owner, device);

        FdoDeviceReplacementProposal proposal = device.ReplacementProposal!;
        FdoOwnerReplacementCommit committed = owner.CommittedReplacement!;
        byte[] oldGuid = fixture.Auth.Voucher.Guid;
        byte[] newGuid = proposal.ReplacementDeviceGuid.ToArray();
        byte[] ownerKey = new FdoPublicKeyCodec().Encode(run.Owner2).ToArray();
        FdoOwnershipVoucherHeader previous = FdoInitializationFields.ReadHeader(fixture.Auth.Voucher.HeaderTag);
        FdoOwnershipVoucherHeader header = FdoInitializationFields.ReadHeader(proposal.EncodedVoucherHeaderTag);
        byte[] expectedHeader = EncodeReplacementHeader(
            newGuid, rendezvous, previous.DeviceInfo, ownerKey, previous.CertificateChainHash.Encode());
        byte[] headerContents = new FdoCborCodec().ReadByteStringPayload(expectedHeader).ToArray();
        byte[] expectedMac = curveSize == 256
            ? HMACSHA256.HashData(run.SecretBytes, headerContents)
            : HMACSHA384.HashData(run.SecretBytes, headerContents);
        byte[] expectedHmac = EncodeReplacementHmac(curveSize == 256 ? 5 : 6, expectedMac);
        byte[] expectedVoucher = EncodeReplacementVoucher(expectedHeader, expectedHmac, fixture.Auth.EncodedChain);

        await Assert.That(oldGuid.Length).IsEqualTo(16);
        await Assert.That(newGuid.Length).IsEqualTo(16);
        await Assert.That(newGuid.AsSpan().SequenceEqual(oldGuid)).IsFalse();
        await Assert.That(proposal.PreviousDeviceGuid.Span.SequenceEqual(oldGuid)).IsTrue();
        await Assert.That(committed.PreviousDeviceGuid.Span.SequenceEqual(oldGuid)).IsTrue();
        await Assert.That(committed.ReplacementDeviceGuid.Span.SequenceEqual(newGuid)).IsTrue();
        await Assert.That(header.Guid.Span.SequenceEqual(newGuid)).IsTrue();
        await Assert.That(header.DeviceInfo).IsEqualTo(previous.DeviceInfo);
        await Assert.That(header.CertificateChainHash.Encode().Span
            .SequenceEqual(previous.CertificateChainHash.Encode().Span)).IsTrue();
        await Assert.That(header.RendezvousInfo.Span.SequenceEqual(rendezvous)).IsTrue();
        await Assert.That(header.ManufacturerKey.Span.SequenceEqual(ownerKey)).IsTrue();
        await Assert.That(proposal.EncodedVoucherHeaderTag.Span.SequenceEqual(expectedHeader)).IsTrue();
        await Assert.That(committed.EncodedVoucherHeaderTag.Span.SequenceEqual(expectedHeader)).IsTrue();
        await Assert.That(proposal.EncodedOwnerPublicKey.Span.SequenceEqual(ownerKey)).IsTrue();
        byte[] expectedOwnerHash = new FdoHashValue(
            curveSize == 256 ? FdoHashAlgorithm.Sha256 : FdoHashAlgorithm.Sha384,
            curveSize == 256 ? SHA256.HashData(ownerKey) : SHA384.HashData(ownerKey)).Encode().ToArray();
        await Assert.That(proposal.EncodedOwnerPublicKeyHash.Span.SequenceEqual(expectedOwnerHash)).IsTrue();
        await Assert.That(proposal.VoucherHmacAlgorithm).IsEqualTo(curveSize == 256
            ? FdoDeviceHmacAlgorithm.HmacSha256 : FdoDeviceHmacAlgorithm.HmacSha384);
        await Assert.That(run.Secret.KeySizeInBytes).IsEqualTo(curveSize == 256 ? 32 : 64);
        await Assert.That(run.Secret.Inputs.Count).IsEqualTo(1);
        await Assert.That(run.Secret.Inputs[0].AsSpan().SequenceEqual(headerContents)).IsTrue();
        await Assert.That(committed.EncodedVoucherHeaderHmac.Span.SequenceEqual(expectedHmac)).IsTrue();
        await Assert.That(committed.EncodedVoucher.Span.SequenceEqual(expectedVoucher)).IsTrue();
        var voucherReader = new CborReader(committed.EncodedVoucher, CborConformanceMode.Canonical);
        await Assert.That(voucherReader.ReadStartArray()).IsEqualTo(5);
        await Assert.That(voucherReader.ReadInt32()).IsEqualTo(200);
        await Assert.That(voucherReader.ReadEncodedValue().Span.SequenceEqual(expectedHeader)).IsTrue();
        await Assert.That(voucherReader.ReadEncodedValue().Span.SequenceEqual(expectedHmac)).IsTrue();
        await Assert.That(voucherReader.ReadEncodedValue().Span.SequenceEqual(fixture.Auth.EncodedChain)).IsTrue();
        await Assert.That(voucherReader.ReadStartArray()).IsEqualTo(0);
        voucherReader.ReadEndArray();
        voucherReader.ReadEndArray();
        await Assert.That(voucherReader.BytesRemaining).IsEqualTo(0);
        await Assert.That(ReferenceEquals(device.StagedReplacement!.VoucherHmacSecret, run.Secret)).IsTrue();
        await Assert.That(ReferenceEquals(device.ActivatedReplacement, device.StagedReplacement)).IsTrue();
        await Assert.That(enrollment.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(owner.DoneAckHandoffConfirmed).IsTrue();
        await Assert.That(device.DoneAckAuthenticated).IsTrue();
    }

    [Test]
    [Arguments(2048, true)]
    [Arguments(2048, false)]
    [Arguments(3072, false)]
    public async Task ReplacementAcceptsDistinctRsaOwner2AndPreservesHmac(int keySize, bool restricted)
    {
        using var run = new ReplacementFixture();
        using RSA manufacturer = RSA.Create(keySize);
        using RSA owner = RSA.Create(keySize);
        using RSA owner2 = RSA.Create(keySize);
        Fixture fixture = run.Fixture;
        fixture.Exchange = keySize == 2048 ? FdoKeyExchangeSuite.Asymkex2048 : FdoKeyExchangeSuite.Asymkex3072;
        fixture.OwnerPairedAsym = fixture.DevicePairedAsym = true;
        ConfigureRsaVoucher(fixture, manufacturer, owner, restricted);
        fixture.Replacement = new FdoOwnerReplacementOptions
        {
            Owner2SigningKey = owner2,
            EncodedRendezvousInfo = run.Rendezvous,
            Handler = run.Handler,
        };

        await fixture.RunAsync();

        FdoDeviceReplacementProposal proposal = fixture.DeviceSession!.ReplacementProposal!;
        FdoOwnerReplacementCommit committed = fixture.Session!.CommittedReplacement!;
        ReadOnlyMemory<byte> encodedOwner2 = new FdoPublicKeyCodec().EncodeRsa(owner2, restricted);
        byte[] headerContents = new FdoCborCodec().ReadByteStringPayload(proposal.EncodedVoucherHeaderTag).ToArray();
        byte[] expectedHmac = EncodeReplacementHmac(5, HMACSHA256.HashData(run.SecretBytes, headerContents));
        await Assert.That(proposal.EncodedOwnerPublicKey.Span.SequenceEqual(encodedOwner2.Span)).IsTrue();
        await Assert.That(proposal.VoucherHmacAlgorithm).IsEqualTo(FdoDeviceHmacAlgorithm.HmacSha256);
        await Assert.That(committed.EncodedVoucherHeaderHmac.Span.SequenceEqual(expectedHmac)).IsTrue();
        await Assert.That(committed.EncodedVoucherHeaderTag.Span.SequenceEqual(proposal.EncodedVoucherHeaderTag.Span))
            .IsTrue();
        await Assert.That(fixture.DeviceSession.ActivatedReplacement).IsNotNull();
        await Assert.That(fixture.Session.CommittedEnrollment).IsNotNull();
    }

    [Test]
    public async Task ReplacementCallbacksFollowAuthenticatedProtocolOrder()
    {
        using var run = new ReplacementFixture();
        await run.Fixture.RunAsync();
        Fixture fixture = run.Fixture;
        List<string> events = fixture.Events;
        await Assert.That(events.IndexOf("validate") >= 0).IsTrue();
        await Assert.That(events.IndexOf("validate") < events.IndexOf("reserve")).IsTrue();
        await Assert.That(events.IndexOf("reserve") < events.IndexOf("stage")).IsTrue();
        await Assert.That(events.IndexOf("stage") < events.IndexOf("wire:90")).IsTrue();
        await Assert.That(events.IndexOf("wire:90") < events.IndexOf("replacement-commit")).IsTrue();
        await Assert.That(events.IndexOf("replacement-commit") < events.IndexOf("commit")).IsTrue();
        await Assert.That(events.IndexOf("commit") < events.IndexOf("wire:91")).IsTrue();
        await Assert.That(events.IndexOf("wire:91") < events.IndexOf("activate")).IsTrue();
        await Assert.That(events.IndexOf("activate") < events.IndexOf("install")).IsTrue();
        await Assert.That(run.Handler.ReserveCalls).IsEqualTo(1);
        await Assert.That(run.Handler.StageCalls).IsEqualTo(1);
        await Assert.That(run.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(run.Handler.ActivateCalls).IsEqualTo(1);
        await Assert.That(run.Handler.AckAuthenticatedAtActivation).IsTrue();
        await Assert.That(run.Handler.DoneSendStartedAtCommit).IsTrue();
        await Assert.That(fixture.Session!.CommittedReplacement).IsNotNull();
        await Assert.That(fixture.Session.CommittedEnrollment).IsNotNull();
        await Assert.That(fixture.DeviceSession!.InstalledEnrollment).IsNotNull();
    }

    [Test]
    [Arguments("setup")]
    [Arguments("certificate")]
    [Arguments("authorization")]
    public async Task ReplacementRejectsBeforeStagingAtAuthenticationAndPolicyBoundaries(string failure)
    {
        using var run = new ReplacementFixture();
        Fixture fixture = run.Fixture;
        fixture.RejectCertificate = failure == "certificate";
        run.Handler.RejectReserve = failure == "authorization";
        if (failure == "setup")
        {
            fixture.Transport.Change = (message, _) =>
            {
                if (message.Type != 87) return message;
                byte[] changed = message.Body.ToArray();
                changed[^1] ^= 1;
                return message with { Body = changed };
            };
        }

        if (failure == "authorization")
            await CatchAsync<InvalidOperationException>(fixture.RunAsync);
        else
            await CatchAsync<CryptographicException>(fixture.RunAsync);

        FdoDeviceSession device = fixture.DeviceSession!;
        await Assert.That(fixture.ValidationCalls).IsEqualTo(failure == "setup" ? 0 : 1);
        await Assert.That(run.Handler.ReserveCalls).IsEqualTo(failure == "authorization" ? 1 : 0);
        await Assert.That(device.ReplacementSecretReservationStarted).IsEqualTo(failure == "authorization");
        await Assert.That(device.ReplacementSecretReserved).IsFalse();
        await Assert.That(device.ReplacementStagingStarted).IsFalse();
        await Assert.That(run.Handler.StageCalls).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 90)).IsFalse();
        await Assert.That(run.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(run.Handler.ActivateCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task ReplacementRejectsDeviceInapplicableRendezvousBeforeReservation()
    {
        using var run = new ReplacementFixture();
        // The only local DNS directive is explicitly Owner-only.
        run.Fixture.Replacement = new FdoOwnerReplacementOptions
        {
            Owner2SigningKey = run.Owner2,
            Handler = run.Handler,
            EncodedRendezvousInfo = Convert.FromHexString("8182820141F682054F6E72767365727665722E6C6F63616C"),
        };
        await ExpectPeerErrorAsync(run.Fixture.RunAsync, 100, FdoTo2MessageType.DeviceServiceInfoRdy20);
        await Assert.That(run.Handler.ReserveCalls).IsEqualTo(0);
        await Assert.That(run.Fixture.ValidationCalls).IsEqualTo(0);
        await Assert.That(run.Fixture.Transport.Messages.Any(message => message.Type == 87)).IsFalse();
        await Assert.That(run.Fixture.Transport.Messages.Any(message => message.Type == 90)).IsFalse();
    }

    [Test]
    [Arguments("algorithm")]
    [Arguments("length")]
    [Arguments("same-handle")]
    public async Task ReplacementRejectsInvalidOrReusedSecretHandle(string failure)
    {
        using var run = new ReplacementFixture();
        using var oldSecret = new RecordingVoucherHmacSecret(
            FdoDeviceHmacAlgorithm.HmacSha256, run.Fixture.Auth.Voucher.Secret);
        if (failure == "same-handle")
        {
            run.Fixture.IncludeRawVoucherSecret = false;
            run.Fixture.OpaqueVoucherSecret = oldSecret;
            run.Handler.Secret = oldSecret;
        }
        else if (failure == "algorithm")
            run.Secret.Algorithm = FdoDeviceHmacAlgorithm.HmacSha384;
        else
            run.Secret.KeySizeInBytes--;

        if (failure == "length")
            await CatchAsync<ArgumentException>(run.Fixture.RunAsync);
        else
            await CatchAsync<CryptographicException>(run.Fixture.RunAsync);

        FdoDeviceSession device = run.Fixture.DeviceSession!;
        await Assert.That(run.Fixture.ValidationCalls).IsEqualTo(1);
        await Assert.That(run.Handler.ReserveCalls).IsEqualTo(1);
        await Assert.That(device.ReplacementSecretReservationStarted).IsTrue();
        await Assert.That(device.ReplacementSecretReserved).IsTrue();
        await Assert.That(device.ReplacementStagingStarted).IsFalse();
        await Assert.That(device.StagedReplacement).IsNull();
        await Assert.That(run.Fixture.Transport.Messages.Any(message => message.Type == 90)).IsFalse();
        await Assert.That(run.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(run.Fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments("stage")]
    [Arguments("compute")]
    [Arguments("short")]
    public async Task ReplacementStageOrComputeFailureDoesNotSendDone(string failure)
    {
        using var run = new ReplacementFixture();
        run.Handler.FailStage = failure == "stage";
        run.Secret.ThrowOnCompute = failure == "compute";
        run.Secret.ShortResult = failure == "short";
        if (failure == "short")
            await CatchAsync<ArgumentException>(run.Fixture.RunAsync);
        else
            await CatchAsync<InvalidOperationException>(run.Fixture.RunAsync);

        FdoDeviceSession device = run.Fixture.DeviceSession!;
        await Assert.That(device.ReplacementSecretReserved).IsTrue();
        await Assert.That(device.ReplacementStagingStarted).IsTrue();
        await Assert.That(run.Handler.StageCalls).IsEqualTo(1);
        await Assert.That(device.StagedReplacement is not null).IsEqualTo(failure != "stage");
        await Assert.That(run.Secret.Inputs.Count).IsEqualTo(failure == "stage" ? 0 : 1);
        await Assert.That(device.DoneSendStarted).IsFalse();
        await Assert.That(run.Fixture.Transport.Messages.Any(message => message.Type == 90)).IsFalse();
        await Assert.That(run.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(run.Fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task TamperedReplacementDoneDoesNotCommitOrActivate()
    {
        using var run = new ReplacementFixture();
        run.Fixture.Transport.Change = (message, _) =>
        {
            if (message.Type != 90) return message;
            byte[] changed = message.Body.ToArray();
            changed[^1] ^= 1;
            return message with { Body = changed };
        };
        await CatchAsync<CryptographicException>(run.Fixture.RunAsync);
        await Assert.That(run.Fixture.DeviceSession!.StagedReplacement).IsNotNull();
        await Assert.That(run.Fixture.DeviceSession.DoneSendStarted).IsTrue();
        await Assert.That(run.Fixture.Session!.ReplacementCommitStarted).IsFalse();
        await Assert.That(run.Fixture.Session.CommittedReplacement).IsNull();
        await Assert.That(run.Fixture.Session.EnrollmentCommitStarted).IsFalse();
        await Assert.That(run.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(run.Handler.ActivateCalls).IsEqualTo(0);
        await Assert.That(run.Fixture.Transport.Messages.Any(message => message.Type == 91)).IsFalse();
        await Assert.That(run.Fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ReplacementLostOrTamperedDoneAckLeavesDeviceInactive(bool tampered)
    {
        using var run = new ReplacementFixture();
        run.Fixture.Transport.Change = (message, _) =>
        {
            if (message.Type != 91) return message;
            if (!tampered) throw new IOException("Handoff failed.");
            byte[] changed = message.Body.ToArray();
            changed[^1] ^= 1;
            return message with { Body = changed };
        };
        if (tampered)
            await CatchAsync<CryptographicException>(run.Fixture.RunAsync);
        else
            await CatchAsync<IOException>(run.Fixture.RunAsync);

        FdoOwnerSession owner = run.Fixture.Session!;
        FdoDeviceSession device = run.Fixture.DeviceSession!;
        await Assert.That(device.StagedReplacement).IsNotNull();
        await Assert.That(device.DoneSendStarted).IsTrue();
        await Assert.That(owner.CommittedReplacement).IsNotNull();
        await Assert.That(owner.CommittedEnrollment).IsNotNull();
        await Assert.That(owner.DoneAckProduced).IsTrue();
        await Assert.That(owner.DoneAckHandoffConfirmed).IsEqualTo(tampered);
        await Assert.That(device.DoneAckAuthenticated).IsFalse();
        await Assert.That(device.ReplacementActivationStarted).IsFalse();
        await Assert.That(device.InstallationStarted).IsFalse();
        await Assert.That(run.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(run.Handler.ActivateCalls).IsEqualTo(0);
        await Assert.That(run.Fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments("lost-ack")]
    [Arguments("owner-commit")]
    [Arguments("device-activation")]
    [Arguments("complete")]
    public async Task ReopensTo2JournalsWithoutInferringActivationOrInstallation(string interruption)
    {
        using var ownerJournal = new DurableRoleJournal();
        using var deviceJournal = new DurableRoleJournal();
        using var cancellation = new CancellationTokenSource();
        DurableRoleJournal.Writer ownerWriter = ownerJournal.FenceAndOpen();
        DurableRoleJournal.Writer deviceWriter = deviceJournal.FenceAndOpen();
        string previousGuid;
        using (var run = new ReplacementFixture())
        {
            previousGuid = Convert.ToHexString(run.Fixture.Auth.Voucher.Guid);
            deviceWriter.Record(Guid.Empty, "active", previousGuid, 0);
            run.Handler.OnStageSucceeded = () =>
            {
                FdoDeviceReplacementCredential staged = run.Handler.Staged!;
                deviceWriter.Record(staged.Proposal.RunId, "stage", Convert.ToHexString(staged.Proposal.ReplacementDeviceGuid.Span), 1);
            };
            run.Handler.OnCommitSucceeded = () =>
            {
                FdoOwnerReplacementCommit committed = run.Handler.Committed!;
                ownerWriter.Record(committed.RunId, "voucher",
                    Convert.ToHexString(SHA256.HashData(committed.EncodedVoucher.Span)), 0);
                if (interruption == "owner-commit")
                {
                    cancellation.Cancel();
                }
            };
            run.Fixture.Handler.OnCommitSucceeded = () =>
            {
                FdoEnrollmentCommit committed = run.Fixture.Handler.Committed!;
                ownerWriter.Record(committed.Request.RunId, "enrollment",
                    Convert.ToHexString(SHA256.HashData(committed.Certificate.Span)), 1);
            };
            run.Handler.OnActivateSucceeded = () =>
            {
                FdoDeviceReplacementCredential staged = run.Handler.Staged!;
                deviceWriter.Record(staged.Proposal.RunId, "active", Convert.ToHexString(staged.Proposal.ReplacementDeviceGuid.Span), 2);
                if (interruption == "device-activation")
                {
                    cancellation.Cancel();
                }
            };
            run.Fixture.OnInstallSucceeded = () => deviceWriter.Record(
                run.Fixture.DeviceSession!.RunId, "install",
                Convert.ToHexString(SHA256.HashData(run.Fixture.Certificate)), 3);
            if (interruption == "lost-ack")
            {
                run.Fixture.Transport.Change = (message, _) => message.Type == 91
                    ? throw new IOException("The acknowledgment did not reach the Device.") : message;
                await CatchAsync<IOException>(run.Fixture.RunAsync);
            }
            else if (interruption != "complete")
            {
                await CatchAsync<OperationCanceledException>(() => run.Fixture.RunAsync(cancellation.Token));
            }
            else
            {
                await run.Fixture.RunAsync();
            }
        }

        ownerJournal.FenceAndOpen();
        deviceJournal.FenceAndOpen();
        var owner = ownerJournal.ReadEffects();
        var device = deviceJournal.ReadEffects();
        bool activated = interruption is "device-activation" or "complete";
        await Assert.That(string.Join(",", owner.Select(effect => effect.Operation)))
            .IsEqualTo(interruption == "owner-commit" ? "voucher" : "voucher,enrollment");
        await Assert.That(string.Join(",", device.Select(effect => effect.Operation)))
            .IsEqualTo(interruption == "complete" ? "active,stage,active,install" :
                activated ? "active,stage,active" : "active,stage");
        await Assert.That(device[1].Input != previousGuid).IsTrue();
        await Assert.That(device.Last(effect => effect.Operation == "active").Input)
            .IsEqualTo(activated ? device[1].Input : previousGuid);
        if (interruption == "complete")
        {
            await Assert.That(device[^1].Input).IsEqualTo(owner[^1].Input);
        }
    }

    [Test]
    public async Task ReplacementRejectsAuthenticatedDoneAckWithWrongNonce()
    {
        using var run = new ReplacementFixture();
        run.Fixture.Transport.Change = (message, _) =>
        {
            if (message.Type == 90)
            {
                // Change the Owner nonce after signed setup, before it seals DoneAck.
                var field = typeof(FdoOwnerSession).GetField(
                    "_setupNonce", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                    ?? throw new InvalidOperationException("The Owner setup nonce field is missing.");
                var nonce = field.GetValue(run.Fixture.Session) as byte[]
                    ?? throw new InvalidOperationException("The Owner setup nonce is missing.");
                nonce[0] ^= 1;
            }
            return message;
        };

        await CatchAsync<CryptographicException>(run.Fixture.RunAsync);

        FdoOwnerSession owner = run.Fixture.Session!;
        FdoDeviceSession device = run.Fixture.DeviceSession!;
        await Assert.That(owner.CommittedReplacement).IsNotNull();
        await Assert.That(owner.CommittedEnrollment).IsNotNull();
        await Assert.That(owner.DoneAckHandoffConfirmed).IsTrue();
        await Assert.That(device.StagedReplacement).IsNotNull();
        await Assert.That(device.DoneAckAuthenticated).IsFalse();
        await Assert.That(device.ReplacementActivationStarted).IsFalse();
        await Assert.That(device.InstallationStarted).IsFalse();
        await Assert.That(run.Handler.ActivateCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments("stage")]
    [Arguments("replacement")]
    [Arguments("activation")]
    public async Task ReplacementCancellationAfterCallbacksPreservesObservedEffects(string phase)
    {
        using var run = new ReplacementFixture();
        using var cancellation = new CancellationTokenSource();
        run.Handler.OnStageSucceeded = phase == "stage" ? cancellation.Cancel : null;
        run.Handler.OnCommitSucceeded = phase == "replacement" ? cancellation.Cancel : null;
        run.Handler.OnActivateSucceeded = phase == "activation" ? cancellation.Cancel : null;

        await CatchAsync<OperationCanceledException>(() => run.Fixture.RunAsync(cancellation.Token));

        FdoOwnerSession owner = run.Fixture.Session!;
        FdoDeviceSession device = run.Fixture.DeviceSession!;
        await Assert.That(device.StagedReplacement).IsNotNull();
        await Assert.That(device.DoneSendStarted).IsEqualTo(phase != "stage");
        await Assert.That(owner.ReplacementCommitStarted).IsEqualTo(phase != "stage");
        await Assert.That(owner.CommittedReplacement is not null).IsEqualTo(phase != "stage");
        await Assert.That(owner.EnrollmentCommitStarted).IsEqualTo(phase == "activation");
        await Assert.That(owner.CommittedEnrollment is not null).IsEqualTo(phase == "activation");
        await Assert.That(device.DoneAckAuthenticated).IsEqualTo(phase == "activation");
        await Assert.That(device.ReplacementActivationStarted).IsEqualTo(phase == "activation");
        await Assert.That(device.ActivatedReplacement is not null).IsEqualTo(phase == "activation");
        await Assert.That(device.InstallationStarted).IsFalse();
        await Assert.That(run.Fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments("replacement")]
    [Arguments("enrollment")]
    [Arguments("activation")]
    public async Task ReplacementCallbackFailuresPreserveOnlyObservedSuccess(string failure)
    {
        using var run = new ReplacementFixture();
        run.Handler.FailCommit = failure == "replacement";
        run.Fixture.Handler.FailCommit = failure == "enrollment";
        run.Handler.FailActivate = failure == "activation";
        if (failure == "activation")
        {
            await CatchAsync<InvalidOperationException>(run.Fixture.RunAsync);
        }
        else
        {
            await ExpectPeerErrorAsync(run.Fixture.RunAsync, 500, FdoTo2MessageType.Done20);
        }

        FdoOwnerSession owner = run.Fixture.Session!;
        FdoDeviceSession device = run.Fixture.DeviceSession!;
        await Assert.That(owner.SentErrorCode).IsEqualTo(failure == "activation" ? null : (ushort?)500);
        await Assert.That(device.DoneSendStarted).IsTrue();
        await Assert.That(owner.ReplacementCommitStarted).IsTrue();
        await Assert.That(owner.CommittedReplacement is not null).IsEqualTo(failure != "replacement");
        await Assert.That(owner.EnrollmentCommitStarted).IsEqualTo(failure != "replacement");
        await Assert.That(owner.CommittedEnrollment is not null).IsEqualTo(failure == "activation");
        await Assert.That(run.Fixture.Handler.CommitCalls).IsEqualTo(failure == "replacement" ? 0 : 1);
        await Assert.That(owner.DoneAckProduced).IsEqualTo(failure == "activation");
        await Assert.That(owner.DoneAckHandoffConfirmed).IsEqualTo(failure == "activation");
        await Assert.That(device.DoneAckAuthenticated).IsEqualTo(failure == "activation");
        await Assert.That(device.ReplacementActivationStarted).IsEqualTo(failure == "activation");
        await Assert.That(device.ActivatedReplacement).IsNull();
        await Assert.That(device.InstallationStarted).IsFalse();
        await Assert.That(run.Handler.ActivateCalls).IsEqualTo(failure == "activation" ? 1 : 0);
        await Assert.That(run.Fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task ReplacementEvidenceSurvivesExposedBufferMutation()
    {
        using var run = new ReplacementFixture();
        await run.Fixture.RunAsync();
        FdoDeviceSession device = run.Fixture.DeviceSession!;
        FdoDeviceReplacementProposal proposal = device.ReplacementProposal!;
        FdoOwnerReplacementCommit commit = run.Fixture.Session!.CommittedReplacement!;
        byte[][] protectedBodies = run.Fixture.Transport.Messages
            .Where(message => message.Type is 87 or 90 or 91)
            .Select(message => message.Body.ToArray()).ToArray();
        byte[][] expected =
        [
            proposal.PreviousDeviceGuid.ToArray(), proposal.ReplacementDeviceGuid.ToArray(),
            proposal.EncodedVoucherHeaderTag.ToArray(), proposal.EncodedRendezvousInfo.ToArray(),
            proposal.EncodedOwnerPublicKey.ToArray(), proposal.EncodedOwnerPublicKeyHash.ToArray(),
            commit.PreviousDeviceGuid.ToArray(), commit.ReplacementDeviceGuid.ToArray(),
            commit.EncodedVoucherHeaderTag.ToArray(), commit.EncodedVoucherHeaderHmac.ToArray(),
            commit.EncodedVoucher.ToArray(),
        ];
        ReadOnlyMemory<byte>[] exposed =
        [
            proposal.PreviousDeviceGuid, proposal.ReplacementDeviceGuid, proposal.EncodedVoucherHeaderTag,
            proposal.EncodedRendezvousInfo, proposal.EncodedOwnerPublicKey, proposal.EncodedOwnerPublicKeyHash,
            commit.PreviousDeviceGuid, commit.ReplacementDeviceGuid, commit.EncodedVoucherHeaderTag,
            commit.EncodedVoucherHeaderHmac, commit.EncodedVoucher,
        ];
        foreach (ReadOnlyMemory<byte> value in exposed) ClearExposedMemory(value);
        ReadOnlyMemory<byte>[] reread =
        [
            proposal.PreviousDeviceGuid, proposal.ReplacementDeviceGuid, proposal.EncodedVoucherHeaderTag,
            proposal.EncodedRendezvousInfo, proposal.EncodedOwnerPublicKey, proposal.EncodedOwnerPublicKeyHash,
            commit.PreviousDeviceGuid, commit.ReplacementDeviceGuid, commit.EncodedVoucherHeaderTag,
            commit.EncodedVoucherHeaderHmac, commit.EncodedVoucher,
        ];
        for (int i = 0; i < expected.Length; i++)
            await Assert.That(reread[i].Span.SequenceEqual(expected[i])).IsTrue();
        await Assert.That(device.StagedReplacement!.Proposal.EncodedVoucherHeaderTag.Span
            .SequenceEqual(expected[2])).IsTrue();
        await Assert.That(ReferenceEquals(device.StagedReplacement.VoucherHmacSecret, run.Secret)).IsTrue();
        await Assert.That(commit.EncodedVoucherHeaderTag.Span.SequenceEqual(expected[2])).IsTrue();
        FdoPairedMessage[] protectedMessages = run.Fixture.Transport.Messages
            .Where(message => message.Type is 87 or 90 or 91).ToArray();
        await Assert.That(protectedBodies.Length).IsEqualTo(3);
        for (int i = 0; i < protectedBodies.Length; i++)
            await Assert.That(protectedMessages[i].Body.Span.SequenceEqual(protectedBodies[i])).IsTrue();
        await Assert.That(run.Fixture.InstallCalls).IsEqualTo(1);
    }

    [Test]
    [Arguments(256, 256, false)]
    [Arguments(384, 256, true)]
    [Arguments(256, 384, true)]
    [Arguments(384, 384, true)]
    public async Task ReplacementHmacSelectionUsesBothKeyStrengths(int deviceSize, int ownerSize, bool sha384)
    {
        using ECDsa device = ECDsa.Create(deviceSize == 256
            ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
        using ECDsa owner = ECDsa.Create(ownerSize == 256
            ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
        int deviceType = FdoInitializationFields.GetKeyType(device);
        int ownerType = FdoInitializationFields.GetKeyType(new FdoPublicKeyCodec().Encode(owner));
        await Assert.That(FdoInitializationFields.SelectHmac(deviceType, ownerType)).IsEqualTo(
            sha384 ? FdoDeviceHmacAlgorithm.HmacSha384 : FdoDeviceHmacAlgorithm.HmacSha256);
        await Assert.That(deviceType == ownerType).IsEqualTo(deviceSize == ownerSize);
    }

    [Test]
    public async Task CredentialReuseDoesNotInvokeConfiguredReplacementHandler()
    {
        using var run = new ReplacementFixture();
        run.Fixture.Replacement = null;
        run.Fixture.OwnerReuse = true;
        run.Fixture.Device = run.Fixture.Device with { AllowCredentialReuse = true };
        FdoDeviceEnrollment result = await run.Fixture.RunAsync();

        await Assert.That(run.Handler.ReserveCalls).IsEqualTo(0);
        await Assert.That(run.Handler.StageCalls).IsEqualTo(0);
        await Assert.That(run.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(run.Handler.ActivateCalls).IsEqualTo(0);
        await Assert.That(run.Fixture.DeviceSession!.ReplacementProposal).IsNull();
        await Assert.That(run.Fixture.Session!.CommittedReplacement).IsNull();
        await Assert.That(run.Fixture.Session.CommittedEnrollment).IsNotNull();
        await Assert.That(run.Fixture.DeviceSession.DoneAckAuthenticated).IsTrue();
        await Assert.That(result.Certificate.Span.SequenceEqual(run.Fixture.Certificate)).IsTrue();
    }

    [Test]
    public async Task ReplacementRequiresExplicitDeviceOptInEvenWhenReuseIsAllowed()
    {
        using var run = new ReplacementFixture();
        run.Fixture.ReplacementHandler = null;
        run.Fixture.Device = run.Fixture.Device with { AllowCredentialReuse = true };

        await CatchAsync<InvalidOperationException>(run.Fixture.RunAsync);

        await Assert.That(run.Fixture.Transport.Messages.Any(message => message.Type == 87)).IsTrue();
        await Assert.That(run.Fixture.Transport.Messages.Any(message => message.Type == 88)).IsFalse();
        await Assert.That(run.Fixture.Transport.Messages.Any(message => message.Type == 90)).IsFalse();
        await Assert.That(run.Fixture.DeviceSession!.ReplacementProposal).IsNull();
        await Assert.That(run.Fixture.ValidationCalls).IsEqualTo(0);
        await Assert.That(run.Handler.ReserveCalls).IsEqualTo(0);
        await Assert.That(run.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(run.Fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task ReplacementTakesPrecedenceWhenBothPeersAlsoAllowReuse()
    {
        using var run = new ReplacementFixture();
        run.Fixture.OwnerReuse = true;
        run.Fixture.Device = run.Fixture.Device with { AllowCredentialReuse = true };
        await run.Fixture.RunAsync();

        await Assert.That(run.Handler.ReserveCalls).IsEqualTo(1);
        await Assert.That(run.Handler.StageCalls).IsEqualTo(1);
        await Assert.That(run.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(run.Handler.ActivateCalls).IsEqualTo(1);
        await Assert.That(run.Fixture.Session!.CommittedReplacement).IsNotNull();
        await Assert.That(run.Fixture.DeviceSession!.ActivatedReplacement).IsNotNull();
        await Assert.That(run.Fixture.InstallCalls).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AuthenticatedOwnerChannelUsesReadyAndOwnerChallengesForTheirOwnMessages(bool replacement)
    {
        using var run = new ReplacementFixture();
        Fixture fixture = run.Fixture;
        if (!replacement)
        {
            fixture.Replacement = null;
            fixture.OwnerReuse = true;
        }

        using FdoOwnerSession owner = fixture.CreateSession();
        var initial = new FdoTo2InitialCodec();
        ReadOnlyMemory<byte> probe = initial.EncodeProbe(new FdoTo2InitialCodec.Probe(
            new byte[] { 4 }, Array.Empty<string>(), fixture.Auth.Voucher.Guid, 8192,
            new long[] { (long)FdoHashAlgorithm.Sha256 }, new byte[16]));
        FdoOwnerResponse acknowledgement = await SendOwnerAsync(owner, FdoTo2MessageType.HelloDeviceProbe, probe);
        byte[] doneNonce = initial.CheckAcknowledgement(probe, acknowledgement.EncodedBody)
            .Message.NonceTo2ProveDv.ToArray();
        using var exchange = FdoEcdhKeyExchange.Create(fixture.Exchange, FdoEcdhParty.Device);
        byte[] ownerProofNonce = Convert.FromHexString("202122232425262728292A2B2C2D2E2F");
        ReadOnlyMemory<byte> proof = new FdoTo2DeviceProofCodec().Sign(
            probe, acknowledgement.EncodedBody, fixture.Exchange, fixture.Cipher,
            exchange.ExportParameter(), ownerProofNonce, fixture.Auth.DeviceSigningKey);
        FdoOwnerResponse ownerProof = await SendOwnerAsync(owner, FdoTo2MessageType.ProveDevice20, proof);
        using FdoTo2OwnerProofCodec.PendingOwnerProof pending = new FdoTo2OwnerProofCodec().BeginDeviceVerification(
            ownerProof.EncodedBody, ownerProofNonce, fixture.Exchange, fixture.Auth.Voucher.Guid,
            fixture.Auth.Voucher.ManufacturerHash, fixture.Auth.Voucher.HmacAlgorithm, fixture.Auth.Voucher.Secret);
        var cbor = new FdoCborCodec();
        for (int i = 0; i < pending.EntryCount; i++)
        {
            FdoOwnerResponse entry = await SendOwnerAsync(
                owner, FdoTo2MessageType.GetOVNextEntry20, FdoPairedProtocol.EncodeEntryRequest(i));
            pending.AppendEntry(i, FdoPairedProtocol.DecodeEntryResponse(cbor, entry.EncodedBody, i));
        }

        FdoTo2OwnerProofCodec.OwnerProof verifiedOwner = pending.CompleteDeviceChecks();
        byte[] key = FdoPairedProtocol.DeriveSessionKey(exchange, verifiedOwner.OwnerParameter, fixture.Cipher);
        using var channel = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, fixture.Cipher, key);
        CryptographicOperations.ZeroMemory(key);
        byte[] readyNonce = (byte[])doneNonce.Clone();
        readyNonce[0] ^= 0x80;
        var info = new FdoTo2ServiceInfoCodec();
        FdoOwnerResponse setup = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceServiceInfoRdy20,
            channel.Seal(info.EncodeDeviceReady(4096, readyNonce)));
        byte[] signedSetup = channel.Open(setup.EncodedBody);
        var setupCodec = new FdoTo2SetupDeviceCodec();
        await Assert.That(setupCodec.ReadUntrustedDisposition(signedSetup)).IsEqualTo(replacement ? 1UL : 2UL);
        if (replacement)
        {
            FdoTo2SetupDeviceCodec.Replacement parsed =
                setupCodec.VerifyReplacement(verifiedOwner, signedSetup, readyNonce);
            await Assert.That(parsed.Nonce.Span.SequenceEqual(readyNonce)).IsTrue();
            await Assert.That(parsed.OwnerKey.Span.SequenceEqual(new FdoPublicKeyCodec().Encode(run.Owner2).Span)).IsTrue();
        }
        else
        {
            await Assert.That(setupCodec.Verify(verifiedOwner, signedSetup, true)).IsEqualTo((ushort?)4096);
        }

        FdoOwnerResponse activation = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false, FdoPairedProtocol.EncodeInventory(
                new FdoDeviceMetadata("test-os", "test-arch", "1", "test-device", ":", "test-arch")))));
        FdoTo2ServiceInfoCodec.OwnerServiceInfo activated = info.DecodeOwner(channel.Open(activation.EncodedBody));
        await Assert.That(activated.ServiceInfo.Single().Key).IsEqualTo("fdo.csr:active");
        FdoOwnerResponse issued = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
            channel.Seal(info.EncodeDevice(false,
            [
                new FdoServiceInfoCodec.Entry("fdo.csr:active", new byte[] { 0xF5 }),
                new FdoCsrBase64TextCodec(4096).EncodeRequest(fixture.Request),
            ])));
        await Assert.That(info.DecodeOwner(channel.Open(issued.EncodedBody)).IsDone).IsTrue();
        var completion = new FdoTo2CompletionCodec();
        var selectedHmac = replacement
            ? new FdoHashValue(FdoHashAlgorithm.HmacSha256, Enumerable.Repeat((byte)0xA5, 32).ToArray())
            : null;
        ReadOnlyMemory<byte> done = completion.EncodeDone(doneNonce, selectedHmac);
        FdoTo2CompletionCodec.Done20 decodedDone = completion.DecodeDone(done);
        await Assert.That(decodedDone.Nonce.Span.SequenceEqual(doneNonce)).IsTrue();
        await Assert.That(decodedDone.Nonce.Span.SequenceEqual(readyNonce)).IsFalse();
        await Assert.That(decodedDone.ReplacementHmac is not null).IsEqualTo(replacement);
        FdoOwnerResponse ack = await SendOwnerAsync(owner, FdoTo2MessageType.Done20, channel.Seal(done));
        await Assert.That(completion.DecodeDoneAck(channel.Open(ack.EncodedBody)).Span
            .SequenceEqual(readyNonce)).IsTrue();
        await Assert.That(owner.DoneAckHandoffConfirmed).IsTrue();
        await Assert.That(owner.CommittedEnrollment).IsNotNull();
        await Assert.That(run.Handler.CommitCalls).IsEqualTo(replacement ? 1 : 0);
    }

    private static byte[] EncodeReplacementHeader(
        byte[] guid, byte[] rendezvous, string deviceInfo, byte[] ownerKey, ReadOnlyMemory<byte> chainHash)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(6);
        writer.WriteInt32(200);
        writer.WriteByteString(guid);
        writer.WriteEncodedValue(rendezvous);
        writer.WriteTextString(deviceInfo);
        writer.WriteEncodedValue(ownerKey);
        writer.WriteEncodedValue(chainHash.Span);
        writer.WriteEndArray();
        var wrapper = new CborWriter(CborConformanceMode.Canonical);
        wrapper.WriteByteString(writer.Encode());
        return wrapper.Encode();
    }

    private static byte[] EncodeReplacementHmac(int algorithm, byte[] mac)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(2);
        writer.WriteInt32(algorithm);
        writer.WriteByteString(mac);
        writer.WriteEndArray();
        return writer.Encode();
    }

    private static byte[] EncodeReplacementVoucher(byte[] header, byte[] hmac, byte[] chain)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(5);
        writer.WriteInt32(200);
        writer.WriteEncodedValue(header);
        writer.WriteEncodedValue(hmac);
        writer.WriteEncodedValue(chain);
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndArray();
        return writer.Encode();
    }

    [Test]
    [Arguments(1)]
    [Arguments(2)]
    public async Task DelegatedReuseCompletesAfterHostAcceptsVerifiedEvidence(int depth)
    {
        using var fixture = new Fixture();
        using var chain = new DelegateChain(fixture.Auth.Voucher.FinalOwner, depth, ReuseOnly);
        RecordingDelegateAcceptance acceptance = fixture.UseDelegate(chain);
        acceptance.MessageCount = () => fixture.Transport.Messages.Count;

        await fixture.RunAsync();

        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(1);
        await Assert.That(acceptance.Calls).IsEqualTo(1);
        FdoDelegateEvidence evidence = acceptance.Evidence!;
        await Assert.That(evidence.LeafCertificate.Span.SequenceEqual(chain.Encoded[0].Span)).IsTrue();
        await Assert.That(SameKey(evidence.DelegatePublicKey, chain.LeafKey)).IsTrue();
        await Assert.That(SameKey(evidence.OwnerPublicKey, fixture.Auth.Voucher.FinalOwner)).IsTrue();
        await Assert.That(evidence.MayOnboardReuseCredentials).IsTrue();
        await Assert.That(evidence.MayOnboardNewCredentials).IsFalse();
        await Assert.That(evidence.MayRedirect).IsFalse();
        await Assert.That(ProbeCapability(fixture)).IsEqualTo((byte)0x84);
        await Assert.That(AckCapability(fixture)).IsEqualTo((byte)0x84);
        int firstServiceInfoReady = fixture.Transport.Messages.FindIndex(message => message.Type == 86);
        await Assert.That(firstServiceInfoReady).IsGreaterThan(0);
        await Assert.That(acceptance.MessagesAtAccept).IsLessThanOrEqualTo(firstServiceInfoReady);
    }

    [Test]
    public async Task DelegatedReplacementRequiresNewCredentialPermissionAndOwner2Signature()
    {
        using var run = new ReplacementFixture();
        using var chain = new DelegateChain(
            run.Fixture.Auth.Voucher.FinalOwner, 2,
            [FdoDelegateChainVerifier.OnboardNewCredentialsOid, FdoDelegateChainVerifier.OnboardReuseCredentialsOid]);
        RecordingDelegateAcceptance acceptance = run.Fixture.UseDelegate(chain);

        await run.Fixture.RunAsync();

        await Assert.That(run.Fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(run.Fixture.Session!.CommittedReplacement).IsNotNull();
        await Assert.That(acceptance.Evidence!.MayOnboardNewCredentials).IsTrue();
        await Assert.That(acceptance.Evidence.MayOnboardReuseCredentials).IsTrue();
    }

    [Test]
    public async Task NondelegatedRunKeepsTheFdo20CapabilityOnly()
    {
        using var fixture = new Fixture();

        await fixture.RunAsync();

        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(ProbeFlags(fixture).SequenceEqual(new byte[] { 0x04 })).IsTrue();
        await Assert.That(AckFlags(fixture).SequenceEqual(new byte[] { 0x04 })).IsTrue();
    }

    [Test]
    public async Task DelegatedDeviceRejectsAnOwnerThatDoesNotAcknowledgeDelegation()
    {
        using var fixture = new Fixture();
        using var chain = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 1, ReuseOnly);
        RecordingDelegateAcceptance acceptance = fixture.UseDelegate(chain);
        fixture.OwnerDelegated = false;
        fixture.OwnerDelegateKey = null;
        fixture.OwnerDelegateChain = null;

        await CatchAsync<NotSupportedException>(fixture.RunAsync);

        await Assert.That(acceptance.Calls).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages.Select(message => message.Type))
            .IsEquivalentTo(new ushort[] { 80, 81 });
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task DelegatedOwnerRejectsADeviceThatDoesNotAdvertiseDelegation()
    {
        using var fixture = new Fixture();
        using var chain = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 1, ReuseOnly);
        fixture.UseDelegate(chain);
        fixture.DeviceDelegated = false;
        fixture.DelegateAcceptance = null;

        await CatchAsync<NotSupportedException>(fixture.RunAsync);

        await Assert.That(fixture.Transport.Messages.Select(message => message.Type))
            .IsEquivalentTo(new ushort[] { 80 });
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task HostDenialEndsTheRunBeforeAnyProtectedMessage()
    {
        using var fixture = new Fixture();
        using var chain = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 1, ReuseOnly);
        RecordingDelegateAcceptance acceptance = fixture.UseDelegate(chain);
        acceptance.Result = false;
        acceptance.MessageCount = () => fixture.Transport.Messages.Count;

        await CatchAsync<FdoDelegateNotAcceptedException>(fixture.RunAsync);

        await Assert.That(acceptance.Calls).IsEqualTo(1);
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(acceptance.MessagesAtAccept);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 255)).IsFalse();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task DeviceSendsError104WhenAnAuthenticatedReplacementLacksDelegatePermission()
    {
        using var run = new ReplacementFixture();
        var transport = new ErrorRecordingTransport(run.Fixture.Events);
        run.Fixture.Transport = transport;
        using var chain = new DelegateChain(run.Fixture.Auth.Voucher.FinalOwner, 1, ReuseOnly);
        RecordingDelegateAcceptance acceptance = run.Fixture.UseDelegate(chain);

        // Test-only bypass: the Owner constructor refuses a replacement when its
        // Delegate chain lacks the new-credential permission. Setting the
        // replacement fields after construction skips only that disposition
        // check; the Owner still verifies its chain, signs the proof with the
        // Delegate, and signs SetupDevice with Owner2, so the Device reaches its
        // own authenticated permission check.
        run.Fixture.Replacement = null;
        run.Fixture.OwnerReuse = true;
        FdoOwnerSession owner = run.Fixture.CreateSession();
        SetField(owner, "_replacementSigningKey", run.Owner2);
        SetField(owner, "_replacementHandler", run.Handler);
        SetField(owner, "_replacementRendezvous", new ReadOnlyMemory<byte>(run.Rendezvous));

        await CatchAsync<FdoDelegateNotPermittedException>(() => run.Fixture.RunAsync(owner));

        await Assert.That(acceptance.Calls).IsEqualTo(1);
        await Assert.That(run.Fixture.DeviceSession!.SentErrorCode).IsEqualTo((ushort?)104);
        await Assert.That(owner.ReceivedErrorCode).IsEqualTo((ushort?)104);
        await Assert.That(transport.Messages[^2].Type).IsEqualTo((ushort)87);
        await Assert.That(transport.Messages[^1].Type).IsEqualTo((ushort)255);
        await Assert.That(run.Handler.ReserveCalls).IsEqualTo(0);
        await Assert.That(run.Fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task OwnerRejectsDelegateChainsItCannotUseBeforeAnyMessage()
    {
        using var fixture = new Fixture();
        ECDsa owner = fixture.Auth.Voucher.FinalOwner;
        using var disable = new DelegateChain(owner, 1, [FdoDelegateChainVerifier.OnboardDisableOid]);
        using var redirect = new DelegateChain(owner, 1, [FdoDelegateChainVerifier.RedirectOid]);
        using var newOnly = new DelegateChain(owner, 1, [FdoDelegateChainVerifier.OnboardNewCredentialsOid]);
        using var p384 = new DelegateChain(owner, 1, ReuseOnly, ECCurve.NamedCurves.nistP384);
        using ECDsa foreignOwner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var foreign = new DelegateChain(foreignOwner, 1, ReuseOnly);
        using var valid = new DelegateChain(owner, 1, ReuseOnly);
        using ECDsa wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        fixture.UseDelegate(disable);
        await Assert.That(Throws<NotSupportedException>(() => fixture.CreateSession())).IsTrue();
        fixture.UseDelegate(redirect);
        await Assert.That(Throws<FdoDelegateNotPermittedException>(() => fixture.CreateSession())).IsTrue();
        fixture.UseDelegate(newOnly);
        await Assert.That(Throws<FdoDelegateNotPermittedException>(() => fixture.CreateSession())).IsTrue();
        fixture.UseDelegate(p384);
        await Assert.That(Throws<CryptographicException>(() => fixture.CreateSession())).IsTrue();
        fixture.UseDelegate(foreign);
        await Assert.That(Throws<FdoDelegateChainException>(() => fixture.CreateSession())).IsTrue();
        fixture.UseDelegate(valid);
        fixture.OwnerDelegateKey = wrongKey;
        await Assert.That(Throws<CryptographicException>(() => fixture.CreateSession())).IsTrue();
        fixture.OwnerDelegateKey = null;
        await Assert.That(Throws<ArgumentNullException>(() => fixture.CreateSession())).IsTrue();
        fixture.OwnerDelegateKey = valid.LeafKey;
        fixture.OwnerDelegated = false;
        await Assert.That(Throws<ArgumentException>(() => fixture.CreateSession())).IsTrue();
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
    }

    [Test]
    public async Task OwnerRejectsReuseOnlyDelegateForReplacement()
    {
        using var run = new ReplacementFixture();
        using var chain = new DelegateChain(run.Fixture.Auth.Voucher.FinalOwner, 1, ReuseOnly);
        run.Fixture.UseDelegate(chain);

        await Assert.That(Throws<FdoDelegateNotPermittedException>(() => run.Fixture.CreateSession())).IsTrue();
    }

    public enum ForgedProof
    {
        RedirectOnly = 0,
        ReuseWithDisable = 1,
        ForeignOwner = 2,
        WrongSigner = 3,
        TamperedEntry = 4,
    }

    [Test]
    [Arguments(ForgedProof.RedirectOnly)]
    [Arguments(ForgedProof.ReuseWithDisable)]
    [Arguments(ForgedProof.ForeignOwner)]
    [Arguments(ForgedProof.WrongSigner)]
    [Arguments(ForgedProof.TamperedEntry)]
    public async Task DeviceRejectsAnUnusableDelegatedProofSilentlyBeforeHostAcceptance(ForgedProof forged)
    {
        using var fixture = new Fixture();
        ECDsa owner = fixture.Auth.Voucher.FinalOwner;
        using var valid = new DelegateChain(owner, 1, ReuseOnly);
        using var redirect = new DelegateChain(owner, 1, [FdoDelegateChainVerifier.RedirectOid]);
        using var disable = new DelegateChain(
            owner, 1, [FdoDelegateChainVerifier.OnboardReuseCredentialsOid, FdoDelegateChainVerifier.OnboardDisableOid]);
        using ECDsa foreignOwner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var foreign = new DelegateChain(foreignOwner, 1, ReuseOnly);
        using ECDsa wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        RecordingDelegateAcceptance acceptance = fixture.UseDelegate(valid);

        // Test-only bypass: the Owner session refuses to sign with these chains,
        // so the transport replaces the Owner's valid delegated ProveOVHdr20 (or
        // its first voucher entry) with a forged one. The Device sees exactly
        // what a misbehaving or impersonating Owner could send.
        fixture.Transport.Change = forged switch
        {
            ForgedProof.RedirectOnly => ResignOwnerProof(redirect.Encoded, redirect.LeafKey),
            ForgedProof.ReuseWithDisable => ResignOwnerProof(disable.Encoded, disable.LeafKey),
            ForgedProof.ForeignOwner => ResignOwnerProof(foreign.Encoded, foreign.LeafKey),
            ForgedProof.WrongSigner => ResignOwnerProof(valid.Encoded, wrongKey),
            _ => (message, count) =>
            {
                if (message.Type != 85 || count != 1)
                {
                    return message;
                }

                byte[] body = message.Body.ToArray();
                body[^1] ^= 0x01;
                return message with { Body = body };
            }
            ,
        };

        Exception failure = await CatchAsync<Exception>(fixture.RunAsync);

        switch (forged)
        {
            case ForgedProof.RedirectOnly:
                await Assert.That(failure.GetType()).IsEqualTo(typeof(FdoDelegateNotPermittedException));
                break;
            case ForgedProof.ReuseWithDisable:
                await Assert.That(failure.GetType()).IsEqualTo(typeof(NotSupportedException));
                break;
            case ForgedProof.ForeignOwner:
                await Assert.That(((FdoDelegateChainException)failure).Reason)
                    .IsEqualTo(FdoDelegateChainFailure.OwnerSignature);
                break;
            default:
                await Assert.That(failure is CryptographicException and not FdoDelegateChainException).IsTrue();
                break;
        }

        ushort[] types = fixture.Transport.Messages.Select(message => message.Type).ToArray();
        await Assert.That(acceptance.Calls).IsEqualTo(0);
        await Assert.That(types.Contains((ushort)86)).IsFalse();
        await Assert.That(types.Contains((ushort)255)).IsFalse();
        await Assert.That(fixture.DeviceSession!.SentErrorCode).IsNull();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(types[^1]).IsEqualTo(forged == ForgedProof.TamperedEntry ? (ushort)85 : (ushort)83);
    }

    private static Func<FdoPairedMessage, int, FdoPairedMessage> ResignOwnerProof(
        IReadOnlyList<ReadOnlyMemory<byte>> chain, ECDsa signer) =>
        (message, _) =>
        {
            if (message.Type != 83)
            {
                return message;
            }

            var reader = new CborReader(message.Body, CborConformanceMode.Canonical);
            reader.ReadTag();
            reader.ReadStartArray();
            reader.ReadByteString();
            reader.SkipValue();
            var payload = new CborReader(reader.ReadByteString(), CborConformanceMode.Canonical);
            payload.ReadStartArray();
            var writer = new CborWriter(CborConformanceMode.Canonical);
            writer.WriteStartArray(8);
            for (int i = 0; i < 7; i++)
            {
                writer.WriteEncodedValue(payload.ReadEncodedValue().Span);
            }

            writer.WriteEncodedValue(new FdoX5ChainCodec().Encode(chain).Span);
            writer.WriteEndArray();
            ReadOnlyMemory<byte> signed = new FdoCoseSign1Codec().Sign(
                FdoSignatureOperation.TO2ProveOVHdr, FdoCoseSignatureAlgorithm.ES256, signer, writer.Encode());
            return message with { Body = signed.ToArray() };
        };

    [Test]
    public async Task DelegationRejectsAsymkexAndInconsistentDeviceOptions()
    {
        using var fixture = new Fixture();
        using var chain = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 1, ReuseOnly);
        fixture.UseDelegate(chain);
        fixture.Exchange = FdoKeyExchangeSuite.Asymkex2048;
        fixture.OwnerPairedAsym = fixture.DevicePairedAsym = true;
        await Assert.That(Throws<NotSupportedException>(() => fixture.CreateDeviceSession())).IsTrue();
        await Assert.That(Throws<NotSupportedException>(() => fixture.CreateSession())).IsTrue();

        fixture.Exchange = FdoKeyExchangeSuite.Ecdh256;
        fixture.OwnerPairedAsym = fixture.DevicePairedAsym = false;
        fixture.DelegateAcceptance = null;
        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        fixture.DelegateAcceptance = new RecordingDelegateAcceptance(fixture.Events);
        fixture.DeviceDelegated = false;
        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        fixture.DelegateAcceptance = null;
        fixture.DeviceDelegateTime = TimeProvider.System;
        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(1)]
    [Arguments(2)]
    public async Task DelegatedRedirectIsAcceptedBeforeKeysWithAnOwnerSignedProof(int depth)
    {
        using var fixture = new Fixture();
        using var chain = new DelegateChain(fixture.Auth.Voucher.FinalOwner, depth, RedirectOnly);
        (RendezvousFixture rendezvous, RecordingRedirectAcceptance acceptance) =
            await UseDelegatedRedirectAsync(fixture, chain);

        FdoDeviceEnrollment result = await fixture.RunAsync();

        await Assert.That(result.Certificate.Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(acceptance.Calls).IsEqualTo(1);
        FdoRedirectDelegateEvidence evidence = acceptance.Evidence!;
        await Assert.That(evidence.LeafCertificate.Span.SequenceEqual(chain.Encoded[0].Span)).IsTrue();
        await Assert.That(SameKey(evidence.DelegatePublicKey, chain.LeafKey)).IsTrue();
        await Assert.That(SameKey(evidence.OwnerPublicKey, fixture.Auth.Voucher.FinalOwner)).IsTrue();
        await Assert.That(evidence.Address.DnsName).IsEqualTo(rendezvous.Address.DnsName);
        await Assert.That(evidence.Address.Port).IsEqualTo(rendezvous.Address.Port);
        int firstProtected = fixture.Transport.Messages.FindIndex(message => message.Type >= 86);
        await Assert.That(acceptance.MessagesAtAccept).IsGreaterThan(0);
        await Assert.That(acceptance.MessagesAtAccept).IsLessThanOrEqualTo(firstProtected);
        await Assert.That(ProbeFlags(fixture).SequenceEqual(new byte[] { 0x04 })).IsTrue();
        await Assert.That(AckFlags(fixture).SequenceEqual(new byte[] { 0x04 })).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DistinctRedirectAndTo2DelegatesNeedSeparatePermissionsAndApprovals(bool discover)
    {
        using var fixture = new Fixture();
        using var onboarding = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 1, ReuseOnly);
        using var redirect = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 2, RedirectOnly);
        RecordingDelegateAcceptance onboardingAcceptance = fixture.UseDelegate(onboarding);
        (_, RecordingRedirectAcceptance redirectAcceptance) = await UseDelegatedRedirectAsync(
            fixture, redirect, discover: discover);
        fixture.DeviceDelegateTime = new RendezvousFixture.TestClock();

        await fixture.RunAsync();

        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(redirectAcceptance.Calls).IsEqualTo(1);
        await Assert.That(onboardingAcceptance.Calls).IsEqualTo(1);
        await Assert.That(SameKey(redirectAcceptance.Evidence!.DelegatePublicKey, redirect.LeafKey)).IsTrue();
        await Assert.That(SameKey(onboardingAcceptance.Evidence!.DelegatePublicKey, onboarding.LeafKey)).IsTrue();
        await Assert.That(onboardingAcceptance.Evidence.MayRedirect).IsFalse();
        await Assert.That(fixture.Events.IndexOf("redirect-accept"))
            .IsLessThan(fixture.Events.IndexOf("delegate-accept"));
        await Assert.That(ProbeCapability(fixture)).IsEqualTo((byte)0x84);
    }

    [Test]
    [Arguments("good")]
    [Arguments("revoked")]
    [Arguments("proof")]
    [Arguments("voucher")]
    public async Task OfflineTo2StatusIsCheckedAfterVoucherAndProofButBeforeAcceptance(string scenario)
    {
        using var fixture = new Fixture();
        using var chain = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 2, ReuseOnly);
        RecordingDelegateAcceptance acceptance = fixture.UseDelegate(chain);
        var clock = new RendezvousFixture.TestClock();
        var source = new OfflineStatusFixture(clock)
        {
            Transform = statuses =>
            {
                fixture.Events.Add("offline-status");
                if (scenario == "revoked")
                {
                    statuses[^1] = statuses[^1] with { Status = FdoDelegateCertificateStatus.Revoked };
                }

                return statuses;
            },
        };
        fixture.DeviceDelegateTime = clock;
        fixture.DeviceOfflineRevocation = source.Policy;
        var ownerSource = new OfflineStatusFixture(clock);
        fixture.OwnerDelegateTime = clock;
        fixture.OwnerOfflineRevocation = ownerSource.Policy;
        fixture.Transport.Change = (message, _) =>
        {
            if ((scenario == "proof" && message.Type == 83) || (scenario == "voucher" && message.Type == 85))
            {
                byte[] altered = message.Body.ToArray();
                altered[^1] ^= 1;
                return message with { Body = altered };
            }

            return message;
        };

        if (scenario == "good")
        {
            await fixture.RunAsync();
            await Assert.That(ownerSource.Calls).IsEqualTo(2);
            await Assert.That(source.Calls).IsEqualTo(1);
            await Assert.That(acceptance.Calls).IsEqualTo(1);
            await Assert.That(fixture.Events.IndexOf("offline-status"))
                .IsLessThan(fixture.Events.IndexOf("delegate-accept"));
            await Assert.That(fixture.InstallCalls).IsEqualTo(1);
        }
        else
        {
            await CatchAsync<CryptographicException>(fixture.RunAsync);
            await Assert.That(source.Calls).IsEqualTo(scenario == "revoked" ? 1 : 0);
            await Assert.That(acceptance.Calls).IsEqualTo(0);
            await Assert.That(fixture.DeviceSession!.SentErrorCode).IsNull();
            await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
            await Assert.That(fixture.InstallCalls).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DelegateExpiryIsCheckedAtProofReceiptAndBeforeAcceptance(bool duringVoucher)
    {
        using var fixture = new Fixture();
        using var chain = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 2, ReuseOnly);
        RecordingDelegateAcceptance acceptance = fixture.UseDelegate(chain);
        var clock = new RendezvousFixture.TestClock();
        fixture.DeviceDelegateTime = clock;
        var source = new OfflineStatusFixture(clock);
        fixture.DeviceOfflineRevocation = source.Policy;
        fixture.Transport.Change = (message, _) =>
        {
            if (message.Type == (duringVoucher ? 85 : 83))
            {
                clock.Now = DateTimeOffset.UtcNow.AddDays(3);
            }

            return message;
        };

        var rejected = await CatchAsync<FdoDelegateChainException>(fixture.RunAsync);
        await Assert.That(rejected.Reason).IsEqualTo(FdoDelegateChainFailure.Validity);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type == 84)).IsEqualTo(duringVoucher);
        await Assert.That(source.Calls).IsEqualTo(0);
        await Assert.That(acceptance.Calls).IsEqualTo(0);
        await Assert.That(fixture.DeviceSession!.SentErrorCode).IsNull();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task RequiredRedirectStatusDoesNotAuthorizeOnboardingOrAcceptAnUnknownIssuer()
    {
        using var fixture = new Fixture();
        using var chain = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 1, RedirectOnly);
        (_, RecordingRedirectAcceptance acceptance) = await UseDelegatedRedirectAsync(fixture, chain);
        var source = new OfflineStatusFixture(fixture.RedirectTime!)
        {
            Transform = statuses => [statuses[0] with { Status = FdoDelegateCertificateStatus.NoAuthority }],
        };
        fixture.RedirectOfflineRevocation = source.Policy;
        await CatchAsync<NotSupportedException>(fixture.RunAsync);
        await Assert.That(source.Calls).IsEqualTo(1);
        await Assert.That(acceptance.Calls).IsEqualTo(0);
        await Assert.That(fixture.DeviceSession!.SentErrorCode).IsNull();
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(2, "accept")]
    [Arguments(3, "accept")]
    [Arguments(2, "tamper")]
    [Arguments(3, "deny")]
    public async Task MultiAddressDelegatedRedirectRequiresExplicitBoundSelection(int count, string outcome)
    {
        using var fixture = new Fixture();
        using var chain = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 1, RedirectOnly);
        var rendezvous = new RendezvousFixture(fixture.Auth)
        {
            Address = new FdoRendezvousAddress(null, "primary.example", 8443, FdoRendezvousTransportProtocol.Https),
        };
        var alternate = new FdoRendezvousAddress(
            IPAddress.Parse("::ffff:192.0.2.21").GetAddressBytes(), null, 7443, FdoRendezvousTransportProtocol.Https);
        var third = new FdoRendezvousAddress(null, "b\u00fccher.example.", 8443, FdoRendezvousTransportProtocol.Https);
        FdoRendezvousAddress[] extras = count == 2 ? [alternate] : [alternate, third];
        using var disk = new FdoAtomicRendezvousStoreTests.TestDisk { Now = rendezvous.Clock.Now };
        var store = disk.Open();
        using var registration = rendezvous.CreateServer(
            FdoRendezvousProtocol.OwnerRegistration, store, new FdoDelegatedRendezvousTests.Admission());
        var to0 = rendezvous.CreateTransport(registration);
        to0.OwnerSignSource = IPAddress.Loopback;
        var owner = rendezvous.CreateOwner(delegateKey: chain.LeafKey, delegateCertificates: chain.Encoded,
            additionalAddresses: extras);
        extras[0] = third;
        await owner.RunAsync(to0);
        using var lookup = rendezvous.CreateServer(FdoRendezvousProtocol.DeviceLookup, store);
        FdoDeviceRendezvousResult result = await rendezvous.CreateDevice(delegated: true).RunAsync(rendezvous.CreateTransport(lookup));
        var submission = rendezvous.Codec.ReadOwnerSign(
            to0.Messages.Single(message => message.Type == FdoRendezvousMessageType.OwnerSign).Body, 10, true);
        await Assert.That(result.SignedRedirect.Span.SequenceEqual(submission.SignedRedirect.Span)).IsTrue();
        await Assert.That(result.SignedRedirect.Span.SequenceEqual(registration.StoredRegistration!.SignedRedirect.Span)).IsTrue();
        await Assert.That(result.CandidateAddresses.Count).IsEqualTo(count);
        await Assert.That(result.CandidateAddresses[0].DnsName).IsEqualTo("primary.example");
        await Assert.That(result.CandidateAddresses[1].Port).IsEqualTo((ushort)7443);
        await Assert.That(Throws<InvalidOperationException>(() => _ = result.CandidateAddress)).IsTrue();

        if (outcome == "tamper")
        {
            byte[] tampered = result.SignedRedirect.ToArray();
            tampered[^1] ^= 1;
            result = FdoDeviceRendezvousResult.FromUntrustedBlob(fixture.Auth.Voucher.Guid, tampered);
        }

        var acceptance = new RecordingRedirectAcceptance(fixture.Events) { Result = outcome != "deny" };
        fixture.DeviceRendezvous = result;
        fixture.AcceptDelegatedRedirect = true;
        fixture.RedirectAcceptance = acceptance;
        fixture.RedirectTime = rendezvous.Clock;
        fixture.OwnerBypass = false;
        fixture.OwnerRendezvous = true;
        fixture.Device = fixture.Device with { AllowRendezvousBypass = false };
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => fixture.CreateDeviceSession(fixture.CreateDeviceOptions())))
            .IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => fixture.CreateDeviceSession(fixture.CreateDeviceOptions(count))))
            .IsTrue();
        int selectedIndex = count - 1;
        FdoDeviceSessionOptions options = fixture.CreateDeviceOptions(selectedIndex);
        using FdoDeviceSession wrongUri = fixture.CreateDeviceSession(options);
        await CatchAsync<InvalidOperationException>(() => wrongUri.RunAsync(
            new OriginRecordingTransport(fixture.Events, new Uri("https://primary.example:8443"))).AsTask());
        var ambiguousOrigin = new Uri(count == 2 ? "https://[::ffff:192.0.2.21%25bogus]:7443/" :
            "https://XN--BCHER-KVA.example:8443/");
        using FdoDeviceSession ambiguousUri = fixture.CreateDeviceSession(options);
        var rejectedTransport = new OriginRecordingTransport(fixture.Events, ambiguousOrigin);
        await CatchAsync<InvalidOperationException>(() => ambiguousUri.RunAsync(rejectedTransport).AsTask());
        await Assert.That(rejectedTransport.Messages.Count).IsEqualTo(0);
        using FdoDeviceSession opaqueTransport = fixture.CreateDeviceSession(options);
        await CatchAsync<InvalidOperationException>(() => opaqueTransport.RunAsync(
            new RecordingTransport(fixture.Events)).AsTask());
        await Assert.That(acceptance.Calls).IsEqualTo(0);
        await Assert.That(fixture.Events.Any(item => item.StartsWith("wire:", StringComparison.Ordinal))).IsFalse();

        var selected = new Uri(count == 2 ? "https://192.0.2.21:7443/" : "https://XN--BCHER-KVA.example.:8443/");
        fixture.Transport = new OriginRecordingTransport(fixture.Events, selected);
        using FdoDeviceSession session = fixture.CreateDeviceSession(options);
        if (outcome == "accept")
        {
            await fixture.RunAsync(fixture.CreateSession(), session);
            await Assert.That(acceptance.Calls).IsEqualTo(1);
            await Assert.That(FdoDelegatedRendezvousRoutes.SameSignedAddress(
                acceptance.Evidence!.Address, result.CandidateAddresses[selectedIndex])).IsTrue();
            await Assert.That(session.DoneAckAuthenticated).IsTrue();
            await Assert.That(fixture.InstallCalls).IsEqualTo(1);
        }
        else
        {
            if (outcome == "deny")
            {
                await CatchAsync<FdoRedirectDelegateNotAcceptedException>(() => fixture.RunAsync(fixture.CreateSession(), session));
            }
            else
            {
                await CatchAsync<CryptographicException>(() => fixture.RunAsync(fixture.CreateSession(), session));
            }

            await Assert.That(fixture.Transport.Messages.Any(message => message.Type >= 86)).IsFalse();
            await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
            await Assert.That(fixture.InstallCalls).IsEqualTo(0);
        }

        using FdoDeviceSession reused = fixture.CreateDeviceSession(options);
        var unused = new OriginRecordingTransport(fixture.Events, selected);
        await CatchAsync<InvalidOperationException>(() => reused.RunAsync(unused).AsTask());
        await Assert.That(unused.Messages.Count).IsEqualTo(0);
    }

    public enum RedirectFailure
    {
        ForeignAnchor = 0,
        WrongSigner = 1,
        Tampered = 2,
        MissingRedirect = 3,
        ExpiredAtRedirectTime = 4,
        HostDenied = 5,
        Canceled = 6,
    }

    [Test]
    [Arguments(RedirectFailure.ForeignAnchor)]
    [Arguments(RedirectFailure.WrongSigner)]
    [Arguments(RedirectFailure.Tampered)]
    [Arguments(RedirectFailure.MissingRedirect)]
    [Arguments(RedirectFailure.ExpiredAtRedirectTime)]
    [Arguments(RedirectFailure.HostDenied)]
    [Arguments(RedirectFailure.Canceled)]
    public async Task DelegatedRedirectFailuresStopBeforeKeysWithoutErrorOrEnrollment(RedirectFailure failure)
    {
        using var fixture = new Fixture();
        using ECDsa foreignOwner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var chain = new DelegateChain(
            failure == RedirectFailure.ForeignAnchor ? foreignOwner : fixture.Auth.Voucher.FinalOwner,
            2,
            failure == RedirectFailure.MissingRedirect
                ? [FdoDelegateChainVerifier.OnboardReuseCredentialsOid, FdoDelegateChainVerifier.OnboardNewCredentialsOid]
                : RedirectOnly);
        using ECDsa wrongSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        (_, RecordingRedirectAcceptance acceptance) = await UseDelegatedRedirectAsync(
            fixture, chain,
            signer: failure == RedirectFailure.WrongSigner ? wrongSigner : null,
            tamper: failure == RedirectFailure.Tampered);
        if (failure == RedirectFailure.ExpiredAtRedirectTime)
        {
            fixture.RedirectTime = new RendezvousFixture.TestClock { Now = DateTimeOffset.UtcNow.AddDays(3) };
        }

        using var cancellation = new CancellationTokenSource();
        acceptance.Result = failure != RedirectFailure.HostDenied;
        if (failure == RedirectFailure.Canceled)
        {
            acceptance.CancelOnAccept = cancellation;
        }

        Exception thrown = await CatchAsync<Exception>(() => fixture.RunAsync(cancellation.Token));

        switch (failure)
        {
            case RedirectFailure.ForeignAnchor:
                await Assert.That(((FdoDelegateChainException)thrown).Reason)
                    .IsEqualTo(FdoDelegateChainFailure.OwnerSignature);
                break;
            case RedirectFailure.ExpiredAtRedirectTime:
                await Assert.That(((FdoDelegateChainException)thrown).Reason)
                    .IsEqualTo(FdoDelegateChainFailure.Validity);
                break;
            case RedirectFailure.MissingRedirect:
                await Assert.That(thrown.GetType()).IsEqualTo(typeof(FdoDelegateNotPermittedException));
                break;
            case RedirectFailure.HostDenied:
                await Assert.That(thrown.GetType()).IsEqualTo(typeof(FdoRedirectDelegateNotAcceptedException));
                break;
            case RedirectFailure.Canceled:
                await Assert.That(thrown is OperationCanceledException).IsTrue();
                break;
            default:
                await Assert.That(thrown is CryptographicException and not FdoDelegateChainException).IsTrue();
                break;
        }

        bool reachedHost = failure is RedirectFailure.HostDenied or RedirectFailure.Canceled;
        await Assert.That(acceptance.Calls).IsEqualTo(reachedHost ? 1 : 0);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type >= 86)).IsFalse();
        await Assert.That(fixture.DeviceSession!.SentErrorCode).IsNull();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
        await Assert.That(fixture.Handler.CommitCalls).IsEqualTo(0);
        await Assert.That(fixture.ValidationCalls).IsEqualTo(0);
        await Assert.That(fixture.InstallCalls).IsEqualTo(0);
    }

    [Test]
    public async Task OnboardingDelegateWithoutRedirectPermissionCannotSignTheRedirect()
    {
        using var fixture = new Fixture();
        using var onboarding = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 1, ReuseOnly);
        RecordingDelegateAcceptance onboardingAcceptance = fixture.UseDelegate(onboarding);
        (_, RecordingRedirectAcceptance redirectAcceptance) = await UseDelegatedRedirectAsync(fixture, onboarding);

        await CatchAsync<FdoDelegateNotPermittedException>(fixture.RunAsync);

        await Assert.That(redirectAcceptance.Calls).IsEqualTo(0);
        await Assert.That(onboardingAcceptance.Calls).IsEqualTo(0);
        await Assert.That(fixture.Transport.Messages.Any(message => message.Type >= 86)).IsFalse();
        await Assert.That(fixture.DeviceSession!.SentErrorCode).IsNull();
        await Assert.That(fixture.Handler.IssueCalls).IsEqualTo(0);
    }

    [Test]
    public async Task DelegatedRedirectRequiresExplicitOptInAndConsistentOptions()
    {
        using var fixture = new Fixture();
        using var chain = new DelegateChain(fixture.Auth.Voucher.FinalOwner, 1, RedirectOnly);
        (_, RecordingRedirectAcceptance acceptance) = await UseDelegatedRedirectAsync(fixture, chain);

        fixture.AcceptDelegatedRedirect = false;
        fixture.RedirectAcceptance = null;
        fixture.RedirectTime = null;
        await Assert.That(Throws<NotSupportedException>(() => fixture.CreateDeviceSession())).IsTrue();
        fixture.RedirectAcceptance = acceptance;
        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        fixture.RedirectAcceptance = null;
        fixture.RedirectTime = TimeProvider.System;
        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        fixture.AcceptDelegatedRedirect = true;
        fixture.RedirectTime = null;
        fixture.RedirectAcceptance = acceptance;
        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        fixture.RedirectAcceptance = null;
        fixture.RedirectTime = TimeProvider.System;
        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        FdoDeviceRendezvousResult? result = fixture.DeviceRendezvous;
        fixture.DeviceRendezvous = null;
        fixture.RedirectAcceptance = acceptance;
        fixture.Device = fixture.Device with { AllowRendezvousBypass = true };
        await Assert.That(Throws<ArgumentException>(() => fixture.CreateDeviceSession())).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoDeviceRendezvousResult.FromUntrustedBlob(
            new byte[15], result!.SignedRedirect))).IsTrue();
        await Assert.That(fixture.Transport.Messages.Count).IsEqualTo(0);

        fixture.DeviceRendezvous = result;
        fixture.Device = fixture.Device with { AllowRendezvousBypass = false };
        await fixture.RunAsync();

        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(acceptance.Calls).IsEqualTo(1);
    }

    [Test]
    public async Task RedirectOptInKeepsNondelegatedBlobsOnTheOwnerSignedPath()
    {
        using var fixture = new Fixture();
        var rendezvous = new RendezvousFixture(fixture.Auth);
        await rendezvous.RegisterAsync();
        fixture.DeviceRendezvous = FdoDeviceRendezvousResult.FromUntrustedBlob(
            fixture.Auth.Voucher.Guid.ToArray(), rendezvous.Store.LastWritten!.SignedRedirect);
        fixture.Device = fixture.Device with { AllowRendezvousBypass = false };
        fixture.OwnerBypass = false;
        fixture.OwnerRendezvous = true;
        var acceptance = new RecordingRedirectAcceptance(fixture.Events);
        fixture.AcceptDelegatedRedirect = true;
        fixture.RedirectAcceptance = acceptance;
        fixture.RedirectTime = TimeProvider.System;

        await fixture.RunAsync();

        await Assert.That(fixture.DeviceSession!.DoneAckAuthenticated).IsTrue();
        await Assert.That(acceptance.Calls).IsEqualTo(0);
        await Assert.That(ProbeFlags(fixture).SequenceEqual(new byte[] { 0x04 })).IsTrue();
    }

    private static async Task<(RendezvousFixture Rendezvous, RecordingRedirectAcceptance Acceptance)>
        UseDelegatedRedirectAsync(
            Fixture fixture, DelegateChain chain, ECDsa? signer = null, bool tamper = false, bool discover = false)
    {
        var rendezvous = new RendezvousFixture(fixture.Auth);
        if (discover)
        {
            using var disk = new FdoAtomicRendezvousStoreTests.TestDisk { Now = rendezvous.Clock.Now };
            IFdoAtomicRendezvousRegistrationStore store = disk.Open();
            using var server = rendezvous.CreateServer(
                FdoRendezvousProtocol.OwnerRegistration, store, new FdoDelegatedRendezvousTests.Admission());
            var transport = rendezvous.CreateTransport(server);
            transport.OwnerSignSource = IPAddress.Loopback;
            await rendezvous.CreateOwner(delegateKey: chain.LeafKey, delegateCertificates: chain.Encoded).RunAsync(transport);
            using var lookup = rendezvous.CreateServer(FdoRendezvousProtocol.DeviceLookup, store);
            fixture.DeviceRendezvous = await rendezvous.CreateDevice(delegated: true).RunAsync(rendezvous.CreateTransport(lookup));
            await Assert.That(fixture.DeviceRendezvous.SignedRedirect.Span.SequenceEqual(
                server.StoredRegistration!.SignedRedirect.Span)).IsTrue();
        }
        else
        {
            await rendezvous.RegisterAsync();
            byte[] blob = DelegateRedirect(
                rendezvous.Store.LastWritten!.SignedRedirect, chain.Encoded, signer ?? chain.LeafKey);
            if (tamper)
            {
                blob[^1] ^= 1;
            }

            fixture.DeviceRendezvous = FdoDeviceRendezvousResult.FromUntrustedBlob(fixture.Auth.Voucher.Guid.ToArray(), blob);
        }
        fixture.Device = fixture.Device with { AllowRendezvousBypass = false };
        fixture.OwnerBypass = false;
        fixture.OwnerRendezvous = true;
        var acceptance = new RecordingRedirectAcceptance(fixture.Events)
        {
            MessageCount = () => fixture.Transport.Messages.Count,
        };
        fixture.AcceptDelegatedRedirect = true;
        fixture.RedirectAcceptance = acceptance;
        fixture.RedirectTime = new RendezvousFixture.TestClock();
        return (rendezvous, acceptance);
    }

    private static byte[] DelegateRedirect(
        ReadOnlyMemory<byte> ownerSigned, IReadOnlyList<ReadOnlyMemory<byte>> chain, ECDsa signer)
    {
        var reader = new CborReader(ownerSigned, CborConformanceMode.Canonical);
        reader.ReadTag();
        reader.ReadStartArray();
        reader.ReadByteString();
        reader.SkipValue();
        var payload = new CborReader(reader.ReadByteString(), CborConformanceMode.Strict);
        payload.ReadStartArray();
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteEncodedValue(payload.ReadEncodedValue().Span);
        writer.WriteEncodedValue(payload.ReadEncodedValue().Span);
        writer.WriteByteString(new FdoX5ChainCodec().Encode(chain).Span);
        writer.WriteEndArray();
        return new FdoCoseSign1Codec().Sign(
            FdoSignatureOperation.TO0OwnerSign, FdoCoseSignatureAlgorithm.ES256, signer, writer.Encode()).ToArray();
    }

    private static readonly string[] RedirectOnly = [FdoDelegateChainVerifier.RedirectOid];

    private static readonly string[] ReuseOnly = [FdoDelegateChainVerifier.OnboardReuseCredentialsOid];

    private static bool SameKey(ReadOnlyMemory<byte> encoded, ECDsa expected)
    {
        var codec = new FdoPublicKeyCodec();
        using FdoPublicKeyCodec.DecodedKey actual = codec.Decode(encoded);
        using FdoPublicKeyCodec.DecodedKey wanted = codec.Decode(codec.Encode(expected));
        return actual.HasSamePublicKey(wanted);
    }

    private static byte[] ProbeFlags(Fixture fixture) => new FdoTo2InitialCodec()
        .DecodeProbe(fixture.Transport.Messages.First(message => message.Type == 80).Body).CapabilityFlags.ToArray();

    private static byte[] AckFlags(Fixture fixture) => new FdoTo2InitialCodec()
        .DecodeAcknowledgement(fixture.Transport.Messages.First(message => message.Type == 81).Body)
        .CapabilityFlags.ToArray();

    private static byte ProbeCapability(Fixture fixture) => ProbeFlags(fixture)[0];

    private static byte AckCapability(Fixture fixture) => AckFlags(fixture)[0];

    private static void SetField(object target, string name, object? value) =>
        target.GetType().GetField(name, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .SetValue(target, value);

    private static async Task<TException> CatchAsync<TException>(Func<Task<FdoDeviceEnrollment>> action)
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

    private static int CaResponseSize(Fixture fixture)
    {
        var codec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        return new FdoTo2ServiceInfoCodec().EncodeOwner(
            false, false, [codec.EncodeCaCertificates(fixture.CreateCaCertificates())]).Length;
    }

    private static int AttributesResponseSize(Fixture fixture)
    {
        var attributes = new FdoCsrAttributes(fixture.OwnerAttributesHandler.EncodedAttributes);
        var codec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        return new FdoTo2ServiceInfoCodec().EncodeOwner(
            false, false, [codec.EncodeCsrAttributes(attributes)]).Length;
    }

    private static byte[] AttributesWithOctets(int length)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.3");
        writer.PushSetOf();
        writer.WriteOctetString(new byte[length]);
        writer.PopSetOf();
        writer.PopSequence();
        writer.PopSequence();
        return writer.Encode();
    }

    private static async Task<FdoTo2PairedAeadChannel> ActivateOwnerAsync(
        Fixture fixture, FdoOwnerSession owner)
    {
        OwnerServiceInfo opened = await OpenOwnerServiceInfoAsync(fixture, owner);
        var info = new FdoTo2ServiceInfoCodec();
        FdoOwnerResponse activation = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceSvcInfo20,
            opened.Channel.Seal(info.EncodeDevice(false, FdoPairedProtocol.EncodeInventory(
                new FdoDeviceMetadata("test-os", "test-arch", "1", "test-device", ":", "test-arch")))));
        FdoTo2ServiceInfoCodec.OwnerServiceInfo activated = info.DecodeOwner(
            opened.Channel.Open(activation.EncodedBody));
        if (activated.ServiceInfo.Single().Key != "fdo.csr:active")
        {
            throw new InvalidOperationException("The Owner did not activate fdo.csr.");
        }

        return opened.Channel;
    }

    private sealed record OwnerServiceInfo(FdoTo2PairedAeadChannel Channel, byte[] DoneNonce, byte[] ReadyNonce);

    /// <summary>
    /// Drives a scripted Device through SetupDevice20 and returns the live
    /// channel before the first DeviceSvcInfo20 is sent.
    /// </summary>
    private static async Task<OwnerServiceInfo> OpenOwnerServiceInfoAsync(Fixture fixture, FdoOwnerSession owner)
    {
        var initial = new FdoTo2InitialCodec();
        ReadOnlyMemory<byte> probe = initial.EncodeProbe(new FdoTo2InitialCodec.Probe(
            new byte[] { 4 }, Array.Empty<string>(), fixture.Auth.Voucher.Guid, 8192,
            new long[] { (long)FdoHashAlgorithm.Sha256 }, RandomNumberGenerator.GetBytes(16)));
        FdoOwnerResponse acknowledgement = await SendOwnerAsync(owner, FdoTo2MessageType.HelloDeviceProbe, probe);
        byte[] doneNonce = initial.CheckAcknowledgement(probe, acknowledgement.EncodedBody)
            .Message.NonceTo2ProveDv.ToArray();
        using var exchange = FdoEcdhKeyExchange.Create(fixture.Exchange, FdoEcdhParty.Device);
        byte[] nonce = RandomNumberGenerator.GetBytes(16);
        ReadOnlyMemory<byte> proof = new FdoTo2DeviceProofCodec().Sign(
            probe, acknowledgement.EncodedBody, fixture.Exchange, fixture.Cipher,
            exchange.ExportParameter(), nonce, fixture.Auth.DeviceSigningKey);
        FdoOwnerResponse ownerProof = await SendOwnerAsync(owner, FdoTo2MessageType.ProveDevice20, proof);
        using FdoTo2OwnerProofCodec.PendingOwnerProof pending = new FdoTo2OwnerProofCodec().BeginDeviceVerification(
            ownerProof.EncodedBody, nonce, fixture.Exchange, fixture.Auth.Voucher.Guid,
            fixture.Auth.Voucher.ManufacturerHash, fixture.Auth.Voucher.HmacAlgorithm, fixture.Auth.Voucher.Secret);
        var cbor = new FdoCborCodec();
        for (int i = 0; i < pending.EntryCount; i++)
        {
            FdoOwnerResponse entry = await SendOwnerAsync(
                owner, FdoTo2MessageType.GetOVNextEntry20, FdoPairedProtocol.EncodeEntryRequest(i));
            pending.AppendEntry(i, FdoPairedProtocol.DecodeEntryResponse(cbor, entry.EncodedBody, i));
        }

        FdoTo2OwnerProofCodec.OwnerProof verifiedOwner = pending.CompleteDeviceChecks();
        byte[] key = FdoPairedProtocol.DeriveSessionKey(exchange, verifiedOwner.OwnerParameter, fixture.Cipher);
        var channel = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, fixture.Cipher, key);
        CryptographicOperations.ZeroMemory(key);
        var info = new FdoTo2ServiceInfoCodec();
        byte[] readyNonce = RandomNumberGenerator.GetBytes(16);
        FdoOwnerResponse setup = await SendOwnerAsync(owner, FdoTo2MessageType.DeviceServiceInfoRdy20,
            channel.Seal(info.EncodeDeviceReady(4096, readyNonce)));
        _ = new FdoTo2SetupDeviceCodec().Verify(verifiedOwner, channel.Open(setup.EncodedBody), true);
        return new OwnerServiceInfo(channel, doneNonce, readyNonce);
    }

    private static async Task<FdoOwnerResponse> SendOwnerAsync(
        FdoOwnerSession owner, FdoTo2MessageType type, ReadOnlyMemory<byte> body)
    {
        FdoOwnerResponse response = await owner.ProcessAsync(200, type, body);
        owner.ConfirmResponseSent();
        return response;
    }

    private static async Task<FdoErrorMessageCodec.ErrorMessage> ExpectOwnerErrorAsync(
        FdoOwnerSession owner, IFdoTo2PairedChannel channel, FdoTo2MessageType type,
        ReadOnlyMemory<byte> body, ushort expectedCode)
    {
        FdoOwnerResponse response = await owner.ProcessAsync(200, type, body);
        await Assert.That(response.ProtocolVersion).IsEqualTo((ushort)200);
        await Assert.That(response.MessageType).IsEqualTo(FdoTo2MessageType.Error);
        FdoErrorMessageCodec.ErrorMessage error = new FdoErrorMessageCodec().Decode(
            channel.Open(response.EncodedBody));
        await Assert.That(error.ErrorCode).IsEqualTo(expectedCode);
        await Assert.That(error.PreviousMessageId).IsEqualTo((byte)type);
        await Assert.That(error.UntrustedDescription)
            .IsEqualTo("FDO message " + ((byte)type).ToString(CultureInfo.InvariantCulture) + " failed.");
        await Assert.That(owner.SentErrorCode).IsEqualTo((ushort?)expectedCode);
        await Assert.That(Throws<InvalidOperationException>(owner.ConfirmResponseSent)).IsTrue();
        return error;
    }

    private static byte[] IssueCertificate(Fixture fixture, ECDsa key, string subject, string? dns)
    {
        CertificateRequest request = CreateCertificateRequest(key, subject, dns);
        using X509Certificate2 certificate = request.Create(
            fixture.Auth.RootCertificate, DateTimeOffset.UtcNow.AddMinutes(-2),
            DateTimeOffset.UtcNow.AddHours(1), [1, 2, 3, 7]);
        return certificate.RawData;
    }

    private static byte[] CreateCsr(ECDsa key, string subject, string? dns, byte[]? identityChange)
    {
        CertificateRequest request = CreateCertificateRequest(key, subject, dns);
        if (identityChange is not null)
        {
            request.OtherRequestAttributes.Add(new AsnEncodedData("1.3.6.1.5.5.7.7.36", identityChange));
        }

        return request.CreateSigningRequest();
    }

    private static CertificateRequest CreateCertificateRequest(ECDsa key, string subject, string? dns)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        if (dns is not null)
        {
            request.CertificateExtensions.Add(DnsNames(dns));
        }

        return request;
    }

    private static X509Extension DnsNames(string dns)
    {
        var builder = new SubjectAlternativeNameBuilder();
        builder.AddDnsName(dns);
        return builder.Build();
    }

    private static byte[] IdentityChange(string? subject, string? dns)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        if (subject is not null)
        {
            writer.WriteEncodedValue(new X500DistinguishedName(subject).RawData);
        }

        if (dns is not null)
        {
            writer.WriteEncodedValue(DnsNames(dns).RawData);
        }

        writer.PopSequence();
        return writer.Encode();
    }

    private static void ClearReenrollmentSnapshots(FdoEnrollmentRequest request)
    {
        if (request.Reenrollment is not FdoReenrollmentDetails details)
        {
            return;
        }

        ClearExposedMemory(details.PriorCertificate);
        if (details.IdentityChange is FdoReenrollmentIdentityChange change)
        {
            ClearExposedMemory(change.EncodedValue);
            ClearExposedMemory(change.SubjectName);
            if (change.SubjectAlternativeNames is ReadOnlyMemory<byte> names)
            {
                ClearExposedMemory(names);
            }
        }
    }

    private static void ClearExposedMemory(ReadOnlyMemory<byte> value)
    {
        if (!MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment) || segment.Array is null)
        {
            throw new InvalidOperationException("The test expected array-backed memory.");
        }

        Array.Clear(segment.Array, segment.Offset, segment.Count);
    }

    private static byte[] Flip(ReadOnlyMemory<byte> value, Index position)
    {
        byte[] changed = value.ToArray();
        changed[position] ^= 1;
        return changed;
    }

    private static async Task ExpectPeerErrorAsync(Func<Task> run, ushort code, FdoTo2MessageType previous)
    {
        FdoPeerErrorException error = await CatchOwnerAsync<FdoPeerErrorException>(run);
        await Assert.That(error.ErrorCode).IsEqualTo(code);
        await Assert.That(error.PreviousMessageType).IsEqualTo(previous);
    }

    private static async Task<TException> CatchOwnerAsync<TException>(Func<Task> action)
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

    private sealed class TlsCertificateFixture : IDisposable
    {
        private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa _serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public TlsCertificateFixture(bool matchingName)
        {
            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
            DateTimeOffset notAfter = notBefore.AddHours(1);
            var rootRequest = new CertificateRequest("CN=FDO HTTPS test CA", _rootKey, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
            RootCertificate = rootRequest.CreateSelfSigned(notBefore, notAfter);

            var serverRequest = new CertificateRequest("CN=FDO HTTPS test server", _serverKey, HashAlgorithmName.SHA256);
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
            var names = new SubjectAlternativeNameBuilder();
            if (matchingName)
            {
                names.AddIpAddress(IPAddress.Loopback);
            }
            else
            {
                names.AddDnsName("other.invalid");
            }

            serverRequest.CertificateExtensions.Add(names.Build());
            using X509Certificate2 certificate = serverRequest.Create(
                RootCertificate, notBefore.AddMinutes(1), notAfter.AddMinutes(-1), [1, 2, 3, 6]);
            ServerCertificate = certificate.CopyWithPrivateKey(_serverKey);
        }

        public X509Certificate2 RootCertificate { get; }
        public X509Certificate2 ServerCertificate { get; }

        public void Dispose()
        {
            ServerCertificate.Dispose();
            RootCertificate.Dispose();
            _serverKey.Dispose();
            _rootKey.Dispose();
        }
    }

    private sealed class ObservedRsa(RSA inner) : RSA
    {
        public int DecryptCalls { get; private set; }
        public override int KeySize { get => inner.KeySize; set => inner.KeySize = value; }
        public override RSAParameters ExportParameters(bool includePrivateParameters) => inner.ExportParameters(includePrivateParameters);
        public override void ImportParameters(RSAParameters parameters) => inner.ImportParameters(parameters);
        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) => inner.Encrypt(data, padding);
        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
            DecryptCalls++;
            return inner.Decrypt(data, padding);
        }
        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) =>
            inner.SignHash(hash, hashAlgorithm, padding);
        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) =>
            inner.VerifyHash(hash, signature, hashAlgorithm, padding);
    }

    private sealed class Fixture : IDisposable, IFdoDeviceEnrollmentHandler, IFdoDeviceServerKeygenHandler
    {
        private readonly X509Certificate2 _issuedCertificate;
        private byte[]? _caCrl;

        public Fixture(
            int curveSize = 256,
            FdoKeyExchangeSuite exchange = FdoKeyExchangeSuite.Ecdh256,
            FdoCoseAeadAlgorithm cipher = FdoCoseAeadAlgorithm.A128Gcm)
        {
            Auth = new AuthenticationFixture(curveSize, exchange, cipher);
            EnrollmentKey = ECDsa.Create(
                curveSize == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
            var request = new CertificateRequest(
                "CN=FDO enrollment", EnrollmentKey,
                curveSize == 256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384);
            Request = request.CreateSigningRequest();
            _issuedCertificate = request.Create(
                Auth.RootCertificate, DateTimeOffset.UtcNow.AddMinutes(-2),
                DateTimeOffset.UtcNow.AddHours(1), [1, 2, 3, 5]);
            Certificate = _issuedCertificate.RawData;
            Handler = new RecordingHandler(this);
            CaHandler = new RecordingCaHandler(this);
            OwnerAttributesHandler = new RecordingOwnerAttributesHandler(this);
            DeviceAttributesHandler = new RecordingDeviceAttributesHandler(this);
            ReenrollmentHandler = new RecordingReenrollmentHandler(this);
            ServerKeygenHandler = new RecordingServerKeygenHandler(this);
            Transport = CreateTransport();
            Device = new TestDeviceSettings(true, true, 8192, 4096);
            TrustedManufacturerKey = Auth.Voucher.ManufacturerKey;
            DeviceTrustAnchor = Auth.RootCertificate.RawData;
            Exchange = exchange;
            Cipher = cipher;
        }

        public AuthenticationFixture Auth { get; }
        public byte[] Request { get; set; }
        public byte[] Certificate { get; }
        public ECDsa EnrollmentKey { get; }
        public List<string> Events { get; } = [];
        public RecordingHandler Handler { get; }
        public RecordingCaHandler CaHandler { get; }
        public RecordingOwnerAttributesHandler OwnerAttributesHandler { get; }
        public RecordingDeviceAttributesHandler DeviceAttributesHandler { get; }
        public RecordingReenrollmentHandler ReenrollmentHandler { get; }
        public RecordingServerKeygenHandler ServerKeygenHandler { get; }
        public RecordingTransport Transport { get; set; }
        public TestDeviceSettings Device { get; set; }
        public FdoOwnerSession? Session { get; private set; }
        public FdoDeviceSession? DeviceSession { get; private set; }
        public FdoDeviceInitializeCredential? InitializedCredential { get; set; }
        public FdoTransferredOwnershipVoucher? TransferredVoucher { get; set; }
        public IFdoDeviceInitializeHmacSecret? OpaqueVoucherSecret { get; set; }
        public FdoOwnerReplacementOptions? Replacement { get; set; }
        public IFdoDeviceReplacementHandler? ReplacementHandler { get; set; }
        public bool IncludeRawVoucherSecret { get; set; } = true;
        public ReadOnlyMemory<byte>? DeviceManufacturerHash { get; set; }
        public ReadOnlyMemory<byte> TrustedManufacturerKey { get; set; }
        public ReadOnlyMemory<byte> DeviceTrustAnchor { get; set; }
        public FdoKeyExchangeSuite Exchange { get; set; }
        public FdoCoseAeadAlgorithm Cipher { get; }
        public AsymmetricAlgorithm? OwnerSigningKeyOverride { get; set; }
        public FdoPairedKeyExchangeSuite? OwnerPrimaryExchange { get; set; }
        public FdoPairedKeyExchangeSuite? OwnerAdditionalExchange { get; set; }
        public IReadOnlyList<ReadOnlyMemory<byte>>? OwnerEntriesOverride { get; set; }
        public ReadOnlyMemory<byte> ProvisionedAsymOwnerKey { get; set; }
        public bool OwnerPairedDh { get; set; }
        public bool DevicePairedDh { get; set; }
        public bool OwnerPairedAsym { get; set; }
        public bool DevicePairedAsym { get; set; }
        private FdoPairedKeyExchangeSuite PairedExchange => Exchange switch
        {
            FdoKeyExchangeSuite.Ecdh256 => FdoPairedKeyExchangeSuite.Ecdh256,
            FdoKeyExchangeSuite.Ecdh384 => FdoPairedKeyExchangeSuite.Ecdh384,
            FdoKeyExchangeSuite.DhkexId14 => FdoPairedKeyExchangeSuite.DhkexId14,
            FdoKeyExchangeSuite.DhkexId15 => FdoPairedKeyExchangeSuite.DhkexId15,
            FdoKeyExchangeSuite.Asymkex2048 => FdoPairedKeyExchangeSuite.Asymkex2048,
            FdoKeyExchangeSuite.Asymkex3072 => FdoPairedKeyExchangeSuite.Asymkex3072,
            _ => throw new ArgumentOutOfRangeException(nameof(Exchange)),
        };
        private FdoPairedCipherSuite PairedCipher => Cipher switch
        {
            FdoCoseAeadAlgorithm.A128Gcm => FdoPairedCipherSuite.A128Gcm,
            FdoCoseAeadAlgorithm.A256Gcm => FdoPairedCipherSuite.A256Gcm,
            FdoCoseAeadAlgorithm.AesCcm16_128_128 => FdoPairedCipherSuite.AesCcm16_128_128,
            FdoCoseAeadAlgorithm.AesCcm16_128_256 => FdoPairedCipherSuite.AesCcm16_128_256,
            FdoCoseAeadAlgorithm.AesCcm64_128_128 => FdoPairedCipherSuite.AesCcm64_128_128,
            FdoCoseAeadAlgorithm.AesCcm64_128_256 => FdoPairedCipherSuite.AesCcm64_128_256,
            FdoCoseAeadAlgorithm.AesCtr128HmacSha256 => FdoPairedCipherSuite.AesCtr128HmacSha256,
            FdoCoseAeadAlgorithm.AesCtr256HmacSha384 => FdoPairedCipherSuite.AesCtr256HmacSha384,
            FdoCoseAeadAlgorithm.AesCbc128HmacSha256 => FdoPairedCipherSuite.AesCbc128HmacSha256,
            FdoCoseAeadAlgorithm.AesCbc256HmacSha384 => FdoPairedCipherSuite.AesCbc256HmacSha384,
            _ => throw new ArgumentOutOfRangeException(nameof(Cipher)),
        };
        public bool OwnerBypass { get; set; } = true;
        public bool OwnerRendezvous { get; set; }
        public FdoDeviceRendezvousResult? DeviceRendezvous { get; set; }
        public bool OwnerReuse { get; set; } = true;
        public bool UsePairedProfile { get; set; } = true;
        public bool DeviceUsePairedProfile { get; set; } = true;
        public bool RequestCaCertificates { get; set; }
        public bool ProvideCaCertificates { get; set; }
        public bool RequestCsrAttributes { get; set; }
        public bool ProvideCsrAttributes { get; set; }
        public bool ConflictingDeviceCsr { get; set; }
        public bool RequestReenrollment { get; set; }
        public bool ProvideReenrollmentHandler { get; set; }
        public bool RequestServerKeyGeneration { get; set; }
        public bool ProvideServerKeyGeneration { get; set; }
        public bool MutateCaSnapshots { get; set; }
        public FdoCaCertificates? ValidationCaCertificates { get; private set; }
        public FdoCaCertificates? InstallationCaCertificates { get; private set; }
        public byte[] CaCrl => _caCrl ??= new CertificateRevocationListBuilder().Build(
            Auth.RootCertificate, 1, DateTimeOffset.UtcNow.AddHours(1), HashAlgorithmName.SHA256);
        public ushort OwnerDeviceServiceInfoSize { get; set; } = 4096;
        public FdoDeviceMetadata Metadata { get; set; } =
            new("test-os", "test-arch", "1", "test-device", ":", "test-arch");
        public int ValidationCalls { get; private set; }
        public int InstallCalls { get; private set; }
        public int ServerKeyInstallCalls { get; private set; }
        public bool? ValidatedReenrollment { get; private set; }
        public bool? InstalledReenrollment { get; private set; }
        public bool RejectCertificate { get; set; }
        public bool RejectInstallation { get; set; }
        public bool MutateDeviceSnapshots { get; set; }
        public Action? OnInstallSucceeded { get; set; }
        public Action<ReadOnlyMemory<byte>>? OnServerKeyInstall { get; set; }

        public RecordingTransport CreateTransport() => new(Events);

        public FdoOwnerSession CreateSession()
        {
            Session?.Dispose();
            Session = new FdoOwnerSession(new FdoOwnerSessionOptions
            {
                EncodedVoucherHeaderTag = TransferredVoucher is { } voucher
                    ? voucher.EncodedVoucherHeaderTag : Auth.Voucher.HeaderTag,
                EncodedVoucherHeaderHmac = TransferredVoucher is { } hmacVoucher
                    ? hmacVoucher.EncodedVoucherHeaderHmac : Auth.Voucher.EncodedHeaderHmac,
                EncodedVoucherEntries = OwnerEntriesOverride ?? TransferredVoucher?.EncodedVoucherEntries ??
                    new ReadOnlyMemory<byte>[] { Auth.Voucher.FirstEntry, Auth.Voucher.SecondEntry },
                EncodedDeviceCertificateChain = TransferredVoucher is { } chainVoucher
                    ? chainVoucher.EncodedDeviceCertificateChain : Auth.EncodedChain,
                TrustedManufacturerKey = TrustedManufacturerKey,
                DeviceTrustAnchor = DeviceTrustAnchor,
                DeviceRevocationMode = X509RevocationMode.NoCheck,
                OwnerSigningKey = OwnerSigningKeyOverride ?? Auth.Voucher.FinalOwner,
                EnrollmentHandler = Handler,
                CaCertificatesHandler = ProvideCaCertificates ? CaHandler : null,
                CsrAttributesHandler = ProvideCsrAttributes ? OwnerAttributesHandler : null,
                ReenrollmentHandler = ProvideReenrollmentHandler ? ReenrollmentHandler : null,
                ServerKeygenHandler = ProvideServerKeyGeneration ? ServerKeygenHandler : null,
                KeyExchangeSuite = OwnerPrimaryExchange ?? PairedExchange,
                AdditionalKeyExchangeSuite = OwnerAdditionalExchange,
                UseProvisionalPairedDh = OwnerPairedDh,
                UseProvisionalPairedAsymkex = OwnerPairedAsym,
                CipherSuite = OwnerPrimaryCipher ?? PairedCipher,
                AdditionalCipherSuites = OwnerAdditionalCiphers,
                AllowRendezvousBypass = OwnerBypass,
                AllowRendezvous = OwnerRendezvous,
                AllowCredentialReuse = OwnerReuse,
                Replacement = Replacement,
                UseProvisionalPairedProfile = UsePairedProfile,
                MaxMessageSize = 8192,
                MaxDeviceServiceInfoSize = OwnerDeviceServiceInfoSize,
                UseDelegatedOwnerProof = OwnerDelegated,
                DelegateSigningKey = OwnerDelegateKey,
                DelegateCertificateChain = OwnerDelegateChain,
                DelegateTimeProvider = OwnerDelegateTime ?? (OwnerDelegated ? TimeProvider.System : null),
                DelegateOfflineRevocation = OwnerOfflineRevocation,
            });
            return Session;
        }

        public bool OwnerDelegated { get; set; }
        public AsymmetricAlgorithm? OwnerDelegateKey { get; set; }
        public IReadOnlyList<ReadOnlyMemory<byte>>? OwnerDelegateChain { get; set; }
        public FdoPairedCipherSuite? OwnerPrimaryCipher { get; set; }
        public IReadOnlyList<FdoPairedCipherSuite>? OwnerAdditionalCiphers { get; set; }
        public TimeProvider? OwnerDelegateTime { get; set; }
        public FdoDelegateOfflineRevocationPolicy? OwnerOfflineRevocation { get; set; }
        public bool DeviceDelegated { get; set; }
        public IFdoDeviceDelegateAcceptance? DelegateAcceptance { get; set; }
        public TimeProvider? DeviceDelegateTime { get; set; }

        public RecordingDelegateAcceptance UseDelegate(DelegateChain chain)
        {
            var acceptance = new RecordingDelegateAcceptance(Events);
            OwnerDelegated = DeviceDelegated = true;
            OwnerDelegateKey = chain.LeafKey;
            OwnerDelegateChain = chain.Encoded;
            DelegateAcceptance = acceptance;
            return acceptance;
        }

        public FdoDeviceSessionOptions CreateDeviceOptions(int? rendezvousAddressIndex = null) => new()
        {
            DeviceGuid = InitializedCredential is { } credential
                ? credential.DeviceGuid : Auth.Voucher.Guid.ToArray(),
            EncodedManufacturerKeyHash = DeviceManufacturerHash ??
                (InitializedCredential is { } manufacturerCredential
                    ? manufacturerCredential.EncodedManufacturerKeyHash : Auth.Voucher.ManufacturerHash.Encode()),
            VoucherHmacAlgorithm = InitializedCredential?.VoucherHmacAlgorithm ??
                (Auth.Voucher.HmacAlgorithm == FdoHashAlgorithm.HmacSha256
                    ? FdoDeviceHmacAlgorithm.HmacSha256 : FdoDeviceHmacAlgorithm.HmacSha384),
            VoucherHmacSecret = IncludeRawVoucherSecret
                ? Auth.Voucher.Secret.ToArray() : ReadOnlyMemory<byte>.Empty,
            VoucherHmacSecretHandle = OpaqueVoucherSecret,
            AttestationKey = Auth.DeviceSigningKey,
            CertificateSigningRequest = RequestCsrAttributes && !ConflictingDeviceCsr
                ? default : Request.ToArray(),
            CsrAttributesHandler = RequestCsrAttributes ? DeviceAttributesHandler : null,
            ServerKeygenHandler = RequestServerKeyGeneration ? this : null,
            KeyExchangeSuite = PairedExchange,
            UseProvisionalPairedDh = DevicePairedDh,
            UseProvisionalPairedAsymkex = DevicePairedAsym,
            EncodedAsymkexOwnerPublicKey = ProvisionedAsymOwnerKey,
            CipherSuite = PairedCipher,
            AllowRendezvousBypass = Device.AllowRendezvousBypass,
            RendezvousResult = DeviceRendezvous,
            RendezvousAddressIndex = rendezvousAddressIndex,
            AllowCredentialReuse = Device.AllowCredentialReuse,
            ReplacementHandler = ReplacementHandler,
            UseProvisionalPairedProfile = DeviceUsePairedProfile,
            MaxMessageSize = Device.MaxMessageSize,
            MaxOwnerServiceInfoSize = Device.MaxOwnerServiceInfoSize,
            RequestCaCertificates = RequestCaCertificates,
            RequestReenrollment = RequestReenrollment,
            Metadata = Metadata,
            EnrollmentHandler = this,
            UseDelegatedOwnerProof = DeviceDelegated,
            DelegateAcceptance = DelegateAcceptance,
            DelegateTimeProvider = DeviceDelegateTime ?? (DeviceDelegated ? TimeProvider.System : null),
            DelegateOfflineRevocation = DeviceOfflineRevocation,
            AcceptDelegatedRendezvousRedirect = AcceptDelegatedRedirect,
            RedirectDelegateAcceptance = RedirectAcceptance,
            RedirectDelegateTimeProvider = RedirectTime,
            RedirectDelegateOfflineRevocation = RedirectOfflineRevocation,
        };

        public bool AcceptDelegatedRedirect { get; set; }
        public IFdoDeviceRedirectDelegateAcceptance? RedirectAcceptance { get; set; }
        public TimeProvider? RedirectTime { get; set; }
        public FdoDelegateOfflineRevocationPolicy? DeviceOfflineRevocation { get; set; }
        public FdoDelegateOfflineRevocationPolicy? RedirectOfflineRevocation { get; set; }

        public FdoDeviceSession CreateDeviceSession(FdoDeviceSessionOptions? options = null)
        {
            DeviceSession?.Dispose();
            DeviceSession = new FdoDeviceSession(options ?? CreateDeviceOptions());
            return DeviceSession;
        }

        public Task<FdoDeviceEnrollment> RunAsync() => RunAsync(CreateSession());

        public FdoCaCertificates CreateCaCertificates() => new([Auth.RootCertificate.RawData], [CaCrl]);

        public Task<FdoDeviceEnrollment> RunAsync(CancellationToken cancellationToken) =>
            RunAsync(CreateSession(), cancellationToken);

        public Task<FdoDeviceEnrollment> RunAsync(
            FdoOwnerSession session, CancellationToken cancellationToken = default) =>
            RunAsync(session, CreateDeviceSession(), cancellationToken);

        public Task<FdoDeviceEnrollment> RunAsync(
            FdoOwnerSession session, FdoDeviceSession deviceSession, CancellationToken cancellationToken = default)
        {
            Transport.Owner = session;
            return deviceSession.RunAsync(Transport, cancellationToken).AsTask();
        }

        public ValueTask ValidateCertificateAsync(FdoDeviceEnrollment enrollment, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add("validate");
            ValidationCalls++;
            ValidationCaCertificates = enrollment.CaCertificates;
            ValidatedReenrollment = enrollment.IsReenrollment;
            if (MutateCaSnapshots && enrollment.CaCertificates is FdoCaCertificates ca)
            {
                ClearExposedMemory(ca.Certificates[0]);
                ClearExposedMemory(ca.CertificateRevocationLists[0]);
            }

            using X509Certificate2 parsed = FdoDerEncoding.LoadCertificate(enrollment.Certificate);
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(Auth.RootCertificate);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            if (RejectCertificate || !chain.Build(parsed))
            {
                throw new CryptographicException("The Device certificate policy rejected enrollment.");
            }

            ClearExposedMemory(enrollment.Certificate);
            if (MutateDeviceSnapshots)
            {
                ClearExposedMemory(enrollment.DeviceGuid);
                ClearExposedMemory(enrollment.CertificateSigningRequest);
            }

            return ValueTask.CompletedTask;
        }

        public ValueTask InstallAsync(FdoDeviceEnrollment enrollment, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add("install");
            InstallCalls++;
            InstallationCaCertificates = enrollment.CaCertificates;
            InstalledReenrollment = enrollment.IsReenrollment;
            if (!DeviceSession!.DoneAckAuthenticated)
            {
                throw new InvalidOperationException("Installation started before DoneAck20 authentication.");
            }

            if (MutateDeviceSnapshots)
            {
                ClearExposedMemory(enrollment.DeviceGuid);
                ClearExposedMemory(enrollment.CertificateSigningRequest);
                ClearExposedMemory(enrollment.Certificate);
            }

            if (RejectInstallation)
            {
                throw new InvalidOperationException("The installation did not report success.");
            }

            OnInstallSucceeded?.Invoke();
            return ValueTask.CompletedTask;
        }

        public ValueTask InstallAsync(
            FdoDeviceEnrollment enrollment,
            ReadOnlyMemory<byte> privateKeyPkcs8,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add("install-server-key");
            ServerKeyInstallCalls++;
            if (!DeviceSession!.DoneAckAuthenticated)
            {
                throw new InvalidOperationException("Server-key installation started before DoneAck20 authentication.");
            }

            FdoCsrServerKeygen.ValidateCredential(enrollment.Certificate, privateKeyPkcs8);
            OnServerKeyInstall?.Invoke(privateKeyPkcs8);
            if (RejectInstallation)
            {
                throw new InvalidOperationException("The installation did not report success.");
            }

            return ValueTask.CompletedTask;
        }

        public void Dispose()
        {
            DeviceSession?.Dispose();
            Session?.Dispose();
            _issuedCertificate.Dispose();
            EnrollmentKey.Dispose();
            Auth.Dispose();
        }
    }

    private sealed class RecordingVoucherHmacSecret : IFdoDeviceInitializeHmacSecret, IDisposable
    {
        private readonly byte[] _secret;

        public RecordingVoucherHmacSecret(FdoDeviceHmacAlgorithm algorithm, byte[]? secret = null)
        {
            Algorithm = algorithm;
            _secret = secret is null
                ? RandomNumberGenerator.GetBytes(algorithm == FdoDeviceHmacAlgorithm.HmacSha256 ? 32 : 64)
                : (byte[])secret.Clone();
            KeySizeInBytes = _secret.Length;
        }

        public FdoDeviceHmacAlgorithm Algorithm { get; set; }
        public int KeySizeInBytes { get; set; }
        public List<byte[]> Inputs { get; } = [];
        public bool MutateInput { get; set; }
        public bool CorruptResult { get; set; }
        public bool ShortResult { get; set; }
        public bool ThrowOnCompute { get; set; }
        public Action? AfterCompute { get; set; }
        public bool Disposed { get; private set; }

        public async ValueTask<ReadOnlyMemory<byte>> ComputeAsync(
            ReadOnlyMemory<byte> encodedHeaderContents, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
            Inputs.Add(encodedHeaderContents.ToArray());
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            if (ThrowOnCompute)
            {
                throw new InvalidOperationException("The HMAC handle failed.");
            }

            byte[] result = Algorithm == FdoDeviceHmacAlgorithm.HmacSha256
                ? HMACSHA256.HashData(_secret, encodedHeaderContents.Span)
                : HMACSHA384.HashData(_secret, encodedHeaderContents.Span);
            if (MutateInput)
            {
                ClearExposedMemory(encodedHeaderContents);
            }

            if (CorruptResult)
            {
                result[0] ^= 1;
            }

            AfterCompute?.Invoke();
            return ShortResult ? result.AsMemory(0, result.Length - 1) : result;
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_secret);
            Disposed = true;
        }
    }

    private sealed class InitializationFixture :
        IDisposable,
        IFdoDeviceInitializeHandler,
        IFdoManufacturerInitializeHandler,
        IFdoDeviceInitializeTransport
    {
        private readonly Fixture _fixture;
        private readonly IFdoDeviceInitializeHmacSecret _secret;
        private FdoDeviceInitializeCredential? _stagedCredential;

        public InitializationFixture(Fixture fixture, IFdoDeviceInitializeHmacSecret secret)
        {
            _fixture = fixture;
            _secret = secret;
            Manufacturer = new FdoManufacturerInitializeSession(new FdoManufacturerInitializeOptions
            {
                Handler = this,
                UseVoucherHeaderHmac = true,
            });
            Device = new FdoDeviceInitializeSession(new FdoDeviceInitializeOptions
            {
                AttestationKey = fixture.Auth.DeviceSigningKey,
                Handler = this,
                UseVoucherHeaderHmac = true,
            });
        }

        public FdoManufacturerInitializeVoucher? Voucher { get; private set; }
        public FdoDeviceInitializeCredential? InstalledCredential { get; private set; }
        public FdoManufacturerInitializeSession Manufacturer { get; }
        public FdoDeviceInitializeSession Device { get; }
        public Uri? AuthorizedHttpAddress { get; set; }
        public ReadOnlyMemory<byte>? EncodedRendezvousInfo { get; set; }

        public Task<FdoDeviceInitializeCredential> RunAsync() => Device.RunAsync(this).AsTask();

        public ValueTask<IFdoDeviceInitializeHmacSecret> AuthorizeAndReserveAsync(
            Guid runId, IFdoDeviceInitializeTransport transport, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool authorizedTransport = ReferenceEquals(transport, this) ||
                (AuthorizedHttpAddress is not null && transport is IFdoHttpPeer peer &&
                 peer.BaseAddress == AuthorizedHttpAddress);
            if (!authorizedTransport)
            {
                throw new InvalidOperationException("The manufacturing station is not authorized.");
            }

            return ValueTask.FromResult(_secret);
        }

        public ValueTask StageAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _stagedCredential = credential;
            return ValueTask.CompletedTask;
        }

        public ValueTask InstallAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!ReferenceEquals(credential, _stagedCredential))
            {
                throw new InvalidOperationException("The staged credential does not match.");
            }

            InstalledCredential = credential;
            return ValueTask.CompletedTask;
        }

        public ValueTask<FdoManufacturerInitializeProposal> AuthorizeAndPrepareAsync(
            FdoManufacturerInitializeRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(FdoManufacturerInitializeProposal.Create(
                "test-device", _fixture.Auth.Voucher.Manufacturer,
                new ReadOnlyMemory<byte>[]
                {
                    _fixture.Auth.DeviceCertificate.RawData,
                    _fixture.Auth.RootCertificate.RawData,
                }, EncodedRendezvousInfo));
        }

        public ValueTask PersistVoucherAsync(FdoManufacturerInitializeVoucher voucher, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Voucher = voucher;
            return ValueTask.CompletedTask;
        }

        public async ValueTask<FdoDeviceInitializeResponse> SendAsync(
            ushort protocolVersion,
            FdoDeviceInitializeMessageType messageType,
            ReadOnlyMemory<byte> encodedBody,
            CancellationToken cancellationToken)
        {
            FdoDeviceInitializeResponse response = await Manufacturer.ProcessAsync(
                protocolVersion, messageType, encodedBody, cancellationToken);
            Manufacturer.ConfirmResponseSent();
            return response;
        }

        public void Dispose() => Manufacturer.Dispose();
    }

    private sealed class RecordingServerKeygenHandler(Fixture fixture) : IFdoOwnerServerKeygenHandler
    {
        public int Calls { get; private set; }
        public bool Reject { get; set; }
        public bool Mismatch { get; set; }
        public Action? OnSucceeded { get; set; }
        public FdoEnrollmentRequest? Request { get; private set; }

        public ValueTask<FdoServerKeygenCredential> AuthorizeAndIssueAsync(
            FdoEnrollmentRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("issue-server-key");
            Calls++;
            Request = request;
            if (Reject)
            {
                throw new InvalidOperationException("The server-key request was not authorized.");
            }

            using ECDsa generatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] privateKey = generatedKey.ExportPkcs8PrivateKey();
            try
            {
                byte[] certificate = Mismatch
                    ? fixture.Certificate
                    : IssueCertificate(fixture, generatedKey, "CN=FDO enrollment", null);
                var credential = new FdoServerKeygenCredential(certificate, privateKey);
                OnSucceeded?.Invoke();
                return ValueTask.FromResult(credential);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
    }

    private sealed class RecordingOwnerAttributesHandler(Fixture fixture) : IFdoOwnerCsrAttributesHandler
    {
        public int Calls { get; private set; }
        public bool Reject { get; set; }
        public bool MutateSnapshots { get; set; }
        public Action? OnSucceeded { get; set; }
        public byte[] EncodedAttributes { get; set; } = Convert.FromBase64String(
            "MEEGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiMBYGCSqGSIb3DQEJDjEJ" +
            "BgcrBgEBAQEWBggqhkjOPQQDAw==");
        public FdoCsrAttributesRequest? Request { get; private set; }

        public ValueTask<FdoCsrAttributes> GetCsrAttributesAsync(
            FdoCsrAttributesRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("owner-attributes");
            Calls++;
            Request = request;
            if (MutateSnapshots)
            {
                ClearExposedMemory(request.DeviceGuid);
                ClearExposedMemory(request.DeviceAttestationCertificate);
            }

            if (Reject)
            {
                throw new InvalidOperationException("The Owner rejected attribute discovery.");
            }

            byte[] data = (byte[])EncodedAttributes.Clone();
            var attributes = new FdoCsrAttributes(data);
            if (MutateSnapshots)
            {
                Array.Clear(data);
                ClearExposedMemory(attributes.EncodedValue);
                ClearExposedMemory(attributes.Entries[1].Values[0]);
            }

            OnSucceeded?.Invoke();
            return ValueTask.FromResult(attributes);
        }
    }

    private sealed class RecordingDeviceAttributesHandler(Fixture fixture) : IFdoDeviceCsrAttributesHandler
    {
        public int Calls { get; private set; }
        public bool Reject { get; set; }
        public bool MutateSnapshots { get; set; }
        public bool GenerateRequest { get; set; }
        public Action? OnSucceeded { get; set; }
        public byte[]? RequestOverride { get; set; }
        public FdoDeviceCsrAttributesRequest? Request { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> CreateCertificateSigningRequestAsync(
            FdoDeviceCsrAttributesRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("device-attributes");
            Calls++;
            Request = request;
            if (MutateSnapshots)
            {
                ClearExposedMemory(request.DeviceGuid);
                ClearExposedMemory(request.Attributes.EncodedValue);
                ClearExposedMemory(request.Attributes.Entries[1].Values[0]);
                if (request.CaCertificates is FdoCaCertificates ca)
                {
                    ClearExposedMemory(ca.Certificates[0]);
                    ClearExposedMemory(ca.CertificateRevocationLists[0]);
                }
            }

            if (Reject)
            {
                throw new InvalidOperationException("The Device rejected attribute discovery.");
            }

            if (GenerateRequest)
            {
                CertificateRequest csr = CreateCertificateRequest(fixture.EnrollmentKey, "CN=FDO enrollment", null);
                var writer = new AsnWriter(AsnEncodingRules.DER);
                writer.WriteCharacterString(UniversalTagNumber.UTF8String, "selected after discovery");
                csr.OtherRequestAttributes.Add(new AsnEncodedData("1.2.840.113549.1.9.7", writer.Encode()));
                fixture.Request = csr.CreateSigningRequest();
            }

            OnSucceeded?.Invoke();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                (byte[])(RequestOverride ?? fixture.Request).Clone());
        }
    }

    private sealed class RecordingReenrollmentHandler(Fixture fixture) : IFdoOwnerReenrollmentHandler
    {
        public int LookupCalls { get; private set; }
        public int ApprovalCalls { get; private set; }
        public bool RejectLookup { get; set; }
        public bool RejectChange { get; set; }
        public bool MutateSnapshots { get; set; }
        public Action? OnLookupSucceeded { get; set; }
        public Action? OnApprovalSucceeded { get; set; }
        public byte[]? PriorCertificate { get; set; }
        public byte[]? ReturnedPrior { get; private set; }
        public FdoEnrollmentRequest? LookupRequest { get; private set; }
        public FdoEnrollmentRequest? ApprovalRequest { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> GetPriorCertificateAsync(
            FdoEnrollmentRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("lookup");
            LookupCalls++;
            LookupRequest = request;
            if (MutateSnapshots)
            {
                ClearExposedMemory(request.DeviceGuid);
                ClearExposedMemory(request.DeviceAttestationCertificate);
                ClearExposedMemory(request.CertificateSigningRequest);
            }

            if (RejectLookup)
            {
                throw new InvalidOperationException("The prior credential was not authorized.");
            }

            ReturnedPrior = (byte[])(PriorCertificate ?? fixture.Certificate).Clone();
            OnLookupSucceeded?.Invoke();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(ReturnedPrior);
        }

        public ValueTask ApproveIdentityChangeAsync(
            FdoEnrollmentRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("approve");
            ApprovalCalls++;
            ApprovalRequest = request;
            if (MutateSnapshots)
            {
                ClearReenrollmentSnapshots(request);
                Array.Clear(ReturnedPrior!);
            }

            if (RejectChange)
            {
                throw new InvalidOperationException("The identity change was not authorized.");
            }

            OnApprovalSucceeded?.Invoke();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RecordingCaHandler(Fixture fixture) : IFdoOwnerCaCertificatesHandler
    {
        public int Calls { get; private set; }
        public bool Reject { get; set; }
        public bool MutateSnapshots { get; set; }
        public FdoCaCertificatesRequest? Request { get; private set; }

        public ValueTask<FdoCaCertificates> GetCaCertificatesAsync(
            FdoCaCertificatesRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("ca");
            Calls++;
            Request = request;
            if (MutateSnapshots)
            {
                ClearExposedMemory(request.DeviceGuid);
                ClearExposedMemory(request.DeviceAttestationCertificate);
            }

            if (Reject)
            {
                throw new InvalidOperationException("The Owner rejected CA distribution.");
            }

            return ValueTask.FromResult(fixture.CreateCaCertificates());
        }
    }

    private sealed class RecordingHandler(Fixture fixture) : IFdoOwnerEnrollmentHandler
    {
        public int IssueCalls { get; private set; }
        public int CommitCalls { get; private set; }
        public bool MutateSnapshots { get; set; }
        public bool FailIssue { get; set; }
        public bool FailCommit { get; set; }
        public Action? OnCommitSucceeded { get; set; }
        public byte[]? CertificateOverride { get; set; }
        public FdoEnrollmentRequest? Request { get; private set; }
        public FdoEnrollmentCommit? Committed { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> AuthorizeAndIssueAsync(
            FdoEnrollmentRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("issue");
            IssueCalls++;
            Request = request;
            if (!request.CertificateSigningRequest.Span.SequenceEqual(fixture.Request))
            {
                throw new CryptographicException("The Owner received an unexpected CSR.");
            }

            if (MutateSnapshots)
            {
                ClearExposedMemory(request.DeviceGuid);
                ClearExposedMemory(request.DeviceAttestationCertificate);
                ClearExposedMemory(request.CertificateSigningRequest);
                ClearReenrollmentSnapshots(request);
            }

            if (FailIssue)
            {
                throw new InvalidOperationException("The Owner rejected issuance.");
            }

            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                (byte[])(CertificateOverride ?? fixture.Certificate).Clone());
        }

        public ValueTask CommitAsync(FdoEnrollmentCommit enrollment, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("commit");
            CommitCalls++;
            Committed = enrollment;
            if (FailCommit)
            {
                throw new InvalidOperationException("The durable commit did not report success.");
            }

            OnCommitSucceeded?.Invoke();
            return ValueTask.CompletedTask;
        }
    }

    private sealed record TestDeviceSettings(
        bool AllowRendezvousBypass,
        bool AllowCredentialReuse,
        ushort MaxMessageSize,
        ushort MaxOwnerServiceInfoSize);

    private readonly record struct FdoPairedMessage(ushort Version, ushort Type, ReadOnlyMemory<byte> Body);

    private sealed class ReplacementFixture : IDisposable
    {
        public ReplacementFixture(int curveSize = 256)
        {
            Fixture = new Fixture(
                curveSize,
                curveSize == 256 ? FdoKeyExchangeSuite.Ecdh256 : FdoKeyExchangeSuite.Ecdh384,
                curveSize == 256 ? FdoCoseAeadAlgorithm.A128Gcm : FdoCoseAeadAlgorithm.A256Gcm);
            Owner2 = ECDsa.Create(curveSize == 256
                ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
            SecretBytes = Enumerable.Range(1, curveSize == 256 ? 32 : 64)
                .Select(value => (byte)(value + 32)).ToArray();
            Secret = new RecordingVoucherHmacSecret(curveSize == 256
                ? FdoDeviceHmacAlgorithm.HmacSha256 : FdoDeviceHmacAlgorithm.HmacSha384, SecretBytes);
            Handler = new RecordingReplacementHandler(Fixture, Secret);
            Rendezvous = EncodeLoopbackRendezvousInfo(8042);
            Fixture.Replacement = new FdoOwnerReplacementOptions
            {
                Owner2SigningKey = Owner2,
                EncodedRendezvousInfo = Rendezvous,
                Handler = Handler,
            };
            Fixture.ReplacementHandler = Handler;
            Fixture.OwnerReuse = false;
            Fixture.Device = Fixture.Device with { AllowCredentialReuse = false };
        }

        public Fixture Fixture { get; }
        public ECDsa Owner2 { get; }
        public byte[] SecretBytes { get; }
        public RecordingVoucherHmacSecret Secret { get; }
        public RecordingReplacementHandler Handler { get; }
        public byte[] Rendezvous { get; }

        public void Dispose()
        {
            Fixture.Dispose();
            Secret.Dispose();
            Owner2.Dispose();
            CryptographicOperations.ZeroMemory(SecretBytes);
        }
    }

    private sealed class RecordingReplacementHandler(Fixture fixture, IFdoDeviceInitializeHmacSecret secret) :
        IFdoDeviceReplacementHandler, IFdoOwnerReplacementHandler
    {
        public IFdoDeviceInitializeHmacSecret Secret { get; set; } = secret;
        public int ReserveCalls { get; private set; }
        public int StageCalls { get; private set; }
        public int CommitCalls { get; private set; }
        public int ActivateCalls { get; private set; }
        public bool RejectReserve { get; set; }
        public bool FailStage { get; set; }
        public bool FailCommit { get; set; }
        public bool FailActivate { get; set; }
        public Action? OnStageSucceeded { get; set; }
        public Action? OnCommitSucceeded { get; set; }
        public Action? OnActivateSucceeded { get; set; }
        public bool AckAuthenticatedAtActivation { get; private set; }
        public bool DoneSendStartedAtCommit { get; private set; }
        public FdoDeviceReplacementProposal? Proposal { get; private set; }
        public FdoDeviceReplacementCredential? Staged { get; private set; }
        public FdoOwnerReplacementCommit? Committed { get; private set; }

        public ValueTask<IFdoDeviceInitializeHmacSecret> ReserveSecretAsync(
            FdoDeviceReplacementProposal proposal, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("reserve");
            ReserveCalls++;
            Proposal = proposal;
            if (RejectReserve) throw new InvalidOperationException("Replacement was not authorized.");
            return ValueTask.FromResult(Secret);
        }

        public ValueTask StageAsync(FdoDeviceReplacementCredential credential, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("stage");
            StageCalls++;
            Staged = credential;
            if (FailStage) throw new InvalidOperationException("Staging did not report success.");
            OnStageSucceeded?.Invoke();
            return ValueTask.CompletedTask;
        }

        public ValueTask CommitAsync(FdoOwnerReplacementCommit replacement, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("replacement-commit");
            CommitCalls++;
            Committed = replacement;
            DoneSendStartedAtCommit = fixture.DeviceSession?.DoneSendStarted ?? false;
            if (FailCommit) throw new InvalidOperationException("Replacement commit did not report success.");
            OnCommitSucceeded?.Invoke();
            return ValueTask.CompletedTask;
        }

        public ValueTask ActivateAsync(FdoDeviceReplacementCredential credential, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            fixture.Events.Add("activate");
            ActivateCalls++;
            AckAuthenticatedAtActivation = fixture.DeviceSession?.DoneAckAuthenticated ?? false;
            if (!ReferenceEquals(Staged, credential))
                throw new InvalidOperationException("Activation did not use the staged credential.");
            if (FailActivate) throw new InvalidOperationException("Activation did not report success.");
            OnActivateSucceeded?.Invoke();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class DelegateChain : IDisposable
    {
        private readonly List<ECDsa> _keys = [];

        public DelegateChain(ECDsa issuer, int depth, string[] ekuOids, ECCurve? leafCurve = null)
        {
            var encoded = new ReadOnlyMemory<byte>[depth];
            ECDsa issuerKey = issuer;
            var issuerName = new X500DistinguishedName("CN=FDO Owner");
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var oids = new OidCollection();
            foreach (string oid in ekuOids)
            {
                oids.Add(new Oid(oid));
            }

            for (int i = 0; i < depth; i++)
            {
                bool leaf = i == depth - 1;
                ECDsa key = ECDsa.Create(leaf && leafCurve is ECCurve curve ? curve : ECCurve.NamedCurves.nistP256);
                _keys.Add(key);
                var subject = new X500DistinguishedName(leaf ? "CN=Delegate Leaf" : $"CN=Delegate CA {i}");
                HashAlgorithmName hash = issuerKey.KeySize is 384 or 3072
                    ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
                var request = new CertificateRequest(subject, key, hash);
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(!leaf, false, 0, true));
                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    leaf ? X509KeyUsageFlags.DigitalSignature : X509KeyUsageFlags.KeyCertSign, true));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids, false));
                byte[] serial = RandomNumberGenerator.GetBytes(8);
                serial[0] &= 0x7F;
                using X509Certificate2 certificate = request.Create(
                    issuerName, X509SignatureGenerator.CreateForECDsa(issuerKey),
                    now.AddDays(-1), now.AddDays(1), serial);
                encoded[depth - 1 - i] = certificate.RawData;
                issuerKey = key;
                issuerName = subject;
            }

            Encoded = encoded;
            LeafKey = _keys[^1];
        }

        public IReadOnlyList<ReadOnlyMemory<byte>> Encoded { get; }
        public ECDsa LeafKey { get; }

        public void Dispose()
        {
            foreach (ECDsa key in _keys)
            {
                key.Dispose();
            }
        }
    }

    private sealed class RecordingDelegateAcceptance(List<string> events) : IFdoDeviceDelegateAcceptance
    {
        public bool Result { get; set; } = true;
        public int Calls { get; private set; }
        public FdoDelegateEvidence? Evidence { get; private set; }
        public Func<int>? MessageCount { get; set; }
        public int MessagesAtAccept { get; private set; } = -1;

        public ValueTask<bool> AcceptAsync(FdoDelegateEvidence evidence, CancellationToken cancellationToken)
        {
            events.Add("delegate-accept");
            Calls++;
            Evidence = evidence;
            MessagesAtAccept = MessageCount?.Invoke() ?? -1;
            return ValueTask.FromResult(Result);
        }
    }

    private sealed class RecordingRedirectAcceptance(List<string> events) : IFdoDeviceRedirectDelegateAcceptance
    {
        public bool Result { get; set; } = true;
        public int Calls { get; private set; }
        public FdoRedirectDelegateEvidence? Evidence { get; private set; }
        public Func<int>? MessageCount { get; set; }
        public int MessagesAtAccept { get; private set; } = -1;
        public CancellationTokenSource? CancelOnAccept { get; set; }

        public ValueTask<bool> AcceptAsync(FdoRedirectDelegateEvidence evidence, CancellationToken cancellationToken)
        {
            events.Add("redirect-accept");
            Calls++;
            Evidence = evidence;
            MessagesAtAccept = MessageCount?.Invoke() ?? -1;
            CancelOnAccept?.Cancel();
            return ValueTask.FromResult(Result);
        }
    }

    private sealed class ErrorRecordingTransport(List<string> events)
        : RecordingTransport(events), IFdoDeviceErrorTransport
    {
        public ValueTask SendErrorAsync(
            ushort protocolVersion, ReadOnlyMemory<byte> encodedBody, CancellationToken cancellationToken) =>
            ForwardErrorAsync(protocolVersion, encodedBody, cancellationToken);
    }

    private sealed class OriginRecordingTransport(List<string> events, Uri origin)
        : RecordingTransport(events), IFdoHttpPeer
    {
        public Uri BaseAddress => origin;
    }

    private class RecordingTransport(List<string> events) : IFdoDeviceTransport
    {
        private readonly Dictionary<ushort, int> _counts = [];

        public FdoOwnerSession? Owner { get; set; }
        public List<FdoPairedMessage> Messages { get; } = [];
        public Func<FdoPairedMessage, int, FdoPairedMessage>? Change { get; set; }

        public async ValueTask<FdoOwnerResponse> SendAsync(
            ushort protocolVersion,
            FdoTo2MessageType messageType,
            ReadOnlyMemory<byte> encodedBody,
            CancellationToken cancellationToken)
        {
            FdoOwnerSession owner = Owner ?? throw new InvalidOperationException("The test transport requires an Owner.");
            bool handedOff = false;
            try
            {
                FdoPairedMessage request = Record(
                    new FdoPairedMessage(protocolVersion, (ushort)messageType, encodedBody), cancellationToken);
                FdoOwnerResponse response = await owner.ProcessAsync(
                    request.Version, (FdoTo2MessageType)request.Type, request.Body, cancellationToken);
                FdoPairedMessage received = Record(
                    new FdoPairedMessage(response.ProtocolVersion, (ushort)response.MessageType, response.EncodedBody),
                    cancellationToken);
                var result = new FdoOwnerResponse(received.Version, (FdoTo2MessageType)received.Type, received.Body);
                if (response.MessageType != FdoTo2MessageType.Error)
                {
                    owner.ConfirmResponseSent();
                    handedOff = true;
                }

                return result;
            }
            finally
            {
                if (!handedOff)
                {
                    owner.Dispose();
                }
            }
        }

        public FdoOwnerResponse? ErrorReply { get; private set; }

        public async ValueTask ForwardErrorAsync(
            ushort protocolVersion, ReadOnlyMemory<byte> encodedBody, CancellationToken cancellationToken)
        {
            FdoOwnerSession owner = Owner ?? throw new InvalidOperationException("The test transport requires an Owner.");
            try
            {
                FdoPairedMessage request = Record(
                    new FdoPairedMessage(protocolVersion, (ushort)FdoTo2MessageType.Error, encodedBody),
                    cancellationToken);
                ErrorReply = await owner.ProcessAsync(
                    request.Version, (FdoTo2MessageType)request.Type, request.Body, cancellationToken);
            }
            finally
            {
                owner.Dispose();
            }
        }

        private FdoPairedMessage Record(FdoPairedMessage message, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            message = message with { Body = message.Body.ToArray() };
            Messages.Add(message);
            events.Add("wire:" + message.Type);
            _counts.TryGetValue(message.Type, out int count);
            _counts[message.Type] = ++count;
            return Change?.Invoke(message, count) ?? message;
        }
    }
}
