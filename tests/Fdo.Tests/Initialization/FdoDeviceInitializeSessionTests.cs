// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Enrollment;
using Fdo.Initialization;
using Fdo.Ownership;
using Fdo.Serialization;
using Fdo.Tests.Recovery;
using Fdo.Tests.Transport;
using Fdo.Transport.Http;

namespace Fdo.Tests.Initialization;

[UnsupportedOSPlatform("browser")]
public sealed class FdoDeviceInitializeSessionTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InitializesOverHttpWithHostAuthorizationAndSeparateHandoff(bool hasManufacturingInfo)
    {
        byte[] encodedInfo = Convert.FromHexString("6673657269616C");
        ReadOnlyMemory<byte>? manufacturingInfo = null;
        if (hasManufacturingInfo)
        {
            manufacturingInfo = encodedInfo;
        }

        using var fixture = new Fixture(manufacturingInfo: manufacturingInfo);
        using var listener = new LoopbackHttpServer();
        Uri address = new(listener.Address, "manufacturing/");
        fixture.AuthorizedHttpAddress = address;
        using var binding = FdoHttpServerSession.ForManufacturer(fixture.Manufacturer, 8192, "/manufacturing");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<IReadOnlyList<RecordedRequest>> serving = listener.ServeSessionAsync(binding, timeout.Token);

        FdoDeviceInitializeCredential credential = await FdoHttp.RunDeviceInitializeAsync(
            fixture.Device, address, 8192, timeout.Token);
        IReadOnlyList<RecordedRequest> requests = await serving;

        await Assert.That(requests.Count).IsEqualTo(2);
        await Assert.That(requests[0].Uri!.AbsolutePath).IsEqualTo("/manufacturing/fdo/200/msg/10");
        await Assert.That(requests[1].Uri!.AbsolutePath).IsEqualTo("/manufacturing/fdo/200/msg/12");
        await Assert.That(requests[0].Authorization).IsNull();
        await Assert.That(requests[1].Authorization!.StartsWith("Bearer ", StringComparison.Ordinal)).IsTrue();
        await Assert.That(fixture.Events.IndexOf("device-authorize") < fixture.Events.IndexOf("stage")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("persist") < fixture.Events.IndexOf("install")).IsTrue();
        await Assert.That(fixture.HostVoucher).IsNotNull();
        await Assert.That(fixture.HostInstalled == credential).IsTrue();
        ReadOnlyMemory<byte>? receivedInfo = fixture.ManufacturerRequest!.EncodedDeviceMfgInfo;
        await Assert.That(receivedInfo.HasValue).IsEqualTo(hasManufacturingInfo);
        if (hasManufacturingInfo)
        {
            await Assert.That(receivedInfo.GetValueOrDefault().Span.SequenceEqual(encodedInfo)).IsTrue();
        }

        await Assert.That(fixture.Manufacturer.DoneHandoffConfirmed).IsTrue();
        await Assert.That(fixture.Device.DoneReceived).IsTrue();
        await Assert.That(binding.IsComplete).IsTrue();
    }

    [Test]
    public async Task LostHttpDiDoneLeavesTheVoucherAndStagedCredentialForReconciliation()
    {
        using var fixture = new Fixture();
        using var listener = new LoopbackHttpServer();
        fixture.AuthorizedHttpAddress = listener.Address;
        using var binding = FdoHttpServerSession.ForManufacturer(fixture.Manufacturer, 8192);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<IReadOnlyList<RecordedRequest>> serving = listener.ServeSessionAsync(binding, timeout.Token, 12);

        await CatchAsync<Fdo.Transport.FdoTransportException>(() =>
            FdoHttp.RunDeviceInitializeAsync(fixture.Device, listener.Address, 8192, timeout.Token).AsTask());
        IReadOnlyList<RecordedRequest> requests = await serving;

        await Assert.That(requests.Count).IsEqualTo(2);
        await Assert.That(listener.HasPendingConnection).IsFalse();
        await Assert.That(fixture.Manufacturer.PersistedVoucher).IsNotNull();
        await Assert.That(fixture.Manufacturer.DoneProduced).IsTrue();
        await Assert.That(fixture.Manufacturer.DoneHandoffConfirmed).IsFalse();
        await Assert.That(fixture.Device.CredentialStaged).IsTrue();
        await Assert.That(fixture.Device.DoneReceived).IsFalse();
        await Assert.That(fixture.Device.InstallationStarted).IsFalse();
        await Assert.That(fixture.HostInstalled).IsNull();
    }

    [Test]
    [Arguments(256, 256)]
    [Arguments(256, 384)]
    [Arguments(384, 256)]
    [Arguments(384, 384)]
    public async Task PersistsMatchingVoucherBeforeDoneAndInstallsCredentialAfterward(
        int deviceCurve, int manufacturerCurve)
    {
        using var fixture = new Fixture(deviceCurve, manufacturerCurve);
        FdoDeviceInitializeCredential credential = await fixture.RunAsync();
        FdoManufacturerInitializeVoucher voucher = fixture.Manufacturer.PersistedVoucher!;
        var codec = new FdoCborCodec();
        ReadOnlyMemory<byte> header = codec.ReadByteStringPayload(voucher.EncodedVoucherHeaderTag);
        FdoHashValue hmac = FdoHashValue.Decode(voucher.EncodedVoucherHeaderHmac);
        FdoHashAlgorithm expectedHmac = fixture.Algorithm == FdoDeviceHmacAlgorithm.HmacSha256
            ? FdoHashAlgorithm.HmacSha256 : FdoHashAlgorithm.HmacSha384;
        FdoHashAlgorithm expectedDigest = fixture.Algorithm == FdoDeviceHmacAlgorithm.HmacSha256
            ? FdoHashAlgorithm.Sha256 : FdoHashAlgorithm.Sha384;
        ReadOnlyMemory<byte> manufacturerKey = new FdoPublicKeyCodec().Encode(fixture.ManufacturerKey);

        await Assert.That(fixture.Events.IndexOf("device-authorize") < fixture.Events.IndexOf("wire:10")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("manufacturer-authorize") < fixture.Events.IndexOf("wire:11")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("stage") < fixture.Events.IndexOf("hmac")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("hmac") < fixture.Events.IndexOf("wire:12")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("persist") < fixture.Events.IndexOf("wire:13")).IsTrue();
        await Assert.That(fixture.Events.IndexOf("wire:13") < fixture.Events.IndexOf("install")).IsTrue();
        await Assert.That(fixture.Device.CredentialStaged).IsTrue();
        await Assert.That(fixture.Device.SetHmacSendStarted).IsTrue();
        await Assert.That(fixture.Device.DoneReceived).IsTrue();
        await Assert.That(fixture.Device.InstallationStarted).IsTrue();
        await Assert.That(fixture.Device.InstalledCredential == credential).IsTrue();
        await Assert.That(fixture.Manufacturer.DoneProduced).IsTrue();
        await Assert.That(fixture.Manufacturer.DoneHandoffConfirmed).IsTrue();
        await Assert.That(credential.Active).IsTrue();
        await Assert.That(credential.ProtocolVersion).IsEqualTo((ushort)200);
        await Assert.That(credential.DeviceInfo).IsEqualTo("test-device");
        await Assert.That(credential.DeviceGuid.Span.SequenceEqual(voucher.DeviceGuid.Span)).IsTrue();
        await Assert.That(credential.EncodedVoucherHeaderTag.Span
            .SequenceEqual(voucher.EncodedVoucherHeaderTag.Span)).IsTrue();
        await Assert.That(ReferenceEquals(credential.VoucherHmacSecret, fixture)).IsTrue();
        await Assert.That(ReferenceEquals(fixture.StagedCredential, credential)).IsTrue();
        await Assert.That(fixture.LastHmacInput!.AsSpan().SequenceEqual(header.Span)).IsTrue();
        await Assert.That(hmac.MatchesHmac(expectedHmac, fixture.Secret, header.Span)).IsTrue();
        await Assert.That(FdoHashValue.Decode(credential.EncodedManufacturerKeyHash)
            .MatchesDigest(expectedDigest, manufacturerKey.Span)).IsTrue();

        var reader = new CborReader(voucher.EncodedVoucher, CborConformanceMode.Canonical);
        await Assert.That(reader.ReadStartArray()).IsEqualTo(5);
        await Assert.That(reader.ReadUInt64()).IsEqualTo(200UL);
        await Assert.That(reader.ReadEncodedValue().Span.SequenceEqual(voucher.EncodedVoucherHeaderTag.Span)).IsTrue();
        await Assert.That(reader.ReadEncodedValue().Span.SequenceEqual(voucher.EncodedVoucherHeaderHmac.Span)).IsTrue();
        await Assert.That(reader.ReadEncodedValue().Span.SequenceEqual(voucher.EncodedDeviceCertificateChain.Span)).IsTrue();
        await Assert.That(reader.ReadStartArray()).IsEqualTo(0);
        reader.ReadEndArray();
        reader.ReadEndArray();
        await Assert.That(reader.BytesRemaining).IsEqualTo(0);

        using var verifier = new FdoOwnershipVoucherChainVerifier(
            voucher.EncodedVoucherHeaderTag, voucher.EncodedVoucherHeaderHmac, 0);
        verifier.CheckDeviceCertificateChain(voucher.EncodedDeviceCertificateChain);
        verifier.CheckDeviceCredentials(
            credential.DeviceGuid.Span, FdoHashValue.Decode(credential.EncodedManufacturerKeyHash),
            expectedHmac, fixture.Secret);
        verifier.CompleteDeviceChecks(manufacturerKey);
    }

    [Test]
    [Arguments(256, 2048, false)]
    [Arguments(256, 2048, true)]
    [Arguments(256, 3072, false)]
    [Arguments(384, 3072, false)]
    public async Task InitializesAndTransfersAnRsaVoucher(
        int deviceCurve, int rsaSize, bool restricted)
    {
        using var fixture = new Fixture(deviceCurve);
        using RSA manufacturer = RSA.Create(rsaSize);
        using RSA owner = RSA.Create(rsaSize);
        fixture.RsaManufacturerKey = manufacturer;
        fixture.RestrictedRsa = restricted;

        FdoDeviceInitializeCredential credential = await fixture.RunAsync();
        FdoManufacturerInitializeVoucher voucher = fixture.Manufacturer.PersistedVoucher!;
        var keys = new FdoPublicKeyCodec();
        ReadOnlyMemory<byte> manufacturerKey = keys.EncodeRsa(manufacturer, restricted);
        ReadOnlyMemory<byte> ownerKey = keys.EncodeRsa(owner, restricted);
        FdoHashAlgorithm expectedDigest = deviceCurve == 384
            ? FdoHashAlgorithm.Sha384 : FdoHashAlgorithm.Sha256;
        FdoHashAlgorithm expectedHmac = deviceCurve == 384
            ? FdoHashAlgorithm.HmacSha384 : FdoHashAlgorithm.HmacSha256;
        FdoTransferredOwnershipVoucher transferred = FdoOwnershipVoucherTransfer.ExtendRsa(
            voucher.EncodedVoucher, manufacturer, owner);
        using var verifier = new FdoOwnershipVoucherChainVerifier(
            transferred.EncodedVoucherHeaderTag, transferred.EncodedVoucherHeaderHmac, 1);
        verifier.CheckDeviceCredentials(
            credential.DeviceGuid.Span, FdoHashValue.Decode(credential.EncodedManufacturerKeyHash),
            expectedHmac, fixture.Secret);
        verifier.AppendEntry(0, transferred.EncodedVoucherEntries[0]);
        verifier.CompleteDeviceChecks(ownerKey);

        await Assert.That(credential.Active).IsTrue();
        await Assert.That(FdoHashValue.Decode(credential.EncodedManufacturerKeyHash)
            .MatchesDigest(expectedDigest, manufacturerKey.Span)).IsTrue();
        await Assert.That(FdoHashValue.Decode(voucher.EncodedVoucherHeaderHmac).Algorithm).IsEqualTo(expectedHmac);
    }

    [Test]
    public async Task RejectsRsaTransferWithAnIncorrectSignerOrChangedSize()
    {
        using var fixture = new Fixture();
        using RSA manufacturer = RSA.Create(2048);
        using RSA wrongSigner = RSA.Create(2048);
        using RSA largerOwner = RSA.Create(3072);
        fixture.RsaManufacturerKey = manufacturer;
        await fixture.RunAsync();
        ReadOnlyMemory<byte> voucher = fixture.Manufacturer.PersistedVoucher!.EncodedVoucher;

        await Assert.That(Throws<CryptographicException>(() =>
            FdoOwnershipVoucherTransfer.ExtendRsa(voucher, wrongSigner, manufacturer))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            FdoOwnershipVoucherTransfer.ExtendRsa(voucher, manufacturer, largerOwner))).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task BothHostsAuthorizeBeforeTheirFirstInitializationAction(bool rejectManufacturer)
    {
        using var fixture = new Fixture(manufacturingInfo: Convert.FromHexString("6673657269616C"));
        fixture.RejectDeviceAuthorization = !rejectManufacturer;
        fixture.RejectManufacturerAuthorization = rejectManufacturer;

        await CatchAsync<InvalidOperationException>(() => fixture.RunAsync());

        await Assert.That(fixture.Device.StagingStarted).IsFalse();
        await Assert.That(fixture.Device.ReservationStarted).IsTrue();
        await Assert.That(fixture.Device.ReservationConfirmed).IsEqualTo(rejectManufacturer);
        await Assert.That(fixture.Device.SetHmacSendStarted).IsFalse();
        await Assert.That(fixture.Manufacturer.VoucherPersistenceStarted).IsFalse();
        await Assert.That(fixture.HostInstalled).IsNull();
        await Assert.That(fixture.Events.Contains("wire:10")).IsEqualTo(rejectManufacturer);
        if (rejectManufacturer)
        {
            ReadOnlyMemory<byte>? received = fixture.ManufacturerRequest!.EncodedDeviceMfgInfo;
            await Assert.That(received.HasValue).IsTrue();
            await Assert.That(received.GetValueOrDefault().Span
                .SequenceEqual(Convert.FromHexString("6673657269616C"))).IsTrue();
            await Assert.That(fixture.ProposalCount).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("stage")]
    [Arguments("persist")]
    [Arguments("install")]
    public async Task ThrowingPersistenceCallbacksLeaveObservableUnknownOutcomes(string failure)
    {
        using var fixture = new Fixture();
        fixture.ThrowAfterStage = failure == "stage";
        fixture.ThrowAfterPersist = failure == "persist";
        fixture.ThrowAfterInstall = failure == "install";

        await CatchAsync<InvalidOperationException>(() => fixture.RunAsync());

        await Assert.That(fixture.StagedCredential).IsNotNull();
        await Assert.That(fixture.Device.StagingStarted).IsTrue();
        await Assert.That(fixture.Device.CredentialStaged).IsEqualTo(failure != "stage");
        await Assert.That(fixture.LastHmacInput is not null).IsEqualTo(failure != "stage");
        await Assert.That(fixture.Device.SetHmacSendStarted).IsEqualTo(failure != "stage");
        await Assert.That(fixture.Manufacturer.VoucherPersistenceStarted).IsEqualTo(failure != "stage");
        await Assert.That(fixture.HostVoucher is not null).IsEqualTo(failure != "stage");
        await Assert.That(fixture.Manufacturer.PersistedVoucher is not null).IsEqualTo(failure == "install");
        await Assert.That(fixture.Manufacturer.DoneProduced).IsEqualTo(failure == "install");
        await Assert.That(fixture.Device.DoneReceived).IsEqualTo(failure == "install");
        await Assert.That(fixture.Device.InstallationStarted).IsEqualTo(failure == "install");
        await Assert.That(fixture.HostInstalled is not null).IsEqualTo(failure == "install");
        await Assert.That(fixture.Device.InstalledCredential).IsNull();
    }

    [Test]
    public async Task LostDoneRetainsBothSidesForReconciliationWithoutRegenerating()
    {
        using var fixture = new Fixture();
        fixture.DropDone = true;

        await CatchAsync<IOException>(() => fixture.RunAsync());

        await Assert.That(fixture.Device.CredentialStaged).IsTrue();
        await Assert.That(fixture.Device.SetHmacSendStarted).IsTrue();
        await Assert.That(fixture.Device.DoneReceived).IsFalse();
        await Assert.That(fixture.Device.InstallationStarted).IsFalse();
        await Assert.That(fixture.Manufacturer.PersistedVoucher).IsNotNull();
        await Assert.That(fixture.Manufacturer.DoneProduced).IsTrue();
        await Assert.That(fixture.Manufacturer.DoneHandoffConfirmed).IsFalse();
        await Assert.That(fixture.HostInstalled).IsNull();

        await CatchAsync<InvalidOperationException>(() => fixture.RunAsync());
        FdoDeviceInitializeSession another = fixture.CreateDevice();
        await CatchAsync<InvalidOperationException>(() => another.RunAsync(fixture).AsTask());
        using FdoManufacturerInitializeSession anotherManufacturer = fixture.CreateManufacturer();
        ReadOnlyMemory<byte> appStart = new FdoDeviceInitializeCodec().EncodeAppStart(
            new FdoDeviceInitializeCodec.AppStart(new byte[] { 4 }, Array.Empty<string>(), null));
        await CatchAsync<InvalidOperationException>(() => anotherManufacturer.ProcessAsync(
            200, FdoDeviceInitializeMessageType.AppStart, appStart).AsTask());
        await Assert.That(fixture.ProposalCount).IsEqualTo(1);
        await Assert.That(ReferenceEquals(fixture.HostVoucher, fixture.Manufacturer.PersistedVoucher)).IsTrue();
    }

    [Test]
    public async Task ReopensBothDiJournalsAndStartsFreshOnlyAfterReconciliation()
    {
        using var deviceJournal = new DurableRoleJournal();
        using var stationJournal = new DurableRoleJournal();
        using ECDsa deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa stationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        DurableRoleJournal.Writer interruptedDevice = deviceJournal.FenceAndOpen();
        DurableRoleJournal.Writer interruptedStation = stationJournal.FenceAndOpen();
        Guid previousDeviceRun;
        Guid previousStationRun;
        using (var interrupted = new Fixture(borrowedKeys: (deviceKey, stationKey))
        {
            DropDone = true,
            DeviceEffect = RecordWithVersion(interruptedDevice, 0),
            StationEffect = RecordWithVersion(interruptedStation, 0),
        })
        {
            previousDeviceRun = interrupted.Device.RunId;
            previousStationRun = interrupted.Manufacturer.RunId;
            await CatchAsync<IOException>(() => interrupted.RunAsync());
        }

        DurableRoleJournal.Writer recoveredDevice = deviceJournal.FenceAndOpen();
        DurableRoleJournal.Writer recoveredStation = stationJournal.FenceAndOpen();
        var oldDevice = deviceJournal.ReadEffects();
        var oldStation = stationJournal.ReadEffects();
        await Assert.That(oldDevice.Length).IsEqualTo(2);
        await Assert.That(oldDevice[0].Operation).IsEqualTo("reserve");
        await Assert.That(oldDevice[1].Operation).IsEqualTo("stage");
        await Assert.That(oldStation.Length).IsEqualTo(1);
        await Assert.That(oldStation[0].Operation).IsEqualTo("voucher");
        await Assert.That(oldStation[0].Input).IsEqualTo(oldDevice[1].Input);
        await Assert.That(Throws<InvalidOperationException>(() =>
            interruptedDevice.Record(previousDeviceRun, "install", oldDevice[1].Input, 2))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            interruptedStation.Record(previousStationRun, "voucher", oldStation[0].Input, 1))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            recoveredDevice.Record(previousDeviceRun, "install", oldDevice[1].Input, 1))).IsTrue();
        await Assert.That(deviceJournal.ReadEffects().Length).IsEqualTo(2);

        // The host quarantines the unused staged credential and matching voucher;
        // it does not manufacture evidence that DI.Done reached the Device.
        recoveredDevice.Record(previousDeviceRun, "quarantine", oldDevice[1].Input, 2);
        recoveredStation.Record(previousStationRun, "quarantine", oldStation[0].Input, 1);
        using var fresh = new Fixture(borrowedKeys: (deviceKey, stationKey))
        {
            DeviceEffect = RecordWithVersion(recoveredDevice, 3),
            StationEffect = RecordWithVersion(recoveredStation, 2),
        };
        await fresh.RunAsync();

        var newDevice = deviceJournal.ReadEffects();
        var newStation = stationJournal.ReadEffects();
        await Assert.That(fresh.Device.RunId != previousDeviceRun).IsTrue();
        await Assert.That(fresh.Manufacturer.RunId != previousStationRun).IsTrue();
        await Assert.That(newDevice.Length).IsEqualTo(6);
        await Assert.That(newStation.Length).IsEqualTo(3);
        await Assert.That(newDevice[^1].RunId).IsEqualTo(fresh.Device.RunId);
        await Assert.That(newDevice[^1].Operation).IsEqualTo("install");
        await Assert.That(newDevice[^1].Input).IsEqualTo(newStation[^1].Input);
        await Assert.That(newDevice[^1].Input != oldDevice[1].Input).IsTrue();
    }

    private static Action<Guid, string, ReadOnlyMemory<byte>> RecordWithVersion(
        DurableRoleJournal.Writer writer, int version) =>
        (runId, operation, input) =>
        {
            writer.Record(runId, operation, Convert.ToHexString(SHA256.HashData(input.Span)), version);
            version++;
        };

    [Test]
    [Arguments("stage")]
    [Arguments("persist")]
    public async Task CancellationAfterDurableWorkDoesNotAdvanceThePeer(string cancelAt)
    {
        using var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        fixture.CancelAfterStage = cancelAt == "stage" ? cancellation : null;
        fixture.CancelAfterPersist = cancelAt == "persist" ? cancellation : null;

        await CatchAsync<OperationCanceledException>(() => fixture.RunAsync(cancellation.Token));

        await Assert.That(fixture.Device.CredentialStaged).IsTrue();
        await Assert.That(fixture.Device.SetHmacSendStarted).IsEqualTo(cancelAt == "persist");
        await Assert.That(fixture.Manufacturer.PersistedVoucher is not null).IsEqualTo(cancelAt == "persist");
        await Assert.That(fixture.Manufacturer.DoneProduced).IsFalse();
        await Assert.That(fixture.Device.DoneReceived).IsFalse();
        await Assert.That(fixture.HostInstalled).IsNull();
    }

    [Test]
    [Arguments("missing")]
    [Arguments("owner-only")]
    [Arguments("duplicate")]
    [Arguments("not-text")]
    public async Task RequiresAnUnambiguousDeviceApplicableLocalDnsEntry(string scenario)
    {
        using var fixture = new Fixture();
        byte[] rendezvous = scenario switch
        {
            "missing" => Rendezvous((5, Text("other.example"))),
            "owner-only" => Rendezvous((1, new byte[] { 0xF6 }), (5, Text("rvserver.local"))),
            "duplicate" => Rendezvous((5, Text("rvserver.local")), (5, Text("other.example"))),
            _ => Rendezvous((5, new byte[] { 0x01 })),
        };
        fixture.RewriteSetCredentials = body => ReplaceHeaderField(body, 2, rendezvous);

        await CatchAsync<CborContentException>(() => fixture.RunAsync());

        await Assert.That(fixture.Device.StagingStarted).IsFalse();
        await Assert.That(fixture.Device.SetHmacSendStarted).IsFalse();
        await Assert.That(fixture.Manufacturer.VoucherPersistenceStarted).IsFalse();
        await Assert.That(fixture.HostInstalled).IsNull();
        await Assert.That(Throws<CborContentException>(() => FdoManufacturerInitializeProposal.Create(
            "device", fixture.ManufacturerKey, fixture.Certificates, rendezvous))).IsTrue();
    }

    [Test]
    [Arguments("version")]
    [Arguments("guid")]
    [Arguments("manufacturer-key")]
    [Arguments("chain-hmac")]
    public async Task RejectsMalformedVoucherHeaderBeforeStaging(string scenario)
    {
        using var fixture = new Fixture();
        int index = scenario switch
        {
            "version" => 0,
            "guid" => 1,
            "manufacturer-key" => 4,
            _ => 5,
        };
        byte[] replacement = scenario switch
        {
            "version" => Convert.FromHexString("1864"),
            "guid" => EncodeBytes(new byte[15]),
            "manufacturer-key" => new byte[] { 0x80 },
            _ => new FdoHashValue(FdoHashAlgorithm.HmacSha256, new byte[32]).Encode().ToArray(),
        };
        fixture.RewriteSetCredentials = body => ReplaceHeaderField(body, index, replacement);

        await CatchAsync<CborContentException>(() => fixture.RunAsync());

        await Assert.That(fixture.Device.StagingStarted).IsFalse();
        await Assert.That(fixture.Device.SetHmacSendStarted).IsFalse();
        await Assert.That(fixture.Manufacturer.VoucherPersistenceStarted).IsFalse();
    }

    [Test]
    [Arguments("declared-size")]
    [Arguments("wrong-algorithm")]
    [Arguments("short-output")]
    public async Task RejectsInvalidOpaqueSecretMetadataAndHmacOutput(string scenario)
    {
        using var fixture = new Fixture();
        fixture.OverrideKeySize = scenario == "declared-size" ? 31 : null;
        fixture.OverrideAlgorithm = scenario == "wrong-algorithm" ? FdoDeviceHmacAlgorithm.HmacSha384 : null;
        fixture.ShortHmacOutput = scenario == "short-output";
        if (scenario == "wrong-algorithm")
        {
            fixture.OverrideKeySize = 64;
        }

        if (scenario == "wrong-algorithm")
        {
            await CatchAsync<CryptographicException>(() => fixture.RunAsync());
        }
        else
        {
            await CatchAsync<ArgumentException>(() => fixture.RunAsync());
        }

        await Assert.That(fixture.Device.StagingStarted).IsEqualTo(scenario == "short-output");
        await Assert.That(fixture.Device.CredentialStaged).IsEqualTo(scenario == "short-output");
        await Assert.That(fixture.Device.SetHmacSendStarted).IsFalse();
        await Assert.That(fixture.Manufacturer.VoucherPersistenceStarted).IsFalse();
        await Assert.That(fixture.Events.Contains("wire:10")).IsEqualTo(scenario != "declared-size");
    }

    [Test]
    [Arguments("algorithm")]
    [Arguments("size")]
    public async Task RejectsOpaqueSecretMetadataChangedDuringStaging(string field)
    {
        using var fixture = new Fixture();
        fixture.AfterStage = () =>
        {
            if (field == "algorithm")
            {
                fixture.OverrideAlgorithm = FdoDeviceHmacAlgorithm.HmacSha384;
            }
            else
            {
                fixture.OverrideKeySize = 31;
            }
        };

        if (field == "algorithm")
        {
            await CatchAsync<CryptographicException>(() => fixture.RunAsync());
        }
        else
        {
            await CatchAsync<ArgumentException>(() => fixture.RunAsync());
        }

        await Assert.That(fixture.Device.CredentialStaged).IsTrue();
        await Assert.That(fixture.Events.Contains("hmac")).IsFalse();
        await Assert.That(fixture.Device.SetHmacSendStarted).IsFalse();
        await Assert.That(fixture.Manufacturer.VoucherPersistenceStarted).IsFalse();
        await Assert.That(fixture.Device.InstallationStarted).IsFalse();
    }

    [Test]
    public async Task ManufacturerRejectsHmacAlgorithmMismatchBeforeVoucherPersistence()
    {
        using var fixture = new Fixture();
        fixture.RewriteSetHmac = _ => new FdoDeviceInitializeCodec().EncodeSetHmac(
            new FdoHashValue(FdoHashAlgorithm.HmacSha384, new byte[48]));

        await CatchAsync<CryptographicException>(() => fixture.RunAsync());

        await Assert.That(fixture.Device.CredentialStaged).IsTrue();
        await Assert.That(fixture.Device.SetHmacSendStarted).IsTrue();
        await Assert.That(fixture.Manufacturer.VoucherPersistenceStarted).IsFalse();
        await Assert.That(fixture.Device.InstallationStarted).IsFalse();
    }

    [Test]
    [Arguments("bad-body")]
    [Arguments("wrong-type")]
    [Arguments("wrong-version")]
    public async Task DeviceDoesNotInstallAfterAnInvalidDone(string scenario)
    {
        using var fixture = new Fixture();
        fixture.RewriteDone = response => scenario switch
        {
            "bad-body" => new FdoDeviceInitializeResponse(200, FdoDeviceInitializeMessageType.Done, new byte[] { 0x81, 0xF6 }),
            "wrong-type" => new FdoDeviceInitializeResponse(200, FdoDeviceInitializeMessageType.SetCredentials, response.EncodedBody),
            _ => new FdoDeviceInitializeResponse(100, FdoDeviceInitializeMessageType.Done, response.EncodedBody),
        };

        await CatchAsync<CborContentException>(() => fixture.RunAsync());

        await Assert.That(fixture.Manufacturer.PersistedVoucher).IsNotNull();
        await Assert.That(fixture.Manufacturer.DoneHandoffConfirmed).IsTrue();
        await Assert.That(fixture.Device.CredentialStaged).IsTrue();
        await Assert.That(fixture.Device.DoneReceived).IsFalse();
        await Assert.That(fixture.Device.InstallationStarted).IsFalse();
        await Assert.That(fixture.HostInstalled).IsNull();
    }

    [Test]
    [Arguments("missing-version")]
    [Arguments("vendor")]
    [Arguments("wrong-type")]
    [Arguments("wrong-version")]
    public async Task RejectsUnexpectedInitialResponseBeforeStaging(string scenario)
    {
        using var fixture = new Fixture();
        fixture.RewriteCredentialsResponse = response =>
        {
            if (scenario == "wrong-type")
            {
                return new FdoDeviceInitializeResponse(200, FdoDeviceInitializeMessageType.Done, response.EncodedBody);
            }

            if (scenario == "wrong-version")
            {
                return new FdoDeviceInitializeResponse(100, response.MessageType, response.EncodedBody);
            }

            var codec = new FdoDeviceInitializeCodec();
            FdoDeviceInitializeCodec.SetCredentials message = codec.DecodeSetCredentials(response.EncodedBody);
            byte[] flags = scenario == "missing-version" ? new byte[] { 1 } : new byte[] { 4 };
            string[] vendors = scenario == "vendor" ? new[] { "com.example.feature" } : Array.Empty<string>();
            ReadOnlyMemory<byte> body = codec.EncodeSetCredentials(
                new FdoDeviceInitializeCodec.SetCredentials(flags, vendors, message.EncodedHeaderTag));
            return new FdoDeviceInitializeResponse(200, response.MessageType, body);
        };

        await CatchAsync<CborContentException>(() => fixture.RunAsync());

        await Assert.That(fixture.Device.ReservationConfirmed).IsTrue();
        await Assert.That(fixture.Device.StagingStarted).IsFalse();
        await Assert.That(fixture.Device.SetHmacSendStarted).IsFalse();
        await Assert.That(fixture.Manufacturer.VoucherPersistenceStarted).IsFalse();
    }

    [Test]
    public async Task DeviceMessageLimitIncludesTheExactEncodedResponse()
    {
        using var atLimit = new Fixture();
        ushort size = SetCredentialsSize(atLimit);
        FdoDeviceInitializeSession device = atLimit.CreateDevice(size);
        FdoDeviceInitializeCredential credential = await device.RunAsync(atLimit);
        await Assert.That(credential.DeviceGuid.Span.SequenceEqual(atLimit.HostVoucher!.DeviceGuid.Span)).IsTrue();

        using var overLimit = new Fixture();
        ushort oneLess = checked((ushort)(SetCredentialsSize(overLimit) - 1));
        FdoDeviceInitializeSession constrained = overLimit.CreateDevice(oneLess);
        await CatchAsync<CborContentException>(() => constrained.RunAsync(overLimit).AsTask());
        await Assert.That(constrained.StagingStarted).IsFalse();
        await Assert.That(constrained.SetHmacSendStarted).IsFalse();
        await Assert.That(overLimit.Manufacturer.VoucherPersistenceStarted).IsFalse();
    }

    [Test]
    public async Task ExplicitBypassStillRetainsTheLocalRendezvousDirective()
    {
        using var fixture = new Fixture();
        byte[] rendezvous = Rendezvous((5, Text("rvserver.local")), (14, new byte[] { 0xF6 }));
        fixture.ProposalRendezvous = rendezvous;

        FdoDeviceInitializeCredential credential = await fixture.RunAsync();

        await Assert.That(credential.EncodedRendezvousInfo.Span.SequenceEqual(rendezvous)).IsTrue();
        await Assert.That(FdoInitializationFields.ReadHeader(credential.EncodedVoucherHeaderTag).HasLocalRendezvous).IsTrue();
        await Assert.That(fixture.HostVoucher!.DeviceGuid.Span.SequenceEqual(credential.DeviceGuid.Span)).IsTrue();
    }

    [Test]
    public async Task ManufacturerRequiresResponseHandoffBeforeTheNextRequest()
    {
        using var fixture = new Fixture();
        ReadOnlyMemory<byte> appStart = new FdoDeviceInitializeCodec().EncodeAppStart(
            new FdoDeviceInitializeCodec.AppStart(new byte[] { 4 }, Array.Empty<string>(), null));
        FdoDeviceInitializeResponse response = await fixture.Manufacturer.ProcessAsync(
            200, FdoDeviceInitializeMessageType.AppStart, appStart);

        await Assert.That(response.MessageType).IsEqualTo(FdoDeviceInitializeMessageType.SetCredentials);
        await CatchAsync<InvalidOperationException>(() => fixture.Manufacturer.ProcessAsync(
            200, FdoDeviceInitializeMessageType.SetHmac, new byte[] { 0x80 }).AsTask());
        await Assert.That(Throws<InvalidOperationException>(fixture.Manufacturer.ConfirmResponseSent)).IsTrue();
        await Assert.That(fixture.Manufacturer.VoucherPersistenceStarted).IsFalse();
        await Assert.That(fixture.ProposalCount).IsEqualTo(1);
    }

    [Test]
    public async Task ActiveCredentialOrUnresolvedReservationIsNotOverwritten()
    {
        using var active = new Fixture();
        active.DeviceActive = true;
        await CatchAsync<InvalidOperationException>(() => active.RunAsync());
        await Assert.That(active.Events.Contains("wire:10")).IsFalse();
        await Assert.That(active.ProposalCount).IsEqualTo(0);

        using var pending = new Fixture();
        pending.ManufacturerReserved = true;
        await CatchAsync<InvalidOperationException>(() => pending.RunAsync());
        await Assert.That(pending.ProposalCount).IsEqualTo(0);
        await Assert.That(pending.Device.StagingStarted).IsFalse();
        await Assert.That(pending.HostVoucher).IsNull();
    }

    [Test]
    public async Task ProposalRequiresUsableDeviceCertificateAndPreservesOwnedData()
    {
        using var fixture = new Fixture();
        await Assert.That(Throws<CryptographicException>(() => FdoManufacturerInitializeProposal.Create(
            "device", fixture.ManufacturerKey, new ReadOnlyMemory<byte>[] { new byte[] { 0x30, 0x00 } }))).IsTrue();
        using X509Certificate2 noSigning = CreateCertificate(fixture.DeviceKey, X509KeyUsageFlags.KeyEncipherment);
        await Assert.That(Throws<CryptographicException>(() => FdoManufacturerInitializeProposal.Create(
            "device", fixture.ManufacturerKey, new ReadOnlyMemory<byte>[] { noSigning.RawData }))).IsTrue();

        FdoDeviceInitializeCredential credential = await fixture.RunAsync();
        byte[] expected = credential.DeviceGuid.ToArray();
        ReadOnlyMemory<byte> exposed = credential.DeviceGuid;
        await Assert.That(MemoryMarshal.TryGetArray(exposed, out ArraySegment<byte> segment)).IsTrue();
        Array.Fill(segment.Array!, (byte)0, segment.Offset, segment.Count);
        await Assert.That(credential.DeviceGuid.Span.SequenceEqual(expected)).IsTrue();
        await Assert.That(fixture.HostVoucher!.DeviceGuid.Span.SequenceEqual(expected)).IsTrue();
    }

    [Test]
    public async Task BothRolesRequireExplicitSelectionOfTheHeaderHmacConvention()
    {
        using var fixture = new Fixture();
        await Assert.That(Throws<InvalidOperationException>(() => new FdoDeviceInitializeSession(
            new FdoDeviceInitializeOptions
            {
                AttestationKey = fixture.DeviceKey,
                Handler = fixture,
                UseVoucherHeaderHmac = false,
            }))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => new FdoManufacturerInitializeSession(
            new FdoManufacturerInitializeOptions
            {
                Handler = fixture,
                UseVoucherHeaderHmac = false,
            }))).IsTrue();
        await Assert.That(fixture.Events.Count).IsEqualTo(0);
    }

    private static ushort SetCredentialsSize(Fixture fixture)
    {
        FdoManufacturerInitializeProposal proposal = FdoManufacturerInitializeProposal.Create(
            "test-device", fixture.ManufacturerKey, fixture.Certificates);
        ReadOnlyMemory<byte> body = new FdoDeviceInitializeCodec().EncodeSetCredentials(
            new FdoDeviceInitializeCodec.SetCredentials(
                new byte[] { 4 }, Array.Empty<string>(), proposal.EncodedVoucherHeaderTag));
        return checked((ushort)body.Length);
    }

    private static byte[] ReplaceHeaderField(ReadOnlyMemory<byte> encodedMessage, int index, byte[] replacement)
    {
        var codec = new FdoDeviceInitializeCodec();
        FdoDeviceInitializeCodec.SetCredentials message = codec.DecodeSetCredentials(encodedMessage);
        ReadOnlyMemory<byte> header = new FdoCborCodec().ReadByteStringPayload(message.EncodedHeaderTag);
        var reader = new CborReader(header, CborConformanceMode.Canonical);
        _ = reader.ReadStartArray();
        var fields = new byte[6][];
        for (int i = 0; i < fields.Length; i++)
        {
            fields[i] = reader.ReadEncodedValue().ToArray();
        }

        fields[index] = replacement;
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(fields.Length);
        foreach (byte[] field in fields)
        {
            writer.WriteEncodedValue(field);
        }

        writer.WriteEndArray();
        var wrapper = new CborWriter(CborConformanceMode.Canonical);
        wrapper.WriteByteString(writer.Encode());
        return codec.EncodeSetCredentials(new FdoDeviceInitializeCodec.SetCredentials(
            message.CapabilityFlags, message.VendorCapabilities, wrapper.Encode())).ToArray();
    }

    private static byte[] Rendezvous(params (int Tag, byte[] Value)[] instructions)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(1);
        writer.WriteStartArray(instructions.Length);
        foreach ((int tag, byte[] value) in instructions)
        {
            writer.WriteStartArray(2);
            writer.WriteInt32(tag);
            writer.WriteByteString(value);
            writer.WriteEndArray();
        }

        writer.WriteEndArray();
        writer.WriteEndArray();
        return writer.Encode();
    }

    private static byte[] Text(string value)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString(value);
        return writer.Encode();
    }

    private static byte[] EncodeBytes(byte[] value)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteByteString(value);
        return writer.Encode();
    }

    private static X509Certificate2 CreateCertificate(ECDsa key, X509KeyUsageFlags keyUsage)
    {
        HashAlgorithmName hash = key.KeySize == 384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
        var request = new CertificateRequest("CN=FDO test device", key, hash);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
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

    private sealed class Fixture :
        IDisposable,
        IFdoDeviceInitializeHandler,
        IFdoDeviceInitializeHmacSecret,
        IFdoManufacturerInitializeHandler,
        IFdoDeviceInitializeTransport
    {
        private readonly X509Certificate2 _certificate;
        private readonly bool _ownsKeys;
        private bool _deviceReserved;

        public Fixture(
            int deviceCurve = 256,
            int manufacturerCurve = 256,
            ReadOnlyMemory<byte>? manufacturingInfo = null,
            (ECDsa Device, ECDsa Manufacturer)? borrowedKeys = null)
        {
            _ownsKeys = borrowedKeys is null;
            DeviceKey = borrowedKeys?.Device ??
                ECDsa.Create(deviceCurve == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
            ManufacturerKey = borrowedKeys?.Manufacturer ??
                ECDsa.Create(manufacturerCurve == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
            _certificate = CreateCertificate(DeviceKey, X509KeyUsageFlags.DigitalSignature);
            Certificates = new ReadOnlyMemory<byte>[] { _certificate.RawData };
            SelectedAlgorithm = deviceCurve == 384 || manufacturerCurve == 384
                ? FdoDeviceHmacAlgorithm.HmacSha384 : FdoDeviceHmacAlgorithm.HmacSha256;
            Secret = RandomNumberGenerator.GetBytes(SelectedAlgorithm == FdoDeviceHmacAlgorithm.HmacSha256 ? 32 : 64);
            ManufacturingInfo = manufacturingInfo;
            Manufacturer = CreateManufacturer();
            Device = CreateDevice();
        }

        public List<string> Events { get; } = [];
        public ECDsa DeviceKey { get; }
        public ECDsa ManufacturerKey { get; }
        public RSA? RsaManufacturerKey { get; set; }
        public bool RestrictedRsa { get; set; }
        public IReadOnlyList<ReadOnlyMemory<byte>> Certificates { get; }
        public byte[] Secret { get; }
        public FdoDeviceHmacAlgorithm SelectedAlgorithm { get; }
        public FdoDeviceInitializeSession Device { get; }
        public FdoManufacturerInitializeSession Manufacturer { get; }
        public FdoDeviceInitializeCredential? StagedCredential { get; private set; }
        public FdoDeviceInitializeCredential? HostInstalled { get; private set; }
        public FdoManufacturerInitializeVoucher? HostVoucher { get; private set; }
        public FdoManufacturerInitializeRequest? ManufacturerRequest { get; private set; }
        public byte[]? LastHmacInput { get; private set; }
        public ReadOnlyMemory<byte>? ManufacturingInfo { get; set; }
        public FdoDeviceHmacAlgorithm? OverrideAlgorithm { get; set; }
        public int? OverrideKeySize { get; set; }
        public bool ShortHmacOutput { get; set; }
        public bool RejectDeviceAuthorization { get; set; }
        public bool RejectManufacturerAuthorization { get; set; }
        public Uri? AuthorizedHttpAddress { get; set; }
        public bool DeviceActive { get; set; }
        public bool ManufacturerReserved { get; set; }
        public bool ThrowAfterStage { get; set; }
        public bool ThrowAfterPersist { get; set; }
        public bool ThrowAfterInstall { get; set; }
        public bool DropDone { get; set; }
        public Action? AfterStage { get; set; }
        public Action<Guid, string, ReadOnlyMemory<byte>>? DeviceEffect { get; init; }
        public Action<Guid, string, ReadOnlyMemory<byte>>? StationEffect { get; init; }
        public CancellationTokenSource? CancelAfterStage { get; set; }
        public CancellationTokenSource? CancelAfterPersist { get; set; }
        public Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>? RewriteSetCredentials { get; set; }
        public Func<FdoDeviceInitializeResponse, FdoDeviceInitializeResponse>? RewriteCredentialsResponse { get; set; }
        public Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>? RewriteSetHmac { get; set; }
        public Func<FdoDeviceInitializeResponse, FdoDeviceInitializeResponse>? RewriteDone { get; set; }
        public ReadOnlyMemory<byte>? ProposalRendezvous { get; set; }
        public int ProposalCount { get; private set; }
        public FdoDeviceHmacAlgorithm Algorithm => OverrideAlgorithm ?? SelectedAlgorithm;
        public int KeySizeInBytes => OverrideKeySize ?? Secret.Length;

        public FdoManufacturerInitializeSession CreateManufacturer() => new(new FdoManufacturerInitializeOptions
        {
            Handler = this,
            UseVoucherHeaderHmac = true,
        });

        public FdoDeviceInitializeSession CreateDevice(ushort maxMessageSize = ushort.MaxValue) => new(new FdoDeviceInitializeOptions
        {
            AttestationKey = DeviceKey,
            Handler = this,
            EncodedDeviceMfgInfo = ManufacturingInfo,
            UseVoucherHeaderHmac = true,
            MaxMessageSize = maxMessageSize,
        });

        public Task<FdoDeviceInitializeCredential> RunAsync(CancellationToken cancellationToken = default) =>
            Device.RunAsync(this, cancellationToken).AsTask();

        public ValueTask<IFdoDeviceInitializeHmacSecret> AuthorizeAndReserveAsync(
            Guid runId,
            IFdoDeviceInitializeTransport transport,
            CancellationToken cancellationToken)
        {
            Events.Add("device-authorize");
            bool authorizedTransport = ReferenceEquals(transport, this) ||
                (AuthorizedHttpAddress is not null && transport is IFdoHttpPeer peer &&
                 peer.BaseAddress == AuthorizedHttpAddress);
            if (!authorizedTransport || RejectDeviceAuthorization || DeviceActive || _deviceReserved)
            {
                throw new InvalidOperationException("The Device or station is not authorized for initialization.");
            }

            DeviceEffect?.Invoke(runId, "reserve", ReadOnlyMemory<byte>.Empty);
            _deviceReserved = true;
            return ValueTask.FromResult<IFdoDeviceInitializeHmacSecret>(this);
        }

        public ValueTask<ReadOnlyMemory<byte>> ComputeAsync(
            ReadOnlyMemory<byte> encodedHeaderContents,
            CancellationToken cancellationToken)
        {
            Events.Add("hmac");
            LastHmacInput = encodedHeaderContents.ToArray();
            byte[] hmac = SelectedAlgorithm == FdoDeviceHmacAlgorithm.HmacSha256
                ? HMACSHA256.HashData(Secret, encodedHeaderContents.Span)
                : HMACSHA384.HashData(Secret, encodedHeaderContents.Span);
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(ShortHmacOutput ? hmac[..^1] : hmac);
        }

        public ValueTask StageAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken)
        {
            Events.Add("stage");
            DeviceEffect?.Invoke(credential.RunId, "stage", credential.EncodedVoucherHeaderTag);
            StagedCredential = credential;
            if (ThrowAfterStage)
            {
                throw new InvalidOperationException("Staging outcome is unknown.");
            }

            AfterStage?.Invoke();
            CancelAfterStage?.Cancel();
            return ValueTask.CompletedTask;
        }

        public ValueTask InstallAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken)
        {
            Events.Add("install");
            if (!ReferenceEquals(credential, StagedCredential) || DeviceActive)
            {
                throw new InvalidOperationException("The staged credential no longer matches.");
            }

            DeviceEffect?.Invoke(credential.RunId, "install", credential.EncodedVoucherHeaderTag);
            HostInstalled = credential;
            DeviceActive = true;
            if (ThrowAfterInstall)
            {
                throw new InvalidOperationException("Installation outcome is unknown.");
            }

            return ValueTask.CompletedTask;
        }

        public ValueTask<FdoManufacturerInitializeProposal> AuthorizeAndPrepareAsync(
            FdoManufacturerInitializeRequest request,
            CancellationToken cancellationToken)
        {
            Events.Add("manufacturer-authorize");
            ManufacturerRequest = request;
            if (RejectManufacturerAuthorization || ManufacturerReserved)
            {
                throw new InvalidOperationException("The Device is not authorized for this station.");
            }

            ManufacturerReserved = true;
            ProposalCount++;
            FdoManufacturerInitializeProposal proposal = RsaManufacturerKey is RSA rsa
                ? FdoManufacturerInitializeProposal.CreateRsa(
                    "test-device", rsa, Certificates, RestrictedRsa, ProposalRendezvous)
                : FdoManufacturerInitializeProposal.Create(
                    "test-device", ManufacturerKey, Certificates, ProposalRendezvous);
            return ValueTask.FromResult(proposal);
        }

        public ValueTask PersistVoucherAsync(FdoManufacturerInitializeVoucher voucher, CancellationToken cancellationToken)
        {
            Events.Add("persist");
            StationEffect?.Invoke(voucher.RunId, "voucher", voucher.EncodedVoucherHeaderTag);
            HostVoucher = voucher;
            if (ThrowAfterPersist)
            {
                throw new InvalidOperationException("Voucher persistence outcome is unknown.");
            }

            CancelAfterPersist?.Cancel();
            return ValueTask.CompletedTask;
        }

        public async ValueTask<FdoDeviceInitializeResponse> SendAsync(
            ushort protocolVersion,
            FdoDeviceInitializeMessageType messageType,
            ReadOnlyMemory<byte> encodedBody,
            CancellationToken cancellationToken)
        {
            Events.Add($"wire:{(ushort)messageType}");
            ReadOnlyMemory<byte> body = messageType == FdoDeviceInitializeMessageType.SetHmac && RewriteSetHmac is not null
                ? RewriteSetHmac(encodedBody) : encodedBody;
            FdoDeviceInitializeResponse response = await Manufacturer.ProcessAsync(
                protocolVersion, messageType, body, cancellationToken);
            Events.Add($"wire:{(ushort)response.MessageType}");
            if (DropDone && response.MessageType == FdoDeviceInitializeMessageType.Done)
            {
                throw new IOException("The response delivery is uncertain.");
            }

            Manufacturer.ConfirmResponseSent();
            if (response.MessageType == FdoDeviceInitializeMessageType.SetCredentials)
            {
                if (RewriteSetCredentials is not null)
                {
                    response = new FdoDeviceInitializeResponse(
                        response.ProtocolVersion, response.MessageType, RewriteSetCredentials(response.EncodedBody));
                }

                if (RewriteCredentialsResponse is not null)
                {
                    response = RewriteCredentialsResponse(response);
                }
            }

            return response.MessageType == FdoDeviceInitializeMessageType.Done && RewriteDone is not null
                ? RewriteDone(response) : response;
        }

        public void Dispose()
        {
            Manufacturer.Dispose();
            if (_ownsKeys)
            {
                DeviceKey.Dispose();
                ManufacturerKey.Dispose();
            }
            _certificate.Dispose();
            CryptographicOperations.ZeroMemory(Secret);
        }
    }
}
