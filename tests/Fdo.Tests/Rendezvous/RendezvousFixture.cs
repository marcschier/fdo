// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Rendezvous;
using AuthenticationFixture = Fdo.Tests.Cryptography.FdoTo2OwnerDeviceAuthenticatorTests.Fixture;

namespace Fdo.Tests.Rendezvous;

[UnsupportedOSPlatform("browser")]
internal sealed class RendezvousFixture
{
    public RendezvousFixture(AuthenticationFixture authentication)
    {
        Authentication = authentication;
        Codec = new FdoRendezvousCodec();
        Store = new RecordingStore();
        Clock = new TestClock();
        Address = new FdoRendezvousAddress(
            new byte[] { 192, 0, 2, 1 }, "owner.example.test", 8443, FdoRendezvousTransportProtocol.Https);
    }

    public AuthenticationFixture Authentication { get; }
    public FdoRendezvousCodec Codec { get; }
    public RecordingStore Store { get; }
    public TestClock Clock { get; }
    public FdoRendezvousAddress Address { get; set; }
    public List<string> Events { get; } = [];
    public uint MaxWaitSeconds { get; set; } = 120;
    public int MaxVoucherEntries { get; set; } = 10;
    public ushort MaxMessageSize { get; set; } = 8192;
    public ReadOnlyMemory<byte>? TrustedManufacturerKey { get; set; }
    public ReadOnlyMemory<byte>? DeviceTrustAnchor { get; set; }

    public FdoOwnerRendezvousSession CreateOwner(
        uint waitSeconds = 300, ECDsa? delegateKey = null,
        IReadOnlyList<ReadOnlyMemory<byte>>? delegateCertificates = null,
        FdoDelegateOfflineRevocationPolicy? offlineRevocation = null,
        IReadOnlyList<FdoRendezvousAddress>? additionalAddresses = null) =>
        new(new FdoOwnerRendezvousOptions
        {
            EncodedVoucherHeaderTag = Authentication.Voucher.HeaderTag,
            EncodedVoucherHeaderHmac = Authentication.Voucher.EncodedHeaderHmac,
            EncodedVoucherEntries = [Authentication.Voucher.FirstEntry, Authentication.Voucher.SecondEntry],
            EncodedDeviceCertificateChain = Authentication.EncodedChain,
            TrustedManufacturerKey = Authentication.Voucher.ManufacturerKey,
            DeviceTrustAnchor = Authentication.RootCertificate.RawData,
            DeviceRevocationMode = X509RevocationMode.NoCheck,
            OwnerSigningKey = delegateKey ?? Authentication.Voucher.FinalOwner,
            DelegateCertificates = delegateCertificates,
            DelegateTimeProvider = delegateCertificates is null ? null : Clock,
            DelegateOfflineRevocation = offlineRevocation,
            OwnerAddress = Address,
            AdditionalOwnerAddresses = additionalAddresses,
            WaitSeconds = waitSeconds,
            MaxMessageSize = MaxMessageSize,
            UseProvisionalPairedProfile = true,
        });

    public FdoDeviceRendezvousSession CreateDevice() => CreateDevice(delegated: false);

    public FdoDeviceRendezvousSession CreateDevice(bool delegated) =>
        new(new FdoDeviceRendezvousOptions
        {
            DeviceGuid = Authentication.Voucher.Guid,
            AttestationKey = Authentication.DeviceSigningKey,
            MaxMessageSize = MaxMessageSize,
            UseProvisionalPairedProfile = true,
            UseDelegatedDiscovery = delegated,
        });

    public FdoRendezvousServerSession CreateServer(
        FdoRendezvousProtocol protocol, IFdoAtomicRendezvousRegistrationStore? atomic = null,
        IFdoRendezvousRegistrationAdmission? admission = null, FdoDelegateOfflineRevocationPolicy? offlineRevocation = null,
        bool multiple = false) =>
        new(new FdoRendezvousServerOptions
        {
            TrustedManufacturerKey = TrustedManufacturerKey ?? Authentication.Voucher.ManufacturerKey,
            DeviceTrustAnchor = DeviceTrustAnchor ?? Authentication.RootCertificate.RawData,
            DeviceRevocationMode = X509RevocationMode.NoCheck,
            RegistrationStore = atomic is null ? Store : null,
            AtomicRegistrationStore = atomic,
            RegistrationAdmission = admission,
            DelegateOfflineRevocation = offlineRevocation,
            AllowMultipleDelegatedRedirects = multiple,
            MaxWaitSeconds = MaxWaitSeconds,
            MaxVoucherEntries = MaxVoucherEntries,
            MaxMessageSize = MaxMessageSize,
            TimeProvider = Clock,
            UseProvisionalPairedProfile = true,
        }, protocol);

    public TestTransport CreateTransport(FdoRendezvousServerSession server) => new(server, Events);

    public async Task<uint> RegisterAsync(uint waitSeconds = 300)
    {
        using FdoRendezvousServerSession server = CreateServer(FdoRendezvousProtocol.OwnerRegistration);
        return await CreateOwner(waitSeconds).RunAsync(CreateTransport(server));
    }

    public async Task<FdoDeviceRendezvousResult> LookupAsync(
        Func<TestMessage, TestMessage>? change = null)
    {
        using FdoRendezvousServerSession server = CreateServer(FdoRendezvousProtocol.DeviceLookup);
        TestTransport transport = CreateTransport(server);
        transport.Change = change;
        return await CreateDevice().RunAsync(transport);
    }

    public byte[] EncodeVoucher(IReadOnlyList<ReadOnlyMemory<byte>>? entries = null, ReadOnlyMemory<byte>? chain = null)
    {
        IReadOnlyList<ReadOnlyMemory<byte>> selected = entries ??
            new ReadOnlyMemory<byte>[] { Authentication.Voucher.FirstEntry, Authentication.Voucher.SecondEntry };
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(5);
        writer.WriteInt32(200);
        writer.WriteEncodedValue(Authentication.Voucher.HeaderTag);
        writer.WriteEncodedValue(Authentication.Voucher.EncodedHeaderHmac);
        writer.WriteEncodedValue((chain ?? Authentication.EncodedChain).Span);
        writer.WriteStartArray(selected.Count);
        foreach (ReadOnlyMemory<byte> entry in selected)
        {
            writer.WriteEncodedValue(entry.Span);
        }

        writer.WriteEndArray();
        writer.WriteEndArray();
        return writer.Encode();
    }

    public ReadOnlyMemory<byte> OwnerSign(
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte>? voucher = null,
        ECDsa? key = null)
    {
        ECDsa signer = key ?? Authentication.Voucher.FinalOwner;
        return Codec.EncodeOwnerSign(
            voucher ?? EncodeVoucher(), 300, nonce, Address,
            Authentication.Voucher.FinalOwner.KeySize == 384 ? FdoHashAlgorithm.Sha384 : FdoHashAlgorithm.Sha256,
            signer);
    }

    public async Task<ReadOnlyMemory<byte>> BeginOwnerAsync(FdoRendezvousServerSession server)
    {
        FdoRendezvousResponse ack = await server.ProcessAsync(
            200, FdoRendezvousMessageType.OwnerHello, Codec.EncodeInitial(20));
        server.ConfirmResponseSent();
        return Codec.ReadInitial(21, ack.EncodedBody).GuidOrNonce!.Value;
    }

    public async Task<ReadOnlyMemory<byte>> BeginDeviceAsync(FdoRendezvousServerSession server)
    {
        FdoRendezvousResponse ack = await server.ProcessAsync(
            200, FdoRendezvousMessageType.DeviceHello,
            Codec.EncodeInitial(30, Authentication.Voucher.Guid));
        server.ConfirmResponseSent();
        return Codec.ReadInitial(31, ack.EncodedBody).GuidOrNonce!.Value;
    }

    internal readonly record struct TestMessage(
        ushort Version,
        FdoRendezvousMessageType Type,
        ReadOnlyMemory<byte> Body);

    internal sealed class TestTransport(FdoRendezvousServerSession server, List<string> events) : IFdoRendezvousTransport
    {
        public List<TestMessage> Messages { get; } = [];
        public Func<TestMessage, TestMessage>? Change { get; set; }
        public IPAddress? OwnerSignSource { get; set; }

        public async ValueTask<FdoRendezvousResponse> SendAsync(
            ushort protocolVersion,
            FdoRendezvousMessageType messageType,
            ReadOnlyMemory<byte> encodedBody,
            CancellationToken cancellationToken)
        {
            TestMessage request = Record(new TestMessage(protocolVersion, messageType, encodedBody));
            FdoRendezvousResponse response = await server.ProcessAsync(
                request.Version, request.Type, request.Body,
                request.Type == FdoRendezvousMessageType.OwnerSign ? OwnerSignSource : null, cancellationToken);
            TestMessage received = Record(new TestMessage(
                response.ProtocolVersion, response.MessageType, response.EncodedBody));
            server.ConfirmResponseSent();
            return new FdoRendezvousResponse(received.Version, received.Type, received.Body);
        }

        private TestMessage Record(TestMessage message)
        {
            var snapshot = message with { Body = message.Body.ToArray() };
            Messages.Add(snapshot);
            events.Add("wire:" + (ushort)snapshot.Type);
            return Change?.Invoke(snapshot) ?? snapshot;
        }
    }

    internal sealed class RecordingStore : IFdoRendezvousRegistrationStore
    {
        private readonly Dictionary<string, FdoRendezvousRegistration> _registrations = [];

        public int Writes { get; private set; }
        public int Reads { get; private set; }
        public bool ThrowAfterWrite { get; set; }
        public Action? AfterWrite { get; set; }
        public FdoRendezvousRegistration? LastWritten { get; private set; }

        public ValueTask StoreAsync(FdoRendezvousRegistration registration, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Writes++;
            _registrations[Convert.ToHexString(registration.DeviceGuid.Span)] = registration;
            LastWritten = registration;
            AfterWrite?.Invoke();
            if (ThrowAfterWrite)
            {
                throw new InvalidOperationException("The store wrote but did not report success.");
            }

            return ValueTask.CompletedTask;
        }

        public ValueTask<FdoRendezvousRegistration?> FindAsync(
            ReadOnlyMemory<byte> deviceGuid, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Reads++;
            _registrations.TryGetValue(Convert.ToHexString(deviceGuid.Span), out FdoRendezvousRegistration? value);
            return ValueTask.FromResult(value);
        }
    }

    internal sealed class TestClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
