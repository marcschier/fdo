// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Initialization;
using Fdo.Ownership;
using Fdo.Serialization;
using VoucherFixture = Fdo.Tests.Cryptography.FdoOwnershipVoucherChainVerifierTests.VoucherFixture;

namespace Fdo.Tests.Cryptography;

public sealed class FdoTo2OwnerDeviceAuthenticatorTests
{
    [Test]
    [Arguments(256, 0, 1, true)]
    [Arguments(384, 1, 3, false)]
    public async Task BindsTrustedVoucherCertificateAndSignedTranscriptInOneAttempt(
        int curveSize, int exchangeValue, int cipherValue, bool includeRoot)
    {
        using var fixture = new Fixture(
            curveSize, (FdoKeyExchangeSuite)exchangeValue, (FdoCoseAeadAlgorithm)cipherValue, includeRoot);
        var policy = new RecordingPolicy(fixture.CreatePolicy());
        FdoTo2OwnerDeviceAuthenticator authenticator = fixture.CreateAuthenticator(policy);
        string expectedHeader = Convert.ToHexString(fixture.Voucher.HeaderTag);
        string expectedEntry = Convert.ToHexString(fixture.Voucher.FirstEntry);
        string expectedChain = Convert.ToHexString(fixture.EncodedChain);
        string expectedProbe = Convert.ToHexString(fixture.Probe);
        string expectedProof = Convert.ToHexString(fixture.Proof);

        Array.Fill(fixture.Voucher.HeaderTag, (byte)0);
        Array.Fill(fixture.Voucher.FirstEntry, (byte)0);
        Array.Fill(fixture.EncodedChain, (byte)0);
        Array.Fill(fixture.Probe, (byte)0);
        Array.Fill(fixture.Acknowledgement, (byte)0);
        FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice result = authenticator.Verify(fixture.Proof);
        Array.Fill(fixture.Proof, (byte)0);

        await Assert.That(Convert.ToHexString(result.Header.Span)).IsEqualTo(expectedHeader);
        await Assert.That(Convert.ToHexString(result.Entries[0].Span)).IsEqualTo(expectedEntry);
        await Assert.That(Convert.ToHexString(result.Voucher.DeviceCertificateChain.Span)).IsEqualTo(expectedChain);
        await Assert.That(Convert.ToHexString(result.DeviceCertificate.Span))
            .IsEqualTo(Convert.ToHexString(fixture.DeviceCertificate.RawData));
        await Assert.That(Convert.ToHexString(result.Probe.Span)).IsEqualTo(expectedProbe);
        await Assert.That(Convert.ToHexString(result.EncodedDeviceProof.Span)).IsEqualTo(expectedProof);
        await Assert.That(Convert.ToHexString(result.OwnerKey.Span))
            .IsEqualTo(Convert.ToHexString(fixture.Voucher.FinalOwnerKey));
        await Assert.That(Convert.ToHexString(result.DeviceProof.Guid.Span))
            .IsEqualTo(Convert.ToHexString(fixture.Voucher.Guid));
        await Assert.That(Convert.ToHexString(policy.Guid.Span))
            .IsEqualTo(Convert.ToHexString(result.DeviceProof.Guid.Span));
        await Assert.That(Convert.ToHexString(policy.Leaf.Span))
            .IsEqualTo(Convert.ToHexString(result.DeviceCertificate.Span));
        await Assert.That(policy.Calls).IsEqualTo(1);

        ClearExposedMemory(result.Header);
        ClearExposedMemory(result.Entries[0]);
        ClearExposedMemory(result.Voucher.DeviceCertificateChain);
        ClearExposedMemory(result.DeviceProof.Guid);
        ClearExposedMemory(result.DeviceCertificate);
        await Assert.That(Convert.ToHexString(result.Header.Span)).IsEqualTo(expectedHeader);
        await Assert.That(Convert.ToHexString(result.Entries[0].Span)).IsEqualTo(expectedEntry);
        await Assert.That(Convert.ToHexString(result.Voucher.DeviceCertificateChain.Span)).IsEqualTo(expectedChain);
        await Assert.That(Convert.ToHexString(result.DeviceProof.Guid.Span))
            .IsEqualTo(Convert.ToHexString(fixture.Voucher.Guid));
        await Assert.That(Convert.ToHexString(result.DeviceCertificate.Span))
            .IsEqualTo(Convert.ToHexString(fixture.DeviceCertificate.RawData));
        await Assert.That(Throws<InvalidOperationException>(() => authenticator.Verify(fixture.Proof))).IsTrue();
    }

    [Test]
    public async Task RejectsAnUntrustedManufacturerOrCertificateAuthority()
    {
        using var fixture = new Fixture();
        using var other = new Fixture();
        var wrongManufacturer = new FdoPinnedDeviceTrustPolicy(
            other.Voucher.ManufacturerKey, fixture.RootCertificate.RawData, X509RevocationMode.NoCheck);
        var wrongRoot = new FdoPinnedDeviceTrustPolicy(
            fixture.Voucher.ManufacturerKey, other.RootCertificate.RawData, X509RevocationMode.NoCheck);

        await Assert.That(Throws<CryptographicException>(() =>
            fixture.CreateAuthenticator(wrongManufacturer).Verify(fixture.Proof))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            fixture.CreateAuthenticator(wrongRoot).Verify(fixture.Proof))).IsTrue();
    }

    [Test]
    [Arguments(2048, false)]
    [Arguments(2048, true)]
    [Arguments(3072, false)]
    public async Task AuthenticatesTheDeviceAgainstTheRsaVoucherOwner(int keySize, bool restricted)
    {
        using var fixture = new Fixture();
        using RSA manufacturer = RSA.Create(keySize);
        using RSA owner = RSA.Create(keySize);
        using RSA wrongOwner = RSA.Create(keySize);
        FdoTransferredOwnershipVoucher voucher = fixture.CreateRsaVoucher(manufacturer, owner, restricted);
        var keys = new FdoPublicKeyCodec();
        ReadOnlyMemory<byte> manufacturerKey = keys.EncodeRsa(manufacturer, restricted);
        ReadOnlyMemory<byte> ownerKey = keys.EncodeRsa(owner, restricted);
        var policy = new FdoPinnedDeviceTrustPolicy(
            manufacturerKey, fixture.RootCertificate.RawData, X509RevocationMode.NoCheck);

        FdoTo2OwnerDeviceAuthenticator CreateAuthenticator(RSA signingKey) => new(
            voucher.EncodedVoucherHeaderTag, voucher.EncodedVoucherHeaderHmac,
            voucher.EncodedVoucherEntries, voucher.EncodedDeviceCertificateChain,
            signingKey, fixture.Probe, fixture.Acknowledgement, policy);

        FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice authenticated =
            CreateAuthenticator(owner).Verify(fixture.Proof);
        byte[] changedProof = (byte[])fixture.Proof.Clone();
        changedProof[^1] ^= 1;

        await Assert.That(authenticated.OwnerKey.Span.SequenceEqual(ownerKey.Span)).IsTrue();
        await Assert.That(authenticated.DeviceProof.Guid.Span.SequenceEqual(fixture.Voucher.Guid)).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => CreateAuthenticator(wrongOwner))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            CreateAuthenticator(owner).Verify(changedProof))).IsTrue();
    }

    [Test]
    public async Task RejectsChangedVoucherChainCertificateHashOwnerAndEmptyVoucher()
    {
        using var fixture = new Fixture();
        byte[] changedEntry = (byte[])fixture.Voucher.FirstEntry.Clone();
        changedEntry[^1] ^= 1;
        byte[] changedChain = (byte[])fixture.EncodedChain.Clone();
        changedChain[^1] ^= 1;

        await Assert.That(Throws<CryptographicException>(() => fixture.CreateAuthenticator(
            entries: [changedEntry, fixture.Voucher.SecondEntry]))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => fixture.CreateAuthenticator(
            encodedChain: changedChain))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => fixture.CreateAuthenticator(
            ownerKey: fixture.Voucher.FirstOwner))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => fixture.CreateAuthenticator(
            entries: Array.Empty<ReadOnlyMemory<byte>>()))).IsTrue();
    }

    [Test]
    public async Task RejectsWrongProofKeyChangedTranscriptAndAnotherVoucherGuid()
    {
        using var fixture = new Fixture();
        using ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] wrongKeyProof = fixture.CreateProof(otherKey);
        var policy = new RecordingPolicy(fixture.CreatePolicy());
        FdoTo2OwnerDeviceAuthenticator wrongKey = fixture.CreateAuthenticator(policy);
        await Assert.That(Throws<CryptographicException>(() => wrongKey.Verify(wrongKeyProof))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => wrongKey.Verify(fixture.Proof))).IsTrue();
        await Assert.That(policy.Calls).IsEqualTo(0);

        var codec = new FdoTo2InitialCodec();
        FdoTo2InitialCodec.Acknowledgement acknowledgement = codec.DecodeAcknowledgement(fixture.Acknowledgement);
        byte[] changedAck = codec.EncodeAcknowledgement(
            acknowledgement with { NonceTo2ProveDv = new byte[16] }).ToArray();
        await Assert.That(Throws<CryptographicException>(() =>
            fixture.CreateAuthenticator(acknowledgement: changedAck).Verify(fixture.Proof))).IsTrue();

        byte[] anotherGuid = (byte[])fixture.Voucher.Guid.Clone();
        anotherGuid[0] ^= 1;
        FdoTo2InitialCodec.Probe probe = codec.DecodeProbe(fixture.Probe);
        byte[] otherProbe = codec.EncodeProbe(probe with { Guid = anotherGuid }).ToArray();
        byte[] otherAck = codec.EncodeAcknowledgement(acknowledgement with
        {
            Guid = anotherGuid,
            HashPrev = codec.ComputeProbeHash(FdoHashAlgorithm.Sha256, otherProbe),
        }).ToArray();
        await Assert.That(Throws<CryptographicException>(() => fixture.CreateAuthenticator(
            probe: otherProbe, acknowledgement: otherAck))).IsTrue();
    }

    [Test]
    public async Task RejectsACertificateThatDoesNotPermitSignatures()
    {
        using var fixture = new Fixture(keyUsage: X509KeyUsageFlags.KeyEncipherment);
        var policy = new RecordingPolicy(fixture.CreatePolicy());
        FdoTo2OwnerDeviceAuthenticator authenticator = fixture.CreateAuthenticator(policy);

        await Assert.That(Throws<CryptographicException>(() => authenticator.Verify(fixture.Proof))).IsTrue();
        await Assert.That(policy.Calls).IsEqualTo(0);
        await Assert.That(Throws<InvalidOperationException>(() => authenticator.Verify(fixture.Proof))).IsTrue();
    }

    [Test]
    public async Task RejectsAValidButReorderedCertificatePath()
    {
        using var fixture = new Fixture();
        FdoPinnedDeviceTrustPolicy policy = fixture.CreatePolicy();
        var evidence = new FdoOwnerDeviceTrustEvidence(
            fixture.Voucher.Guid,
            fixture.Voucher.ManufacturerKey,
            new ReadOnlyMemory<byte>[] { fixture.RootCertificate.RawData, fixture.DeviceCertificate.RawData });

        await Assert.That(Throws<CryptographicException>(() => policy.Validate(evidence))).IsTrue();
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

    private static void ClearExposedMemory(ReadOnlyMemory<byte> value)
    {
        if (!MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment) || segment.Array is null)
        {
            throw new InvalidOperationException("The test expected array-backed memory.");
        }

        Array.Clear(segment.Array, segment.Offset, segment.Count);
    }

    private sealed class RecordingPolicy(IFdoOwnerDeviceTrustPolicy inner) : IFdoOwnerDeviceTrustPolicy
    {
        public int Calls { get; private set; }
        public ReadOnlyMemory<byte> Guid { get; private set; }
        public ReadOnlyMemory<byte> Leaf { get; private set; }

        public void Validate(FdoOwnerDeviceTrustEvidence evidence)
        {
            Calls++;
            inner.Validate(evidence);
            Guid = evidence.Guid;
            Leaf = evidence.DeviceCertificates[0];
        }
    }

    internal sealed class Fixture : IDisposable
    {
        private readonly ECDsa _rootKey;
        private readonly FdoKeyExchangeSuite _exchange;
        private readonly FdoCoseAeadAlgorithm _cipher;
        private readonly byte[] _ownerNonce = Convert.FromHexString("303132333435363738393A3B3C3D3E3F");

        public Fixture(
            int curveSize = 256,
            FdoKeyExchangeSuite exchange = FdoKeyExchangeSuite.Ecdh256,
            FdoCoseAeadAlgorithm cipher = FdoCoseAeadAlgorithm.A128Gcm,
            bool includeRoot = true,
            X509KeyUsageFlags keyUsage = X509KeyUsageFlags.DigitalSignature)
        {
            _exchange = exchange;
            _cipher = cipher;
            ECCurve curve = curveSize == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384;
            HashAlgorithmName hash = curveSize == 256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384;
            _rootKey = ECDsa.Create(curve);
            DeviceSigningKey = ECDsa.Create(curve);
            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
            DateTimeOffset notAfter = notBefore.AddDays(1);
            var rootRequest = new CertificateRequest("CN=FDO test CA", _rootKey, hash);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
            RootCertificate = rootRequest.CreateSelfSigned(notBefore, notAfter);

            var deviceRequest = new CertificateRequest("CN=FDO test Device", DeviceSigningKey, hash);
            deviceRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            deviceRequest.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
            DeviceCertificate = deviceRequest.Create(
                RootCertificate, notBefore.AddMinutes(1), notAfter.AddMinutes(-1), [1, 2, 3, 4]);
            var certificates = includeRoot
                ? new ReadOnlyMemory<byte>[] { DeviceCertificate.RawData, RootCertificate.RawData }
                : new ReadOnlyMemory<byte>[] { DeviceCertificate.RawData };
            EncodedChain = new FdoX5ChainCodec().Encode(certificates).ToArray();
            Voucher = new VoucherFixture(curveSize, encodedCertificateChain: EncodedChain);

            var initial = new FdoTo2InitialCodec();
            Probe = initial.EncodeProbe(new FdoTo2InitialCodec.Probe(
                new byte[] { 4 }, Array.Empty<string>(), Voucher.Guid, 4096,
                new long[] { (long)FdoHashAlgorithm.Sha256 }, new byte[16])).ToArray();
            Acknowledgement = initial.EncodeAcknowledgement(new FdoTo2InitialCodec.Acknowledgement(
                new byte[] { 4 }, Array.Empty<string>(), Voucher.Guid, 4096,
                new[] { "ECDH256", "ECDH384" },
                new long[] { 1, 3, 30, 31, 32, 33, -17760703, -17760704, -17760705, -17760706 },
                Convert.FromHexString("202122232425262728292A2B2C2D2E2F"),
                initial.ComputeProbeHash(FdoHashAlgorithm.Sha256, Probe))).ToArray();
            Proof = CreateProof(DeviceSigningKey);
        }

        public X509Certificate2 RootCertificate { get; }
        public X509Certificate2 DeviceCertificate { get; }
        public ECDsa DeviceSigningKey { get; }
        public VoucherFixture Voucher { get; }
        public byte[] EncodedChain { get; }
        public byte[] Probe { get; }
        public byte[] Acknowledgement { get; }
        public byte[] Proof { get; }

        public FdoPinnedDeviceTrustPolicy CreatePolicy() => new(
            Voucher.ManufacturerKey, RootCertificate.RawData, X509RevocationMode.NoCheck);

        public FdoTransferredOwnershipVoucher CreateRsaVoucher(RSA manufacturer, RSA owner, bool restricted)
        {
            ReadOnlyMemory<byte> manufacturerKey = new FdoPublicKeyCodec().EncodeRsa(manufacturer, restricted);
            byte[] header = Voucher.CreateHeaderTag(manufacturerKey: manufacturerKey);
            ReadOnlyMemory<byte> headerContents = new CborReader(header).ReadDefiniteLengthByteString();
            FdoHashValue hmac = FdoHashValue.ComputeHmac(
                Voucher.HmacAlgorithm, Voucher.Secret, headerContents.Span);
            ReadOnlyMemory<byte> original = FdoInitializationFields.CreateVoucher(header, hmac, EncodedChain);
            return FdoOwnershipVoucherTransfer.ExtendRsa(original, manufacturer, owner);
        }

        public FdoTo2OwnerDeviceAuthenticator CreateAuthenticator(
            IFdoOwnerDeviceTrustPolicy? policy = null,
            IReadOnlyList<ReadOnlyMemory<byte>>? entries = null,
            ReadOnlyMemory<byte>? encodedChain = null,
            ECDsa? ownerKey = null,
            ReadOnlyMemory<byte>? probe = null,
            ReadOnlyMemory<byte>? acknowledgement = null) =>
            new(
                Voucher.HeaderTag,
                Voucher.EncodedHeaderHmac,
                entries ?? new ReadOnlyMemory<byte>[] { Voucher.FirstEntry, Voucher.SecondEntry },
                encodedChain ?? EncodedChain,
                ownerKey ?? Voucher.FinalOwner,
                probe ?? Probe,
                acknowledgement ?? Acknowledgement,
                policy ?? CreatePolicy());

        public byte[] CreateProof(ECDsa key)
        {
            using FdoEcdhKeyExchange exchange = FdoEcdhKeyExchange.Create(_exchange, FdoEcdhParty.Device);
            return new FdoTo2DeviceProofCodec().Sign(
                Probe, Acknowledgement, _exchange, _cipher,
                exchange.ExportParameter(), _ownerNonce, key).ToArray();
        }

        public void Dispose()
        {
            Voucher.Dispose();
            DeviceCertificate.Dispose();
            RootCertificate.Dispose();
            DeviceSigningKey.Dispose();
            _rootKey.Dispose();
        }
    }
}
