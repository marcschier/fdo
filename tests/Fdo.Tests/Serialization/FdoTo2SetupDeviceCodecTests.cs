using System;
using System.Formats.Cbor;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Ownership;
using Fdo.Serialization;
using OwnerFixture = Fdo.Tests.Cryptography.FdoTo2OwnerDeviceAuthenticatorTests.Fixture;

namespace Fdo.Tests.Serialization;

[UnsupportedOSPlatform("browser")]
public sealed class FdoTo2SetupDeviceCodecTests
{
    [Test]
    [Arguments(256, 0, 1)]
    [Arguments(384, 1, 3)]
    public async Task SignsAndVerifiesCredentialReuseWithTheProvenOwnerKey(
        int curveSize, int exchangeValue, int cipherValue)
    {
        using var fixture = new Fixture(curveSize, (FdoKeyExchangeSuite)exchangeValue, (FdoCoseAeadAlgorithm)cipherValue);
        var codec = new FdoTo2SetupDeviceCodec();
        ushort?[] sizes = [null, 0, 1300, ushort.MaxValue];
        string[] payloads = ["8302F6F6", "8302F600", "8302F6190514", "8302F619FFFF"];

        for (int i = 0; i < sizes.Length; i++)
        {
            ReadOnlyMemory<byte> signed = codec.Sign(fixture.Device, fixture.Voucher.FinalOwner, true, sizes[i]);
            ushort? decodedSize = codec.Verify(fixture.Owner, signed, true);

            await Assert.That(decodedSize).IsEqualTo(sizes[i]);
            await Assert.That(Convert.ToHexString(ReadPayload(signed))).IsEqualTo(payloads[i]);
        }
    }

    [Test]
    public async Task RequiresOptInOnEachSideAndTheVoucherOwnerSigningKey()
    {
        using var fixture = new Fixture();
        var codec = new FdoTo2SetupDeviceCodec();
        ReadOnlyMemory<byte> signed = codec.Sign(fixture.Device, fixture.Voucher.FinalOwner, true, 1300);

        await Assert.That(Throws<InvalidOperationException>(() =>
            codec.Sign(fixture.Device, fixture.Voucher.FinalOwner, false, 1300))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            codec.Verify(fixture.Owner, signed, false))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Sign(fixture.Device, fixture.Voucher.FirstOwner, true, 1300))).IsTrue();
    }

    [Test]
    [Arguments(2048, false)]
    [Arguments(2048, true)]
    [Arguments(3072, false)]
    public async Task SignsAndVerifiesSetupWithTheAuthenticatedRsaOwner(int keySize, bool restricted)
    {
        using var fixture = new OwnerFixture();
        using RSA manufacturer = RSA.Create(keySize);
        using RSA owner = RSA.Create(keySize);
        using RSA wrongOwner = RSA.Create(keySize);
        FdoTransferredOwnershipVoucher voucher = fixture.CreateRsaVoucher(manufacturer, owner, restricted);
        var keys = new FdoPublicKeyCodec();
        ReadOnlyMemory<byte> manufacturerKey = keys.EncodeRsa(manufacturer, restricted);
        ReadOnlyMemory<byte> ownerKey = keys.EncodeRsa(owner, restricted);
        var policy = new FdoPinnedDeviceTrustPolicy(
            manufacturerKey, fixture.RootCertificate.RawData, X509RevocationMode.NoCheck);
        var authenticator = new FdoTo2OwnerDeviceAuthenticator(
            voucher.EncodedVoucherHeaderTag, voucher.EncodedVoucherHeaderHmac,
            voucher.EncodedVoucherEntries, voucher.EncodedDeviceCertificateChain,
            owner, fixture.Probe, fixture.Acknowledgement, policy);
        FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice device = authenticator.Verify(fixture.Proof);
        using var verifier = new FdoOwnershipVoucherChainVerifier(
            voucher.EncodedVoucherHeaderTag, voucher.EncodedVoucherHeaderHmac, voucher.EncodedVoucherEntries.Count);
        FdoHashValue manufacturerHash = FdoHashValue.ComputeDigest(
            fixture.Voucher.ManufacturerHash.Algorithm, manufacturerKey.Span);
        verifier.CheckDeviceCredentials(
            fixture.Voucher.Guid, manufacturerHash, fixture.Voucher.HmacAlgorithm, fixture.Voucher.Secret);
        verifier.AppendEntry(0, voucher.EncodedVoucherEntries[0]);
        verifier.CompleteDeviceChecks(ownerKey);
        var verifiedOwner = new FdoTo2OwnerProofCodec.OwnerProof(ownerKey, ReadOnlyMemory<byte>.Empty, 4096);
        var codec = new FdoTo2SetupDeviceCodec();

        byte[] signed = codec.Sign(device, owner, true, 1300).ToArray();
        byte[] changed = (byte[])signed.Clone();
        changed[^1] ^= 1;

        await Assert.That(codec.Verify(verifiedOwner, signed, true)).IsEqualTo((ushort?)1300);
        await Assert.That(Throws<CryptographicException>(() => codec.Sign(device, wrongOwner, true, 1300))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.Verify(verifiedOwner, changed, true))).IsTrue();
    }

    [Test]
    public async Task RejectsWrongSignatureSignerAndDomain()
    {
        using var fixture = new Fixture();
        var codec = new FdoTo2SetupDeviceCodec();
        byte[] signed = codec.Sign(fixture.Device, fixture.Voucher.FinalOwner, true, 1300).ToArray();
        byte[] changed = (byte[])signed.Clone();
        changed[^1] ^= 1;
        byte[] payload = ReadPayload(signed);
        ReadOnlyMemory<byte> wrongSigner = SignPayload(fixture.Voucher.FirstOwner, payload);
        ReadOnlyMemory<byte> wrongDomain = SignPayload(
            fixture.Voucher.FinalOwner, payload, FdoSignatureOperation.TO2ProveOVHdr);

        await Assert.That(Throws<CryptographicException>(() => codec.Verify(fixture.Owner, changed, true))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.Verify(fixture.Owner, wrongSigner, true))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.Verify(fixture.Owner, wrongDomain, true))).IsTrue();
    }

    [Test]
    public async Task RejectsUnsupportedOrMalformedSignedSetupPayloads()
    {
        using var fixture = new Fixture();
        var codec = new FdoTo2SetupDeviceCodec();

        await Assert.That(Rejects<NotSupportedException>(codec, fixture, new byte[] { 0x83, 0x01, 0xF6, 0xF6 }))
            .IsTrue();
        await Assert.That(Rejects<NotSupportedException>(codec, fixture, new byte[] { 0x83, 0x03, 0xF6, 0xF6 }))
            .IsTrue();
        await Assert.That(Rejects<CborContentException>(codec, fixture, new byte[] { 0x82, 0x02, 0xF6 }))
            .IsTrue();
        await Assert.That(Rejects<CborContentException>(codec, fixture, new byte[] { 0x83, 0x02, 0x80, 0xF6 }))
            .IsTrue();
        await Assert.That(Rejects<CborContentException>(codec, fixture, new byte[] { 0x83, 0x02, 0xF6, 0x20 }))
            .IsTrue();
        await Assert.That(Rejects<CborContentException>(
            codec, fixture, new byte[] { 0x83, 0x02, 0xF6, 0x1A, 0x00, 0x01, 0x00, 0x00 })).IsTrue();
    }

    [Test]
    public async Task ExposingCompletedProofBytesCannotChangeTheSetupVerificationKey()
    {
        using var fixture = new Fixture();
        var codec = new FdoTo2SetupDeviceCodec();
        string expectedOwnerKey = Convert.ToHexString(fixture.Owner.OwnerKey.Span);
        string expectedParameter = Convert.ToHexString(fixture.Owner.OwnerParameter.Span);
        ClearExposedMemory(fixture.Owner.OwnerKey);
        ClearExposedMemory(fixture.Owner.OwnerParameter);

        ReadOnlyMemory<byte> signed = codec.Sign(fixture.Device, fixture.Voucher.FinalOwner, true, null);

        await Assert.That(Convert.ToHexString(fixture.Owner.OwnerKey.Span)).IsEqualTo(expectedOwnerKey);
        await Assert.That(Convert.ToHexString(fixture.Owner.OwnerParameter.Span)).IsEqualTo(expectedParameter);
        await Assert.That(codec.Verify(fixture.Owner, signed, true)).IsEqualTo((ushort?)null);
    }

    private static bool Rejects<TException>(
        FdoTo2SetupDeviceCodec codec, Fixture fixture, byte[] payload)
        where TException : Exception =>
        Throws<TException>(() => codec.Verify(
            fixture.Owner, SignPayload(fixture.Voucher.FinalOwner, payload), true));

    private static ReadOnlyMemory<byte> SignPayload(
        ECDsa key,
        byte[] payload,
        FdoSignatureOperation operation = FdoSignatureOperation.TO2SetupDevice)
    {
        FdoCoseSignatureAlgorithm algorithm = key.KeySize == 256
            ? FdoCoseSignatureAlgorithm.ES256
            : FdoCoseSignatureAlgorithm.ES384;
        return new FdoCoseSign1Codec().Sign(operation, algorithm, key, payload);
    }

    private static byte[] ReadPayload(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Canonical);
        reader.ReadTag();
        reader.ReadStartArray();
        reader.ReadByteString();
        reader.ReadStartMap();
        reader.ReadEndMap();
        byte[] payload = reader.ReadByteString();
        reader.ReadByteString();
        reader.ReadEndArray();
        return payload;
    }

    private static void ClearExposedMemory(ReadOnlyMemory<byte> value)
    {
        if (!MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment) || segment.Array is null)
        {
            throw new InvalidOperationException("The test expected array-backed memory.");
        }

        Array.Clear(segment.Array, segment.Offset, segment.Count);
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

    private sealed class Fixture : IDisposable
    {
        private readonly OwnerFixture _fixture;

        public Fixture(
            int curveSize = 256,
            FdoKeyExchangeSuite exchange = FdoKeyExchangeSuite.Ecdh256,
            FdoCoseAeadAlgorithm cipher = FdoCoseAeadAlgorithm.A128Gcm)
        {
            _fixture = new OwnerFixture(curveSize, exchange, cipher);
            Device = _fixture.CreateAuthenticator().Verify(_fixture.Proof);
            using FdoEcdhKeyExchange keyExchange = FdoEcdhKeyExchange.Create(exchange, FdoEcdhParty.Owner);
            var proofCodec = new FdoTo2OwnerProofCodec();
            ReadOnlyMemory<byte> signedProof = proofCodec.Sign(
                Voucher.HeaderTag, Voucher.EncodedHeaderHmac, 2, Device.DeviceProof.OwnerNonce,
                exchange, keyExchange.ExportParameter(), 4096, Voucher.FinalOwner);
            using FdoTo2OwnerProofCodec.PendingOwnerProof pending = proofCodec.BeginDeviceVerification(
                signedProof, Device.DeviceProof.OwnerNonce, exchange, Voucher.Guid,
                Voucher.ManufacturerHash, Voucher.HmacAlgorithm, Voucher.Secret);
            pending.AppendEntry(0, Voucher.FirstEntry);
            pending.AppendEntry(1, Voucher.SecondEntry);
            Owner = pending.CompleteDeviceChecks();
        }

        public Fdo.Tests.Cryptography.FdoOwnershipVoucherChainVerifierTests.VoucherFixture Voucher => _fixture.Voucher;
        public FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice Device { get; }
        public FdoTo2OwnerProofCodec.OwnerProof Owner { get; }

        public void Dispose() => _fixture.Dispose();
    }

    [Test]
    [Arguments(256, 0, 1, false)]
    [Arguments(256, 0, 1, true)]
    [Arguments(384, 1, 3, false)]
    [Arguments(384, 1, 3, true)]
    public async Task SignsAndVerifiesReplacementWithDistinctOwner2Key(
        int curveSize, int exchangeValue, int cipherValue, bool includeSize)
    {
        using var fixture = new Fixture(curveSize, (FdoKeyExchangeSuite)exchangeValue, (FdoCoseAeadAlgorithm)cipherValue);
        using ECDsa owner2 = ECDsa.Create(curveSize == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
        var codec = new FdoTo2SetupDeviceCodec();
        byte[] rendezvous = ReplacementRendezvous("rvserver.local");
        byte[] guid = ReplacementGuid();
        byte[] nonce = ReplacementNonce();
        ushort? size = includeSize ? (ushort)1300 : null;
        ReadOnlyMemory<byte> key = new FdoPublicKeyCodec().Encode(owner2);

        ReadOnlyMemory<byte> signed = codec.SignReplacement(fixture.Device, owner2, rendezvous, guid, nonce, size);
        FdoTo2SetupDeviceCodec.Replacement result = codec.VerifyReplacement(fixture.Owner, signed, nonce);

        await Assert.That(codec.ReadUntrustedDisposition(signed)).IsEqualTo(1UL);
        await Assert.That(Convert.ToHexString(result.RendezvousInfo.Span)).IsEqualTo(Convert.ToHexString(rendezvous));
        await Assert.That(Convert.ToHexString(result.Guid.Span)).IsEqualTo(Convert.ToHexString(guid));
        await Assert.That(Convert.ToHexString(result.Nonce.Span)).IsEqualTo(Convert.ToHexString(nonce));
        await Assert.That(Convert.ToHexString(result.OwnerKey.Span)).IsEqualTo(Convert.ToHexString(key.Span));
        await Assert.That(result.MaxDeviceServiceInfoSize).IsEqualTo(size);
    }

    [Test]
    public async Task RejectsSameOrIncompatibleOwner2Key()
    {
        using var fixture = new Fixture();
        using ECDsa wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using RSA wrongType = RSA.Create(2048);
        var codec = new FdoTo2SetupDeviceCodec();
        var keys = new FdoPublicKeyCodec();
        byte[] rendezvous = ReplacementRendezvous("rvserver.local");
        byte[] guid = ReplacementGuid();
        byte[] nonce = ReplacementNonce();

        await Assert.That(Throws<CryptographicException>(() =>
            codec.SignReplacement(fixture.Device, fixture.Voucher.FinalOwner, rendezvous, guid, nonce, null))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.SignReplacement(fixture.Device, wrongCurve, rendezvous, guid, nonce, null))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.SignReplacement(fixture.Device, wrongType, rendezvous, guid, nonce, null))).IsTrue();

        byte[] samePayload = ReplacementPayload(rendezvous, guid, nonce, keys.Encode(fixture.Voucher.FinalOwner));
        byte[] wrongCurvePayload = ReplacementPayload(rendezvous, guid, nonce, keys.Encode(wrongCurve));
        await Assert.That(Throws<CryptographicException>(() =>
            codec.VerifyReplacement(fixture.Owner, SignPayload(fixture.Voucher.FinalOwner, samePayload), nonce))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.VerifyReplacement(fixture.Owner, SignPayload(wrongCurve, wrongCurvePayload), nonce))).IsTrue();
    }

    [Test]
    public async Task RejectsReplacementSignedByWrongKeyOrWithModifiedSignature()
    {
        using var fixture = new Fixture();
        using ECDsa owner2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var codec = new FdoTo2SetupDeviceCodec();
        byte[] nonce = ReplacementNonce();
        byte[] signed = codec.SignReplacement(
            fixture.Device, owner2, ReplacementRendezvous("rvserver.local"), ReplacementGuid(), nonce, 1300).ToArray();
        byte[] payload = ReadPayload(signed);
        byte[] modified = (byte[])signed.Clone();
        modified[^1] ^= 1;
        ReadOnlyMemory<byte> wrongSigner = SignPayload(fixture.Voucher.FinalOwner, payload);
        ReadOnlyMemory<byte> wrongDomain = SignPayload(owner2, payload, FdoSignatureOperation.TO2ProveOVHdr);

        await Assert.That(codec.VerifyReplacement(fixture.Owner, signed, nonce).MaxDeviceServiceInfoSize)
            .IsEqualTo((ushort?)1300);
        await Assert.That(Throws<CryptographicException>(() => codec.VerifyReplacement(fixture.Owner, modified, nonce))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.VerifyReplacement(fixture.Owner, wrongSigner, nonce))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.VerifyReplacement(fixture.Owner, wrongDomain, nonce))).IsTrue();
    }

    [Test]
    public async Task RejectsReplacementWithWrongOrInvalidLengthNonce()
    {
        using var fixture = new Fixture();
        using ECDsa owner2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var codec = new FdoTo2SetupDeviceCodec();
        byte[] rendezvous = ReplacementRendezvous("rvserver.local");
        byte[] guid = ReplacementGuid();
        byte[] nonce = ReplacementNonce();
        byte[] wrongNonce = (byte[])nonce.Clone();
        wrongNonce[0] ^= 1;
        ReadOnlyMemory<byte> signed = codec.SignReplacement(fixture.Device, owner2, rendezvous, guid, nonce, null);
        ReadOnlyMemory<byte> key = new FdoPublicKeyCodec().Encode(owner2);

        await Assert.That(Convert.ToHexString(codec.VerifyReplacement(fixture.Owner, signed, nonce).Nonce.Span))
            .IsEqualTo(Convert.ToHexString(nonce));
        await Assert.That(Throws<CryptographicException>(() =>
            codec.VerifyReplacement(fixture.Owner, signed, wrongNonce))).IsTrue();
        foreach (int length in new[] { 0, 15, 17 })
        {
            byte[] invalidNonce = new byte[length];
            byte[] payload = ReplacementPayload(rendezvous, guid, invalidNonce, key);
            ReadOnlyMemory<byte> signedInvalid = SignPayload(owner2, payload);
            await Assert.That(Throws<CborContentException>(() =>
                codec.SignReplacement(fixture.Device, owner2, rendezvous, guid, invalidNonce, null))).IsTrue();
            await Assert.That(Throws<CborContentException>(() =>
                codec.VerifyReplacement(fixture.Owner, signed, invalidNonce))).IsTrue();
            await Assert.That(Throws<CryptographicException>(() =>
                codec.VerifyReplacement(fixture.Owner, signedInvalid, nonce))).IsTrue();
        }
    }

    [Test]
    public async Task RejectsInvalidReplacementGuidAndRendezvous()
    {
        using var fixture = new Fixture();
        using ECDsa owner2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var codec = new FdoTo2SetupDeviceCodec();
        byte[] rendezvous = ReplacementRendezvous("rvserver.local");
        byte[] nonce = ReplacementNonce();
        ReadOnlyMemory<byte> key = new FdoPublicKeyCodec().Encode(owner2);
        byte[][] invalidGuids = [Array.Empty<byte>(), new byte[15], new byte[17], fixture.Voucher.Guid];

        foreach (byte[] guid in invalidGuids)
        {
            ReadOnlyMemory<byte> signed = SignPayload(owner2, ReplacementPayload(rendezvous, guid, nonce, key));
            await Assert.That(Throws<CborContentException>(() =>
                codec.SignReplacement(fixture.Device, owner2, rendezvous, guid, nonce, null))).IsTrue();
            await Assert.That(Throws<CborContentException>(() =>
                codec.VerifyReplacement(fixture.Owner, signed, nonce))).IsTrue();
        }

        byte[][] invalidRendezvous =
        [
            [0x80],
            [0xF6],
            ReplacementRendezvous("other.example"),
            ReplacementRendezvous("rvserver.local", ownerOnly: true),
            [0x81, 0x81, 0x82, 0x05, 0x41, 0x18],
        ];
        foreach (byte[] invalid in invalidRendezvous)
        {
            ReadOnlyMemory<byte> signed = SignPayload(owner2, ReplacementPayload(invalid, ReplacementGuid(), nonce, key));
            await Assert.That(Throws<CborContentException>(() =>
                codec.SignReplacement(fixture.Device, owner2, invalid, ReplacementGuid(), nonce, null))).IsTrue();
            await Assert.That(Throws<CborContentException>(() =>
                codec.VerifyReplacement(fixture.Owner, signed, nonce))).IsTrue();
        }
    }

    [Test]
    public async Task RejectsMalformedSignedReplacementPayload()
    {
        using var fixture = new Fixture();
        using ECDsa owner2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var codec = new FdoTo2SetupDeviceCodec();
        byte[] nonce = ReplacementNonce();
        ReadOnlyMemory<byte> key = new FdoPublicKeyCodec().Encode(owner2);
        byte[][] invalidPayloads =
        [
            [0x82, 0x01, 0xF6],
            [0x83, 0x02, 0xF6, 0xF6],
            [0x83, 0x01, 0x83, 0xF6, 0xF6, 0xF6, 0xF6],
            [0x83, 0x01, 0x84, 0x80, 0xF6, 0x40, 0xF6, 0xF6],
            [0x83, 0x01, 0x84, 0x80, 0x40, 0x40, 0xF6, 0xF6],
            [0x83, 0x01, 0x84, 0x80, 0x40, 0x40, 0xF6, 0x20],
            ReplacementPayload(ReplacementRendezvous("rvserver.local"), ReplacementGuid(), nonce, key, 65536),
        ];

        foreach (byte[] payload in invalidPayloads)
        {
            ReadOnlyMemory<byte> signed = SignPayload(owner2, payload);
            await Assert.That(Throws<CborContentException>(() =>
                codec.VerifyReplacement(fixture.Owner, signed, nonce))).IsTrue();
        }

        await Assert.That(Throws<CborContentException>(() =>
            SignPayload(owner2, [0x83, 0x01, 0xF6]))).IsTrue();
    }

    [Test]
    public async Task UntrustedDispositionDoesNotAuthenticateReplacement()
    {
        using var fixture = new Fixture();
        using ECDsa owner2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var codec = new FdoTo2SetupDeviceCodec();
        byte[] nonce = ReplacementNonce();
        byte[] signed = codec.SignReplacement(
            fixture.Device, owner2, ReplacementRendezvous("rvserver.local"), ReplacementGuid(), nonce, null).ToArray();
        signed[^1] ^= 1;

        await Assert.That(codec.ReadUntrustedDisposition(signed)).IsEqualTo(1UL);
        await Assert.That(Throws<CryptographicException>(() =>
            codec.VerifyReplacement(fixture.Owner, signed, nonce))).IsTrue();
    }

    [Test]
    public async Task ReplacementVerificationEvidenceDoesNotAliasCallerBuffers()
    {
        using var fixture = new Fixture();
        using ECDsa owner2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var codec = new FdoTo2SetupDeviceCodec();
        byte[] rendezvous = ReplacementRendezvous("rvserver.local");
        byte[] guid = ReplacementGuid();
        byte[] nonce = ReplacementNonce();
        string expectedRendezvous = Convert.ToHexString(rendezvous);
        string expectedGuid = Convert.ToHexString(guid);
        string expectedNonce = Convert.ToHexString(nonce);
        string expectedKey = Convert.ToHexString(new FdoPublicKeyCodec().Encode(owner2).Span);
        byte[] signed = codec.SignReplacement(fixture.Device, owner2, rendezvous, guid, nonce, 1300).ToArray();
        FdoTo2SetupDeviceCodec.Replacement result = codec.VerifyReplacement(fixture.Owner, signed, nonce);

        Array.Clear(rendezvous);
        Array.Clear(guid);
        Array.Clear(nonce);
        Array.Clear(signed);

        await Assert.That(Convert.ToHexString(result.RendezvousInfo.Span)).IsEqualTo(expectedRendezvous);
        await Assert.That(Convert.ToHexString(result.Guid.Span)).IsEqualTo(expectedGuid);
        await Assert.That(Convert.ToHexString(result.Nonce.Span)).IsEqualTo(expectedNonce);
        await Assert.That(Convert.ToHexString(result.OwnerKey.Span)).IsEqualTo(expectedKey);
        await Assert.That(result.MaxDeviceServiceInfoSize).IsEqualTo((ushort?)1300);
    }

    [Test]
    public async Task ReuseDispositionAcceptsSignedNoncanonicalEmbeddedEncoding()
    {
        using var fixture = new Fixture();
        var codec = new FdoTo2SetupDeviceCodec();
        // Definite array, but non-shortest encodings of disposition 2 and size 24.
        byte[] payload = [0x83, 0x18, 0x02, 0xF6, 0x19, 0x00, 0x18];
        ReadOnlyMemory<byte> signed = SignPayload(fixture.Voucher.FinalOwner, payload);

        await Assert.That(Convert.ToHexString(ReadPayload(signed))).IsEqualTo("831802F6190018");
        await Assert.That(codec.Verify(fixture.Owner, signed, true)).IsEqualTo((ushort?)24);
        await Assert.That(codec.ReadUntrustedDisposition(signed)).IsEqualTo(2UL);
    }

    private static byte[] ReplacementGuid() => Convert.FromHexString("102132435465768798A9BACBDCEDFE0F");

    private static byte[] ReplacementNonce() => Convert.FromHexString("FFEEDDCCBBAA99887766554433221100");

    private static byte[] ReplacementRendezvous(string dnsName, bool ownerOnly = false)
    {
        var dns = new CborWriter(CborConformanceMode.Canonical);
        dns.WriteTextString(dnsName);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(1);
        writer.WriteStartArray(ownerOnly ? 2 : 1);
        if (ownerOnly)
        {
            writer.WriteStartArray(2);
            writer.WriteInt32(1);
            writer.WriteByteString([0xF6]);
            writer.WriteEndArray();
        }
        writer.WriteStartArray(2);
        writer.WriteInt32(5);
        writer.WriteByteString(dns.Encode());
        writer.WriteEndArray();
        writer.WriteEndArray();
        writer.WriteEndArray();
        return writer.Encode();
    }

    private static byte[] ReplacementPayload(
        ReadOnlyMemory<byte> rendezvous,
        ReadOnlyMemory<byte> guid,
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> key,
        ulong? size = null)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteInt32(1);
        writer.WriteStartArray(4);
        writer.WriteEncodedValue(rendezvous.Span);
        writer.WriteByteString(guid.Span);
        writer.WriteByteString(nonce.Span);
        writer.WriteEncodedValue(key.Span);
        writer.WriteEndArray();
        if (size is ulong value)
        {
            writer.WriteUInt64(value);
        }
        else
        {
            writer.WriteNull();
        }
        writer.WriteEndArray();
        return writer.Encode();
    }
}
