using System;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Ownership;
using Fdo.Serialization;
using AuthenticationFixture = Fdo.Tests.Cryptography.FdoTo2OwnerDeviceAuthenticatorTests.Fixture;
using VoucherFixture = Fdo.Tests.Cryptography.FdoOwnershipVoucherChainVerifierTests.VoucherFixture;

namespace Fdo.Tests.Serialization;

public sealed class FdoTo2OwnerProofCodecTests
{
    private static readonly byte[] OwnerNonce = Convert.FromHexString("303132333435363738393A3B3C3D3E3F");

    [Test]
    [Arguments(256, 0, 5)]
    [Arguments(384, 1, 6)]
    public async Task VerifiesTheSignedProofDeviceAnchorsAndOrderedVoucherBeforeReleasingParameters(
        int curveSize, int exchangeValue, int hmacValue)
    {
        var exchange = (FdoKeyExchangeSuite)exchangeValue;
        using var fixture = new VoucherFixture(curveSize, (FdoHashAlgorithm)hmacValue);
        using FdoEcdhKeyExchange keyExchange = FdoEcdhKeyExchange.Create(exchange, FdoEcdhParty.Owner);
        var codec = new FdoTo2OwnerProofCodec();
        byte[] parameter = keyExchange.ExportParameter();
        byte[] expectedParameter = (byte[])parameter.Clone();
        byte[] proof = codec.Sign(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, 2, OwnerNonce,
            exchange, parameter, 4096, fixture.FinalOwner).ToArray();
        using FdoTo2OwnerProofCodec.PendingOwnerProof pending = Begin(codec, fixture, proof, exchange);

        Array.Fill(proof, (byte)0);
        Array.Fill(parameter, (byte)0);
        pending.AppendEntry(0, fixture.FirstEntry);
        pending.AppendEntry(1, fixture.SecondEntry);
        FdoTo2OwnerProofCodec.OwnerProof result = pending.CompleteDeviceChecks();

        await Assert.That(pending.EntryCount).IsEqualTo(2);
        await Assert.That(Convert.ToHexString(result.OwnerKey.Span))
            .IsEqualTo(Convert.ToHexString(fixture.FinalOwnerKey));
        await Assert.That(Convert.ToHexString(result.OwnerParameter.Span))
            .IsEqualTo(Convert.ToHexString(expectedParameter));
        await Assert.That(result.MaxOwnerMessageSize).IsEqualTo((ushort)4096);
        await Assert.That(Throws<ObjectDisposedException>(() =>
            pending.AppendEntry(1, fixture.SecondEntry))).IsTrue();
    }

    [Test]
    public async Task RejectsAZeroEntryVoucherForPairedOnboarding()
    {
        using var fixture = new VoucherFixture();
        using FdoEcdhKeyExchange exchange = FdoEcdhKeyExchange.Create(
            FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Owner);
        var codec = new FdoTo2OwnerProofCodec();
        byte[] parameter = exchange.ExportParameter();
        byte[] proof = CreateSignedProof(fixture, parameter, entryCount: 0);

        await Assert.That(Throws<ArgumentOutOfRangeException>(() => codec.Sign(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, 0, OwnerNonce,
            FdoKeyExchangeSuite.Ecdh256, parameter, ushort.MaxValue, fixture.Manufacturer))).IsTrue();
        await Assert.That(Rejects<CborContentException>(codec, fixture, proof)).IsTrue();
    }

    [Test]
    public async Task RejectsChangedSignaturesWrongDomainsAndAnIncorrectAdvertisedKey()
    {
        using var fixture = new VoucherFixture();
        using FdoEcdhKeyExchange exchange = FdoEcdhKeyExchange.Create(
            FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Owner);
        byte[] parameter = exchange.ExportParameter();
        var codec = new FdoTo2OwnerProofCodec();
        byte[] proof = codec.Sign(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, 2, OwnerNonce,
            FdoKeyExchangeSuite.Ecdh256, parameter, 4096, fixture.FinalOwner).ToArray();
        byte[] changedSignature = (byte[])proof.Clone();
        changedSignature[^1] ^= 0x01;
        byte[] wrongDomain = CreateSignedProof(
            fixture, parameter, operation: FdoSignatureOperation.TO0OwnerSign);
        byte[] differentAdvertisedKey = CreateSignedProof(
            fixture, parameter, advertisedKey: fixture.FirstOwnerKey);

        await Assert.That(Rejects<CryptographicException>(codec, fixture, changedSignature)).IsTrue();
        await Assert.That(Rejects<CryptographicException>(codec, fixture, wrongDomain)).IsTrue();
        await Assert.That(Rejects<CryptographicException>(codec, fixture, differentAdvertisedKey)).IsTrue();
    }

    [Test]
    public async Task RejectsWrongChallengeAndEachDeviceCredentialAnchor()
    {
        using var fixture = new VoucherFixture();
        using FdoEcdhKeyExchange exchange = FdoEcdhKeyExchange.Create(
            FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Owner);
        var codec = new FdoTo2OwnerProofCodec();
        byte[] proof = codec.Sign(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, 2, OwnerNonce,
            FdoKeyExchangeSuite.Ecdh256, exchange.ExportParameter(), 4096, fixture.FinalOwner).ToArray();
        byte[] wrongNonce = (byte[])OwnerNonce.Clone();
        wrongNonce[0] ^= 1;
        byte[] wrongGuid = (byte[])fixture.Guid.Clone();
        wrongGuid[0] ^= 1;
        byte[] wrongSecret = (byte[])fixture.Secret.Clone();
        wrongSecret[0] ^= 1;
        byte[] wrongHashBytes = fixture.ManufacturerHash.Value;
        wrongHashBytes[0] ^= 1;
        var wrongHash = new FdoHashValue(fixture.ManufacturerHash.Algorithm, wrongHashBytes);

        await Assert.That(Throws<CryptographicException>(() =>
        {
            using var pending = codec.BeginDeviceVerification(
                proof, wrongNonce, FdoKeyExchangeSuite.Ecdh256, fixture.Guid,
                fixture.ManufacturerHash, fixture.HmacAlgorithm, fixture.Secret);
        })).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
        {
            using var pending = codec.BeginDeviceVerification(
                proof, OwnerNonce, FdoKeyExchangeSuite.Ecdh256, wrongGuid,
                fixture.ManufacturerHash, fixture.HmacAlgorithm, fixture.Secret);
        })).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
        {
            using var pending = codec.BeginDeviceVerification(
                proof, OwnerNonce, FdoKeyExchangeSuite.Ecdh256, fixture.Guid,
                wrongHash, fixture.HmacAlgorithm, fixture.Secret);
        })).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
        {
            using var pending = codec.BeginDeviceVerification(
                proof, OwnerNonce, FdoKeyExchangeSuite.Ecdh256, fixture.Guid,
                fixture.ManufacturerHash, fixture.HmacAlgorithm, wrongSecret);
        })).IsTrue();
    }

    [Test]
    public async Task NeverReleasesParametersForAnIncompleteInvalidOrMismatchedVoucher()
    {
        using var fixture = new VoucherFixture();
        using FdoEcdhKeyExchange exchange = FdoEcdhKeyExchange.Create(
            FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Owner);
        byte[] parameter = exchange.ExportParameter();
        var codec = new FdoTo2OwnerProofCodec();
        byte[] proof = codec.Sign(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, 2, OwnerNonce,
            FdoKeyExchangeSuite.Ecdh256, parameter, 4096, fixture.FinalOwner).ToArray();
        byte[] proofFromEarlierOwner = codec.Sign(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, 2, OwnerNonce,
            FdoKeyExchangeSuite.Ecdh256, parameter, 4096, fixture.FirstOwner).ToArray();
        byte[] changedEntry = (byte[])fixture.FirstEntry.Clone();
        changedEntry[^1] ^= 1;
        using FdoTo2OwnerProofCodec.PendingOwnerProof incomplete = Begin(codec, fixture, proof);
        using FdoTo2OwnerProofCodec.PendingOwnerProof invalid = Begin(codec, fixture, proof);
        using FdoTo2OwnerProofCodec.PendingOwnerProof mismatch = Begin(codec, fixture, proofFromEarlierOwner);

        incomplete.AppendEntry(0, fixture.FirstEntry);
        mismatch.AppendEntry(0, fixture.FirstEntry);
        mismatch.AppendEntry(1, fixture.SecondEntry);

        await Assert.That(Throws<InvalidOperationException>(() => incomplete.CompleteDeviceChecks())).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() =>
            incomplete.AppendEntry(1, fixture.SecondEntry))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => invalid.AppendEntry(0, changedEntry))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => invalid.CompleteDeviceChecks())).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => mismatch.CompleteDeviceChecks())).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => mismatch.CompleteDeviceChecks())).IsTrue();
    }

    [Test]
    public async Task RejectsUnsupportedDelegationMalformedFieldsAndOwnerSuiteMismatch()
    {
        using var fixture = new VoucherFixture();
        using FdoEcdhKeyExchange exchange = FdoEcdhKeyExchange.Create(
            FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Owner);
        using FdoEcdhKeyExchange otherExchange = FdoEcdhKeyExchange.Create(
            FdoKeyExchangeSuite.Ecdh384, FdoEcdhParty.Owner);
        byte[] parameter = exchange.ExportParameter();
        byte[] malformedParameter = (byte[])parameter.Clone();
        malformedParameter[1] ^= 1;
        var codec = new FdoTo2OwnerProofCodec();
        byte[] delegated = CreateSignedProof(fixture, parameter, delegateValue: [0x80]);
        byte[] badNonce = CreateSignedProof(fixture, parameter, nonce: new byte[15]);
        byte[] badParameter = CreateSignedProof(fixture, malformedParameter);
        byte[] tooManyEntries = CreateSignedProof(fixture, parameter, entryCount: 256);
        byte[] tooLargeMessageSize = CreateSignedProof(fixture, parameter, maxMessageSize: 65536);
        byte[] mismatchedSuite = CreateSignedProof(fixture, otherExchange.ExportParameter());

        await Assert.That(Rejects<NotSupportedException>(codec, fixture, delegated)).IsTrue();
        await Assert.That(Rejects<CborContentException>(codec, fixture, badNonce)).IsTrue();
        await Assert.That(Rejects<CryptographicException>(codec, fixture, badParameter)).IsTrue();
        await Assert.That(Rejects<CborContentException>(codec, fixture, tooManyEntries)).IsTrue();
        await Assert.That(Rejects<CborContentException>(codec, fixture, tooLargeMessageSize)).IsTrue();
        await Assert.That(Rejects<CryptographicException>(
            codec, fixture, mismatchedSuite, FdoKeyExchangeSuite.Ecdh384)).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.Sign(
            fixture.HeaderTag, fixture.EncodedHeaderHmac, 2, OwnerNonce,
            FdoKeyExchangeSuite.Ecdh384, otherExchange.ExportParameter(), 4096, fixture.FinalOwner))).IsTrue();
    }

    [Test]
    [Arguments(2, 2048, false, 256)]
    [Arguments(2, 2048, true, 256)]
    [Arguments(3, 3072, false, 384)]
    [Arguments(4, 2048, false, 32)]
    [Arguments(4, 2048, true, 32)]
    [Arguments(5, 3072, false, 96)]
    public async Task VerifiesRsaOwnerProofAndRoleSpecificParameterWidths(
        int suiteValue, int keySize, bool restricted, int expectedLength)
    {
        var suite = (FdoKeyExchangeSuite)suiteValue;
        using var fixture = new AuthenticationFixture();
        using RSA manufacturer = RSA.Create(keySize);
        using RSA ownerKey = RSA.Create(keySize);
        FdoTransferredOwnershipVoucher voucher = fixture.CreateRsaVoucher(manufacturer, ownerKey, restricted);
        var keys = new FdoPublicKeyCodec();
        FdoHashValue manufacturerHash = FdoHashValue.ComputeDigest(
            FdoHashAlgorithm.Sha256, keys.EncodeRsa(manufacturer, restricted).Span);
        byte[] parameter = new byte[expectedLength];
        parameter[0] = 0x7f;
        parameter[^1] = 0xa5;
        var codec = new FdoTo2OwnerProofCodec();
        byte[] proof = codec.Sign(
            voucher.EncodedVoucherHeaderTag, voucher.EncodedVoucherHeaderHmac,
            voucher.EncodedVoucherEntries.Count, OwnerNonce, suite, parameter, 4096, ownerKey).ToArray();

        using FdoTo2OwnerProofCodec.PendingOwnerProof pending = codec.BeginDeviceVerification(
            proof, OwnerNonce, suite, fixture.Voucher.Guid, manufacturerHash,
            fixture.Voucher.HmacAlgorithm, fixture.Voucher.Secret);
        pending.AppendEntry(0, voucher.EncodedVoucherEntries[0]);
        FdoTo2OwnerProofCodec.OwnerProof verified = pending.CompleteDeviceChecks();

        await Assert.That(verified.OwnerKey.Span.SequenceEqual(keys.EncodeRsa(ownerKey, restricted).Span)).IsTrue();
        await Assert.That(verified.OwnerParameter.Span.SequenceEqual(parameter)).IsTrue();
        foreach (byte[] invalid in new[] { new byte[expectedLength - 1], new byte[expectedLength + 1] })
        {
            byte[] signed = CreateSignedRsaProof(voucher, ownerKey, restricted, invalid);
            await Assert.That(Throws<CryptographicException>(() =>
            {
                using var rejected = codec.BeginDeviceVerification(
                    signed, OwnerNonce, suite, fixture.Voucher.Guid, manufacturerHash,
                    fixture.Voucher.HmacAlgorithm, fixture.Voucher.Secret);
            })).IsTrue();
            await Assert.That(Throws<CryptographicException>(() => codec.Sign(
                voucher.EncodedVoucherHeaderTag, voucher.EncodedVoucherHeaderHmac,
                voucher.EncodedVoucherEntries.Count, OwnerNonce, suite, invalid, 4096, ownerKey))).IsTrue();
        }
    }

    [Test]
    [Arguments(2, 3072)]
    [Arguments(3, 2048)]
    [Arguments(4, 3072)]
    [Arguments(5, 2048)]
    public async Task RejectsOwnerKeysIncompatibleWithTheSelectedRsaExchange(int suiteValue, int wrongKeySize)
    {
        var suite = (FdoKeyExchangeSuite)suiteValue;
        using RSA wrongSize = RSA.Create(wrongKeySize);
        using ECDsa wrongType = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keys = new FdoPublicKeyCodec();
        using FdoPublicKeyCodec.DecodedKey rsa = keys.Decode(keys.EncodeRsa(wrongSize));
        using FdoPublicKeyCodec.DecodedKey ec = keys.Decode(keys.Encode(wrongType));

        await Assert.That(Throws<CryptographicException>(() =>
            FdoTo2OwnerProofCodec.RequireOwnerSuite(suite, rsa))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            FdoTo2OwnerProofCodec.RequireOwnerSuite(suite, ec))).IsTrue();
    }

    private static byte[] CreateSignedRsaProof(
        FdoTransferredOwnershipVoucher voucher, RSA ownerKey, bool restricted, byte[] parameter)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(8);
        writer.WriteEncodedValue(voucher.EncodedVoucherHeaderTag.Span);
        writer.WriteInt32(voucher.EncodedVoucherEntries.Count);
        writer.WriteEncodedValue(voucher.EncodedVoucherHeaderHmac.Span);
        writer.WriteByteString(OwnerNonce);
        writer.WriteByteString(parameter);
        writer.WriteInt32(4096);
        writer.WriteEncodedValue(new FdoPublicKeyCodec().EncodeRsa(ownerKey, restricted).Span);
        writer.WriteNull();
        writer.WriteEndArray();
        return new FdoCoseSign1Codec().Sign(
            FdoSignatureOperation.TO2ProveOVHdr,
            ownerKey.KeySize == 2048 ? FdoCoseSignatureAlgorithm.RS256 : FdoCoseSignatureAlgorithm.RS384,
            ownerKey, writer.Encode()).ToArray();
    }

    private static FdoTo2OwnerProofCodec.PendingOwnerProof Begin(
        FdoTo2OwnerProofCodec codec,
        VoucherFixture fixture,
        ReadOnlyMemory<byte> proof,
        FdoKeyExchangeSuite exchange = FdoKeyExchangeSuite.Ecdh256) =>
        codec.BeginDeviceVerification(
            proof, OwnerNonce, exchange, fixture.Guid, fixture.ManufacturerHash,
            fixture.HmacAlgorithm, fixture.Secret);

    private static bool Rejects<TException>(
        FdoTo2OwnerProofCodec codec,
        VoucherFixture fixture,
        ReadOnlyMemory<byte> proof,
        FdoKeyExchangeSuite exchange = FdoKeyExchangeSuite.Ecdh256)
        where TException : Exception =>
        Throws<TException>(() =>
        {
            using FdoTo2OwnerProofCodec.PendingOwnerProof pending = Begin(codec, fixture, proof, exchange);
        });

    private static byte[] CreateSignedProof(
        VoucherFixture fixture,
        ReadOnlyMemory<byte> parameter,
        byte[]? nonce = null,
        int entryCount = 2,
        int maxMessageSize = 4096,
        ReadOnlyMemory<byte>? advertisedKey = null,
        byte[]? delegateValue = null,
        FdoSignatureOperation operation = FdoSignatureOperation.TO2ProveOVHdr)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(8);
        writer.WriteEncodedValue(fixture.HeaderTag);
        writer.WriteInt32(entryCount);
        writer.WriteEncodedValue(fixture.EncodedHeaderHmac);
        writer.WriteByteString(nonce ?? OwnerNonce);
        writer.WriteByteString(parameter.Span);
        writer.WriteInt32(maxMessageSize);
        writer.WriteEncodedValue((advertisedKey ?? fixture.FinalOwnerKey).Span);
        writer.WriteEncodedValue(delegateValue ?? [0xF6]);
        writer.WriteEndArray();
        return new FdoCoseSign1Codec().Sign(
            operation, FdoCoseSignatureAlgorithm.ES256, fixture.FinalOwner, writer.Encode()).ToArray();
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
