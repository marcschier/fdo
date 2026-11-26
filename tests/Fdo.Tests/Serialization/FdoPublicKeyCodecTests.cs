using System;
using System.Formats.Asn1;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Tests.Serialization;

public sealed class FdoPublicKeyCodecTests
{
    [Test]
    [Arguments(256, 10)]
    [Arguments(384, 11)]
    public async Task EncodesHostPublicKeysAsFdoSubjectPublicKeyInfo(int curveSize, int expectedType)
    {
        using ECDsa privateKey = CreateKey(curveSize);
        using ECDsa publicKey = ECDsa.Create(privateKey.ExportParameters(false));
        byte[] expected = EncodeKey(expectedType, 1, publicKey.ExportSubjectPublicKeyInfo());

        ReadOnlyMemory<byte> encoded = new FdoPublicKeyCodec().Encode(publicKey);

        await Assert.That(encoded.Span.SequenceEqual(expected)).IsTrue();
    }

    [Test]
    public async Task EncodingRejectsNullAndUnsupportedCurves()
    {
        using ECDsa unsupported = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var codec = new FdoPublicKeyCodec();

        await Assert.That(Throws<ArgumentNullException>(() => codec.Encode(null!))).IsTrue();
        await Assert.That(Throws<NotSupportedException>(() => codec.Encode(unsupported))).IsTrue();
    }

    [Test]
    [Arguments(256, 10, -7)]
    [Arguments(384, 11, -35)]
    public async Task RoundTripsSupportedKeysAndOwnsTheExactEncoding(
        int curveSize, int expectedType, int expectedAlgorithm)
    {
        using ECDsa key = CreateKey(curveSize);
        var codec = new FdoPublicKeyCodec();
        byte[] encoded = codec.Encode(key).ToArray();
        string original = Convert.ToHexString(encoded);
        using FdoPublicKeyCodec.DecodedKey decoded = codec.Decode(encoded);
        using FdoPublicKeyCodec.DecodedKey sameKey = codec.Decode(codec.Encode(key));
        encoded[^1] ^= 0x01;

        await Assert.That(decoded.KeyType).IsEqualTo(expectedType);
        await Assert.That((int)decoded.Algorithm).IsEqualTo(expectedAlgorithm);
        await Assert.That(Convert.ToHexString(decoded.Encoded.Span)).IsEqualTo(original);
        await Assert.That(decoded.HasSamePublicKey(sameKey)).IsTrue();
    }

    [Test]
    public async Task RejectsMalformedTrailingAndMismatchedSubjectPublicKeyInfo()
    {
        using ECDsa p256 = CreateKey(256);
        using ECDsa p384 = CreateKey(384);
        var codec = new FdoPublicKeyCodec();
        byte[] p256Spki = p256.ExportSubjectPublicKeyInfo();
        byte[] nonDerSpki = [0x30, 0x81, p256Spki[1], .. p256Spki[2..]];

        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(10, 1, [0x30, 0x01, 0x00])))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(10, 1, [.. p256Spki, 0x00])))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(10, 1, nonDerSpki)))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(10, 1, p384.ExportSubjectPublicKeyInfo())))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(11, 1, p256Spki)))).IsTrue();
    }

    [Test]
    public async Task RejectsUnsupportedTypesEncodingsAndMalformedFields()
    {
        using ECDsa key = CreateKey(256);
        var codec = new FdoPublicKeyCodec();
        byte[] spki = key.ExportSubjectPublicKeyInfo();

        await Assert.That(Throws<NotSupportedException>(() => codec.Decode(EncodeKey(9, 1, spki)))).IsTrue();
        await Assert.That(Throws<NotSupportedException>(() => codec.Decode(EncodeKey(10, 3, spki)))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.Decode(EncodeKey(10, 2, spki)))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.Decode(Convert.FromHexString("820A01")))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.Decode(Convert.FromHexString("83200140")))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.Decode(Convert.FromHexString("830A0180")))).IsTrue();
    }

    [Test]
    [Arguments(256, false)]
    [Arguments(384, true)]
    public async Task X5ChainPreservesTheExactEncodingButComparesOnlyTheLeafKey(int curve, bool multiple)
    {
        using ECDsa leafKey = CreateKey(curve);
        using ECDsa unrelatedKey = CreateKey(curve);
        using X509Certificate2 leaf = CreateKeyCertificate(leafKey);
        using X509Certificate2 unrelated = CreateKeyCertificate(unrelatedKey, ca: true);
        var codec = new FdoPublicKeyCodec();
        ReadOnlyMemory<byte>[] chain = multiple ? [leaf.RawData, unrelated.RawData] : [leaf.RawData];
        byte[] expected = EncodeChainKey(curve == 256 ? 10 : 11, chain);
        byte[] encoded = codec.EncodeCertificateChain(chain).ToArray();
        await Assert.That(encoded.AsSpan().SequenceEqual(expected)).IsTrue();
        using FdoPublicKeyCodec.DecodedKey decoded = codec.Decode(encoded);
        using FdoPublicKeyCodec.DecodedKey same = codec.Decode(codec.Encode(leafKey));
        using FdoPublicKeyCodec.DecodedKey other = codec.Decode(codec.Encode(unrelatedKey));
        Array.Clear(encoded);
        await Assert.That(decoded.Encoded.Span.SequenceEqual(expected)).IsTrue();
        await Assert.That(decoded.HasSamePublicKey(same)).IsTrue();
        await Assert.That(decoded.HasSamePublicKey(other)).IsFalse();
    }

    [Test]
    public async Task X5ChainDoesNotUseLaterCertificatesOrTreatACaAsAnOwner()
    {
        using ECDsa p256 = CreateKey(256);
        using ECDsa p384 = CreateKey(384);
        using X509Certificate2 leaf256 = CreateKeyCertificate(p256);
        using X509Certificate2 leaf384 = CreateKeyCertificate(p384);
        using X509Certificate2 ca256 = CreateKeyCertificate(p256, ca: true);
        var codec = new FdoPublicKeyCodec();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeChainKey(10, [leaf384.RawData, leaf256.RawData])))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeChainKey(10, [new byte[] { 0x30, 0x00 }, leaf256.RawData])))).IsTrue();
        await Assert.That(Throws<NotSupportedException>(() =>
            codec.Decode(EncodeChainKey(10, [ca256.RawData, leaf256.RawData])))).IsTrue();
        await Assert.That(Throws<NotSupportedException>(() =>
            codec.Decode(EncodeChainKey(5, [leaf256.RawData])))).IsTrue();
    }

    private static X509Certificate2 CreateKeyCertificate(ECDsa key, bool ca = false)
    {
        var request = new CertificateRequest("CN=FDO test key", key,
            key.KeySize == 384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static byte[] EncodeChainKey(int keyType, ReadOnlyMemory<byte>[] certificates)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteInt32(keyType);
        writer.WriteInt32(2);
        writer.WriteEncodedValue(new FdoX5ChainCodec().Encode(certificates).Span);
        writer.WriteEndArray();
        return writer.Encode();
    }

    [Test]
    public async Task ComparesPublicPointsAndRejectsDifferentKeysAndCurves()
    {
        using ECDsa first = CreateKey(256);
        using ECDsa second = CreateKey(256);
        using ECDsa differentCurve = CreateKey(384);
        var codec = new FdoPublicKeyCodec();
        using FdoPublicKeyCodec.DecodedKey firstPublic = codec.Decode(codec.Encode(first));
        using FdoPublicKeyCodec.DecodedKey samePublic = codec.Decode(codec.Encode(first));
        using FdoPublicKeyCodec.DecodedKey secondPublic = codec.Decode(codec.Encode(second));
        using FdoPublicKeyCodec.DecodedKey otherCurvePublic = codec.Decode(codec.Encode(differentCurve));

        await Assert.That(firstPublic.HasSamePublicKey(samePublic)).IsTrue();
        await Assert.That(firstPublic.HasSamePublicKey(secondPublic)).IsFalse();
        await Assert.That(firstPublic.HasSamePublicKey(otherCurvePublic)).IsFalse();
    }

    [Test]
    [Arguments(256, -7)]
    [Arguments(384, -35)]
    public async Task VerifiesTheSignedPayloadOnlyForItsKeyAndOperation(int curveSize, int algorithm)
    {
        using ECDsa signer = CreateKey(curveSize);
        using ECDsa otherSigner = CreateKey(curveSize);
        var keys = new FdoPublicKeyCodec();
        using FdoPublicKeyCodec.DecodedKey publicKey = keys.Decode(keys.Encode(signer));
        var signatures = new FdoCoseSign1Codec();
        byte[] payload = [0x82, 0x01, 0x02];
        byte[] signed = signatures.Sign(
            FdoSignatureOperation.OVEntry, (FdoCoseSignatureAlgorithm)algorithm, signer, payload).ToArray();
        byte[] wrongSigner = signatures.Sign(
            FdoSignatureOperation.OVEntry, (FdoCoseSignatureAlgorithm)algorithm, otherSigner, payload).ToArray();

        ReadOnlyMemory<byte> verified = publicKey.VerifySignature(
            signatures, FdoSignatureOperation.OVEntry, signed);

        await Assert.That(Convert.ToHexString(verified.Span)).IsEqualTo("820102");
        await Assert.That(Throws<CryptographicException>(() => publicKey.VerifySignature(
            signatures, FdoSignatureOperation.TO0OwnerSign, signed))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => publicKey.VerifySignature(
            signatures, FdoSignatureOperation.OVEntry, wrongSigner))).IsTrue();
    }

    [Test]
    [Arguments(2048, false, 5, -257)]
    [Arguments(2048, true, 1, -257)]
    [Arguments(3072, false, 5, -258)]
    public async Task RoundTripsAndVerifiesSupportedRsaKeys(
        int keySize, bool restricted, int expectedType, int expectedAlgorithm)
    {
        using RSA key = RSA.Create(keySize);
        using RSA other = RSA.Create(keySize);
        var codec = new FdoPublicKeyCodec();
        byte[] encoded = codec.EncodeRsa(key, restricted).ToArray();
        byte[] expectedEncoding = (byte[])encoded.Clone();
        using FdoPublicKeyCodec.DecodedKey decoded = codec.Decode(encoded);
        using FdoPublicKeyCodec.DecodedKey same = codec.Decode(codec.EncodeRsa(key, restricted));
        using FdoPublicKeyCodec.DecodedKey different = codec.Decode(codec.EncodeRsa(other, restricted));
        Array.Fill(encoded, (byte)0);
        var signatures = new FdoCoseSign1Codec();
        byte[] signed = signatures.Sign(
            FdoSignatureOperation.OVEntry, (FdoCoseSignatureAlgorithm)expectedAlgorithm,
            key, new byte[] { 0x82, 0x01, 0x02 }).ToArray();

        ReadOnlyMemory<byte> verified = decoded.VerifySignature(
            signatures, FdoSignatureOperation.OVEntry, signed);

        await Assert.That(decoded.KeyType).IsEqualTo(expectedType);
        await Assert.That((int)decoded.Algorithm).IsEqualTo(expectedAlgorithm);
        await Assert.That(decoded.Encoded.Span.SequenceEqual(expectedEncoding)).IsTrue();
        await Assert.That(decoded.HasSamePublicKey(same)).IsTrue();
        await Assert.That(decoded.HasSamePublicKey(different)).IsFalse();
        await Assert.That(Convert.ToHexString(verified.Span)).IsEqualTo("820102");
        await Assert.That(Throws<CryptographicException>(() => different.VerifySignature(
            signatures, FdoSignatureOperation.OVEntry, signed))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => decoded.VerifySignature(
            signatures, FdoSignatureOperation.TO0OwnerSign, signed))).IsTrue();
    }

    [Test]
    public async Task RejectsRsaKeySizesAndRestrictedExponentViolations()
    {
        using RSA tooSmall = RSA.Create(1024);
        using RSA rsa2048 = RSA.Create(2048);
        using RSA rsa3072 = RSA.Create(3072);
        RSAParameters withExponentThree = rsa2048.ExportParameters(false);
        withExponentThree.Exponent = [3];
        using RSA exponentThree = RSA.Create();
        exponentThree.ImportParameters(withExponentThree);
        var codec = new FdoPublicKeyCodec();
        using FdoPublicKeyCodec.DecodedKey unrestricted = codec.Decode(codec.EncodeRsa(exponentThree));

        await Assert.That(unrestricted.KeyType).IsEqualTo(5);
        await Assert.That(Throws<ArgumentNullException>(() => codec.EncodeRsa(null!))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.EncodeRsa(tooSmall))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.EncodeRsa(rsa3072, restricted: true))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.EncodeRsa(exponentThree, restricted: true))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(1, 1, exponentThree.ExportSubjectPublicKeyInfo())))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(1, 1, rsa3072.ExportSubjectPublicKeyInfo())))).IsTrue();
    }

    [Test]
    public async Task RejectsNonDerOrMismatchedRsaSubjectPublicKeyInfo()
    {
        using RSA rsa = RSA.Create(2048);
        using ECDsa ec = CreateKey(256);
        var codec = new FdoPublicKeyCodec();
        byte[] spki = rsa.ExportSubjectPublicKeyInfo();
        byte[] rsaPublicKey = rsa.ExportRSAPublicKey();

        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(5, 1, [.. spki, 0])))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(5, 1, ec.ExportSubjectPublicKeyInfo())))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(5, 1, EncodeRsaSpki("1.2.840.113549.1.1.10", true, rsaPublicKey))))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(5, 1, EncodeRsaSpki("1.2.840.113549.1.1.1", false, rsaPublicKey))))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decode(EncodeKey(5, 1, EncodeRsaSpki("1.2.840.113549.1.1.1", true, [.. rsaPublicKey, 0]))))).IsTrue();
    }

    private static byte[] EncodeRsaSpki(string oid, bool includeNull, byte[] rsaPublicKey)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier(oid);
        if (includeNull)
        {
            writer.WriteNull();
        }

        writer.PopSequence();
        writer.WriteBitString(rsaPublicKey);
        writer.PopSequence();
        return writer.Encode();
    }

    private static ECDsa CreateKey(int curveSize) => ECDsa.Create(
        curveSize == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);

    private static byte[] EncodeKey(int keyType, int encoding, ReadOnlySpan<byte> key)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteInt32(keyType);
        writer.WriteInt32(encoding);
        writer.WriteByteString(key);
        writer.WriteEndArray();
        return writer.Encode();
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
