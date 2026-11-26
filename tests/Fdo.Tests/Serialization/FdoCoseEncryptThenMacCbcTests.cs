using System;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Tests.Serialization;

[UnsupportedOSPlatform("browser")]
public sealed class FdoCoseEncryptThenMacCbcTests
{
    private const int Suite128 = -17760703;
    private const int Suite256 = -17760705;
    private static readonly byte[] Iv = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");

    [Test]
    [Arguments(Suite128, 32, 16, 5, 32, 0)]
    [Arguments(Suite128, 32, 16, 5, 32, 16)]
    [Arguments(Suite256, 64, 32, 6, 48, 0)]
    [Arguments(Suite256, 64, 32, 6, 48, 16)]
    public async Task Encrypt_MatchesIndependentCbcEtmEnvelope(
        int suiteValue, int svkLength, int sekLength, int macType, int tagLength, int contentLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        var namedSuite = suiteValue == Suite128
            ? FdoCoseAeadAlgorithm.AesCbc128HmacSha256
            : FdoCoseAeadAlgorithm.AesCbc256HmacSha384;
        await Assert.That((int)namedSuite).IsEqualTo(suiteValue);
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(contentLength);
        byte[] originalPlaintext = (byte[])plaintext.Clone();
        byte[] ciphertext = ReferenceEncrypt(sek, Iv, plaintext);
        byte[] inner = EtmEnvelope.Encrypt0(EtmEnvelope.Protected(suiteValue), Iv, ciphertext);
        byte[] expected = EtmEnvelope.Mac0(macType, svk, EtmEnvelope.Protected(macType), inner);
        var codec = new FdoCoseEncryptThenMacCodec();

        ReadOnlyMemory<byte> actual = codec.Encrypt(suite, svk, sek, Iv, plaintext);
        await Assert.That(actual.Span.SequenceEqual(expected)).IsTrue();
        await Assert.That(plaintext.AsSpan().SequenceEqual(originalPlaintext)).IsTrue();

        var actualOuter = ReadOuter(actual.ToArray());
        var expectedOuter = ReadOuter(expected);
        await Assert.That(actualOuter.Protected.AsSpan().SequenceEqual(EtmEnvelope.Protected(macType))).IsTrue();
        await Assert.That(actualOuter.Payload.AsSpan().SequenceEqual(inner)).IsTrue();
        await Assert.That(actualOuter.Tag.Length).IsEqualTo(tagLength);
        await Assert.That(actualOuter.Tag.AsSpan().SequenceEqual(expectedOuter.Tag)).IsTrue();

        var actualInner = ReadInner(actualOuter.Payload);
        await Assert.That(actualInner.Protected.AsSpan().SequenceEqual(EtmEnvelope.Protected(suiteValue))).IsTrue();
        await Assert.That(actualInner.Iv.AsSpan().SequenceEqual(Iv)).IsTrue();
        await Assert.That(actualInner.Ciphertext.AsSpan().SequenceEqual(ciphertext)).IsTrue();

        FdoCoseEncryptThenMacCodec.AuthenticatedMessage message = codec.VerifyAndParse(suite, svk, actual);
        await Assert.That(message.CounterBlock.AsSpan().SequenceEqual(Iv)).IsTrue();
        await Assert.That(message.Ciphertext.AsSpan().SequenceEqual(ciphertext)).IsTrue();
        await Assert.That(codec.Decrypt(suite, sek, message).AsSpan().SequenceEqual(plaintext)).IsTrue();
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5, 32)]
    [Arguments(Suite256, 64, 32, 6, 48)]
    public async Task VerifyAndParse_AuthenticatesEveryPayloadAndMacByte(
        int suiteValue, int svkLength, int sekLength, int macType, int tagLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(20);
        byte[] ciphertext = ReferenceEncrypt(sek, Iv, plaintext);
        byte[] inner = EtmEnvelope.Encrypt0(EtmEnvelope.Protected(suiteValue), Iv, ciphertext);
        byte[] encoded = EtmEnvelope.Mac0(macType, svk, EtmEnvelope.Protected(macType), inner);
        var outer = ReadOuter(encoded);
        var codec = new FdoCoseEncryptThenMacCodec();
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage valid = codec.VerifyAndParse(suite, svk, encoded);
        await Assert.That(valid.Ciphertext.AsSpan().SequenceEqual(ciphertext)).IsTrue();
        await Assert.That(outer.Tag.Length).IsEqualTo(tagLength);

        // Offsets come from the CBOR reader, not a search for byte values.
        for (int i = 0; i < outer.Payload.Length; i++)
        {
            byte[] tampered = (byte[])encoded.Clone();
            tampered[outer.PayloadOffset + i] ^= 0x01;
            await Assert.That(Throws<CryptographicException>(() =>
                codec.VerifyAndParse(suite, svk, tampered))).IsTrue();
        }

        for (int i = 0; i < outer.Tag.Length; i++)
        {
            byte[] tampered = (byte[])encoded.Clone();
            tampered[outer.TagOffset + i] ^= 0x01;
            await Assert.That(Throws<CryptographicException>(() =>
                codec.VerifyAndParse(suite, svk, tampered))).IsTrue();
        }

        byte[] wrongFirstByte = (byte[])svk.Clone();
        wrongFirstByte[0] ^= 0x80;
        byte[] wrongLastByte = (byte[])svk.Clone();
        wrongLastByte[^1] ^= 0x80;
        await Assert.That(Throws<CryptographicException>(() =>
            codec.VerifyAndParse(suite, wrongFirstByte, encoded))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.VerifyAndParse(suite, wrongLastByte, encoded))).IsTrue();
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5, 32)]
    [Arguments(Suite256, 64, 32, 6, 48)]
    public async Task VerifyAndParse_AuthenticatesBeforeParsingInner(
        int suiteValue, int svkLength, int sekLength, int macType, int tagLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, _) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] signed = EtmEnvelope.Mac0(macType, svk, EtmEnvelope.Protected(macType), [0x00]);
        var outer = ReadOuter(signed);
        var codec = new FdoCoseEncryptThenMacCodec();
        await Assert.That(outer.Tag.Length).IsEqualTo(tagLength);

        foreach (int index in new[] { tagLength - 2, tagLength - 1 })
        {
            byte[] corrupt = (byte[])signed.Clone();
            corrupt[outer.TagOffset + index] ^= 0x01;
            await Assert.That(Throws<CryptographicException>(() =>
                codec.VerifyAndParse(suite, svk, corrupt))).IsTrue();
        }

        foreach (int retained in new[] { 0, tagLength - 2, tagLength - 1 })
        {
            byte[] truncated = EncodeOuter(outer.Protected, outer.Payload, outer.Tag[..retained]);
            await Assert.That(Throws<CryptographicException>(() =>
                codec.VerifyAndParse(suite, svk, truncated))).IsTrue();
        }

        byte[] extendedTag = new byte[tagLength + 1];
        outer.Tag.CopyTo(extendedTag, 0);
        byte[] extended = EncodeOuter(outer.Protected, outer.Payload, extendedTag);
        await Assert.That(Throws<CryptographicException>(() =>
            codec.VerifyAndParse(suite, svk, extended))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            codec.VerifyAndParse(suite, svk, signed))).IsTrue();
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5)]
    [Arguments(Suite256, 64, 32, 6)]
    public async Task VerifyAndParse_RejectsAuthenticatedWrongSuiteIvAndHeader(
        int suiteValue, int svkLength, int sekLength, int macType)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] ciphertext = ReferenceEncrypt(sek, Iv, FdoCoseEncryptThenMacCodecTests.Plaintext(3));
        byte[] header = EtmEnvelope.Protected(suiteValue);
        int otherSuite = suiteValue == Suite128 ? Suite256 : Suite128;
        byte[] validInner = EtmEnvelope.Encrypt0(header, Iv, ciphertext);
        byte[][] malformed =
        [
            EtmEnvelope.Encrypt0(EtmEnvelope.Protected(otherSuite), Iv, ciphertext),
            EtmEnvelope.Encrypt0(header, new byte[15], ciphertext),
            EtmEnvelope.Encrypt0(header, new byte[17], ciphertext),
            EtmEnvelope.Encrypt0(header, Iv, ciphertext, extraHeader: true),
            EtmEnvelope.Encrypt0(header, Iv, ciphertext, tagged: false),
            [.. validInner, 0x00],
        ];
        var codec = new FdoCoseEncryptThenMacCodec();
        foreach (byte[] inner in malformed)
        {
            byte[] signed = EtmEnvelope.Mac0(macType, svk, EtmEnvelope.Protected(macType), inner);
            byte[] badMac = (byte[])signed.Clone();
            badMac[^1] ^= 0x01;
            await Assert.That(Throws<CryptographicException>(() =>
                codec.VerifyAndParse(suite, svk, badMac))).IsTrue();
            await Assert.That(Throws<CborContentException>(() =>
                codec.VerifyAndParse(suite, svk, signed))).IsTrue();
        }
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5)]
    [Arguments(Suite256, 64, 32, 6)]
    public async Task VerifyAndParse_RejectsMalformedOuterHeaders(
        int suiteValue, int svkLength, int sekLength, int macType)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] ciphertext = ReferenceEncrypt(sek, Iv, FdoCoseEncryptThenMacCodecTests.Plaintext(2));
        byte[] inner = EtmEnvelope.Encrypt0(EtmEnvelope.Protected(suiteValue), Iv, ciphertext);
        int otherMacType = macType == 5 ? 6 : 5;
        byte[][] malformed =
        [
            EtmEnvelope.Mac0(otherMacType, svk, EtmEnvelope.Protected(otherMacType), inner),
            EtmEnvelope.Mac0(macType, svk, EtmEnvelope.Protected(macType), inner, extraHeader: true),
            EtmEnvelope.Mac0(macType, svk, EtmEnvelope.Protected(macType), inner, tagged: false),
        ];
        var codec = new FdoCoseEncryptThenMacCodec();
        foreach (byte[] encoded in malformed)
        {
            await Assert.That(Throws<CborContentException>(() =>
                codec.VerifyAndParse(suite, svk, encoded))).IsTrue();
        }

        byte[] valid = EtmEnvelope.Mac0(macType, svk, EtmEnvelope.Protected(macType), inner);
        await Assert.That(codec.VerifyAndParse(suite, svk, valid).Ciphertext.AsSpan().SequenceEqual(ciphertext)).IsTrue();
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5, 32)]
    [Arguments(Suite256, 64, 32, 6, 48)]
    public async Task CbcEnvelope_BudgetAndEncodingBoundaries(
        int suiteValue, int svkLength, int sekLength, int macType, int tagLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        (int Content, int Plaintext, int Ciphertext, int Inner)[] cases =
        [
            (0, 1, 16, 46),
            (14, 15, 16, 46),
            (15, 16, 32, 63),
            (16, 17, 32, 63),
            (22, 23, 32, 63),
            (23, 24, 32, 63),
            (24, 26, 32, 63),
            (221, 223, 224, 255),
            (222, 224, 240, 271),
            (237, 239, 240, 271),
            (238, 240, 256, 288),
            (255, 257, 272, 304),
            (256, 259, 272, 304),
        ];
        foreach (var item in cases)
        {
            byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(item.Content);
            byte[] ciphertext = ReferenceEncrypt(sek, Iv, plaintext);
            byte[] inner = EtmEnvelope.Encrypt0(EtmEnvelope.Protected(suiteValue), Iv, ciphertext);
            byte[] expected = EtmEnvelope.Mac0(macType, svk, EtmEnvelope.Protected(macType), inner);
            await Assert.That(plaintext.Length).IsEqualTo(item.Plaintext);
            await Assert.That(ciphertext.Length).IsEqualTo(item.Ciphertext);
            await Assert.That(inner.Length).IsEqualTo(item.Inner);
            int outerOverhead = item.Inner <= byte.MaxValue ? 11 : 12;
            await Assert.That(expected.Length).IsEqualTo(item.Inner + tagLength + outerOverhead);

            var exact = new FdoCoseEncryptThenMacCodec(maxEncodedBytes: expected.Length);
            ReadOnlyMemory<byte> actual = exact.Encrypt(suite, svk, sek, Iv, plaintext);
            await Assert.That(actual.Length).IsEqualTo(expected.Length);
            await Assert.That(actual.Span.SequenceEqual(expected)).IsTrue();
            FdoCoseEncryptThenMacCodec.AuthenticatedMessage message = exact.VerifyAndParse(suite, svk, actual);
            await Assert.That(message.CounterBlock.AsSpan().SequenceEqual(Iv)).IsTrue();
            await Assert.That(message.Ciphertext.AsSpan().SequenceEqual(ciphertext)).IsTrue();
            await Assert.That(exact.Decrypt(suite, sek, message).AsSpan().SequenceEqual(plaintext)).IsTrue();

            var below = new FdoCoseEncryptThenMacCodec(maxEncodedBytes: expected.Length - 1);
            await Assert.That(Throws<CborContentException>(() =>
                below.Encrypt(suite, svk, sek, Iv, plaintext))).IsTrue();
            await Assert.That(Throws<CborContentException>(() =>
                below.VerifyAndParse(suite, svk, expected))).IsTrue();
        }
    }

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task KeysAndIv_RequireExactSuiteLengths(int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(7);
        var codec = new FdoCoseEncryptThenMacCodec();
        ReadOnlyMemory<byte> encoded = codec.Encrypt(suite, svk, sek, Iv, plaintext);
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage message = codec.VerifyAndParse(suite, svk, encoded);

        int[] invalidSvkLengths = svkLength == 32
            ? [0, 16, 31, 33, 64]
            : [0, 32, 48, 63, 65];
        foreach (int length in invalidSvkLengths)
        {
            byte[] invalidSvk = new byte[length];
            await Assert.That(Throws<ArgumentException>(() =>
                codec.Encrypt(suite, invalidSvk, sek, Iv, plaintext))).IsTrue();
            await Assert.That(Throws<ArgumentException>(() =>
                codec.VerifyAndParse(suite, invalidSvk, encoded))).IsTrue();
        }

        foreach (int length in new[] { 0, sekLength - 1, sekLength + 1, 24, sekLength == 16 ? 32 : 16 })
        {
            byte[] invalidSek = new byte[length];
            await Assert.That(Throws<ArgumentException>(() =>
                codec.Encrypt(suite, svk, invalidSek, Iv, plaintext))).IsTrue();
            await Assert.That(Throws<ArgumentException>(() =>
                codec.Decrypt(suite, invalidSek, message))).IsTrue();
        }

        foreach (int length in new[] { 0, 15, 17 })
        {
            byte[] invalidIv = new byte[length];
            await Assert.That(Throws<ArgumentException>(() =>
                codec.Encrypt(suite, svk, sek, invalidIv, plaintext))).IsTrue();
        }

        await Assert.That(Throws<ArgumentNullException>(() => codec.Decrypt(suite, sek, null!))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            codec.Encrypt((FdoCoseAeadAlgorithm)int.MaxValue, svk, sek, Iv, plaintext))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            codec.VerifyAndParse((FdoCoseAeadAlgorithm)int.MaxValue, svk, encoded))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            codec.Decrypt((FdoCoseAeadAlgorithm)int.MaxValue, sek, message))).IsTrue();
        await Assert.That(codec.Decrypt(suite, sek, message).AsSpan().SequenceEqual(plaintext)).IsTrue();
    }

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task Decrypt_RejectsMalformedAuthenticatedMessage(int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (_, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(2);
        byte[] ciphertext = ReferenceEncrypt(sek, Iv, plaintext);
        var codec = new FdoCoseEncryptThenMacCodec();
        foreach (int length in new[] { 0, 1, 15, 17, 31 })
        {
            var message = new FdoCoseEncryptThenMacCodec.AuthenticatedMessage(Iv, new byte[length]);
            await Assert.That(Throws<CryptographicException>(() => codec.Decrypt(suite, sek, message))).IsTrue();
        }

        foreach (int length in new[] { 0, 15, 17 })
        {
            var message = new FdoCoseEncryptThenMacCodec.AuthenticatedMessage(new byte[length], ciphertext);
            await Assert.That(Throws<ArgumentException>(() => codec.Decrypt(suite, sek, message))).IsTrue();
        }

        var valid = new FdoCoseEncryptThenMacCodec.AuthenticatedMessage(Iv, ciphertext);
        await Assert.That(codec.Decrypt(suite, sek, valid).AsSpan().SequenceEqual(plaintext)).IsTrue();
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5)]
    [Arguments(Suite256, 64, 32, 6)]
    public async Task EncryptAndDecrypt_RejectInvalidCborPlaintexts(
        int suiteValue, int svkLength, int sekLength, int macType)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[][] invalidPlaintexts = [Array.Empty<byte>(), [0x00, 0x01], [0x58, 0x01, 0x02]];
        var codec = new FdoCoseEncryptThenMacCodec();
        foreach (byte[] plaintext in invalidPlaintexts)
        {
            await Assert.That(Throws<CborContentException>(() =>
                codec.Encrypt(suite, svk, sek, Iv, plaintext))).IsTrue();

            byte[] ciphertext = ReferenceEncrypt(sek, Iv, plaintext);
            byte[] inner = EtmEnvelope.Encrypt0(EtmEnvelope.Protected(suiteValue), Iv, ciphertext);
            byte[] signed = EtmEnvelope.Mac0(macType, svk, EtmEnvelope.Protected(macType), inner);
            FdoCoseEncryptThenMacCodec.AuthenticatedMessage message = codec.VerifyAndParse(suite, svk, signed);
            await Assert.That(message.Ciphertext.AsSpan().SequenceEqual(ciphertext)).IsTrue();
            await Assert.That(Throws<CborContentException>(() => codec.Decrypt(suite, sek, message))).IsTrue();
        }
    }

    [Test]
    public async Task Constructor_RejectsInvalidLimits()
    {
        foreach (int limit in new[] { 0, -1 })
        {
            await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
                new FdoCoseEncryptThenMacCodec(maxEncodedBytes: limit))).IsTrue();
            await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
                new FdoCoseEncryptThenMacCodec(maxItems: limit))).IsTrue();
        }

        foreach (int depth in new[] { 0, 129 })
        {
            await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
                new FdoCoseEncryptThenMacCodec(maxDepth: depth))).IsTrue();
        }

        _ = new FdoCoseEncryptThenMacCodec(maxEncodedBytes: 1, maxDepth: 1, maxItems: 1);
        _ = new FdoCoseEncryptThenMacCodec(maxDepth: 128);
    }

    internal static byte[] ReferenceEncrypt(byte[] key, byte[] iv, byte[] plaintext)
    {
        using Aes aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;
        using ICryptoTransform encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    private static (byte[] Protected, byte[] Payload, byte[] Tag, int PayloadOffset, int TagOffset)
        ReadOuter(byte[] encoded)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Canonical);
        if (reader.ReadTag() != (CborTag)17 || reader.ReadStartArray() != 4)
        {
            throw new InvalidOperationException("Expected tagged COSE_Mac0.");
        }

        byte[] protectedHeader = reader.ReadByteString();
        if (reader.ReadStartMap() != 0)
        {
            throw new InvalidOperationException("Expected an empty outer unprotected header.");
        }

        reader.ReadEndMap();
        byte[] payload = reader.ReadByteString();
        int payloadEnd = encoded.Length - reader.BytesRemaining;
        byte[] tag = reader.ReadByteString();
        int tagEnd = encoded.Length - reader.BytesRemaining;
        reader.ReadEndArray();
        if (reader.BytesRemaining != 0)
        {
            throw new InvalidOperationException("Unexpected outer trailing data.");
        }

        return (protectedHeader, payload, tag, payloadEnd - payload.Length, tagEnd - tag.Length);
    }

    private static (byte[] Protected, byte[] Iv, byte[] Ciphertext) ReadInner(byte[] encoded)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Canonical);
        if (reader.ReadTag() != (CborTag)16 || reader.ReadStartArray() != 3)
        {
            throw new InvalidOperationException("Expected tagged COSE_Encrypt0.");
        }

        byte[] protectedHeader = reader.ReadByteString();
        if (reader.ReadStartMap() != 1 || reader.ReadInt32() != 5)
        {
            throw new InvalidOperationException("Expected only the IV header.");
        }

        byte[] iv = reader.ReadByteString();
        reader.ReadEndMap();
        byte[] ciphertext = reader.ReadByteString();
        reader.ReadEndArray();
        if (reader.BytesRemaining != 0)
        {
            throw new InvalidOperationException("Unexpected inner trailing data.");
        }

        return (protectedHeader, iv, ciphertext);
    }

    private static byte[] EncodeOuter(byte[] protectedHeader, byte[] payload, byte[] tag)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)17);
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeader);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString(payload);
        writer.WriteByteString(tag);
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
