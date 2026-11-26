using System;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;
using Fdo.Tests.Cryptography;

namespace Fdo.Tests.Serialization;

[UnsupportedOSPlatform("browser")]
public sealed class FdoCoseEncryptThenMacCodecTests
{
    private static readonly byte[] CounterBlock = Convert.FromHexString("000102030405060708090A0B00000007");

    [Test]
    [Arguments(-17760704, 32, 16, 5)]
    [Arguments(-17760706, 64, 32, 6)]
    public async Task ProducesTheIndependentlyComputedEnvelopeAndRoundTrips(
        int suiteValue, int svkLength, int sekLength, int macType)
    {
        if (!FdoAesCtr.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = Keys(svkLength, sekLength);
        byte[] plaintext = Plaintext(40);
        var codec = new FdoCoseEncryptThenMacCodec();

        ReadOnlyMemory<byte> encoded = codec.Encrypt(suite, svk, sek, CounterBlock, plaintext);

        byte[] ciphertext = FdoAesCtrTests.ReferenceCtr(sek, CounterBlock, plaintext);
        byte[] inner = EtmEnvelope.Encrypt0(EtmEnvelope.Protected(suiteValue), CounterBlock, ciphertext);
        byte[] expected = EtmEnvelope.Mac0(macType, svk, EtmEnvelope.Protected(macType), inner);
        await Assert.That(encoded.Span.SequenceEqual(expected)).IsTrue();

        FdoCoseEncryptThenMacCodec.AuthenticatedMessage message = codec.VerifyAndParse(suite, svk, encoded);
        await Assert.That(message.CounterBlock.AsSpan().SequenceEqual(CounterBlock)).IsTrue();
        await Assert.That(message.Ciphertext.AsSpan().SequenceEqual(ciphertext)).IsTrue();
        byte[] decrypted = codec.Decrypt(suite, sek, message);
        await Assert.That(decrypted.AsSpan().SequenceEqual(plaintext)).IsTrue();
    }

    [Test]
    [Arguments(-17760704, 32, 16)]
    [Arguments(-17760706, 64, 32)]
    public async Task RejectsAnyTamperedByteWithAnAuthenticationFailure(int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCtr.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = Keys(svkLength, sekLength);
        var codec = new FdoCoseEncryptThenMacCodec();
        byte[] encoded = codec.Encrypt(suite, svk, sek, CounterBlock, Plaintext(20)).ToArray();

        var reader = new CborReader(encoded, CborConformanceMode.Canonical);
        reader.ReadTag();
        reader.ReadStartArray();
        reader.ReadByteString();
        reader.ReadStartMap();
        reader.ReadEndMap();
        int payloadLength = reader.ReadByteString().Length;
        int payloadEnd = encoded.Length - reader.BytesRemaining;
        int tagLength = reader.ReadByteString().Length;
        var authenticated = new System.Collections.Generic.List<int>();
        for (int offset = payloadEnd - payloadLength; offset < payloadEnd; offset++)
        {
            authenticated.Add(offset);
        }

        for (int offset = encoded.Length - tagLength; offset < encoded.Length; offset++)
        {
            authenticated.Add(offset);
        }

        // Every payload byte (inner tag, inner headers, IV and ciphertext) and
        // every tag byte is authenticated; no flip reaches the inner parser.
        foreach (int offset in authenticated)
        {
            byte[] tampered = (byte[])encoded.Clone();
            tampered[offset] ^= 0x01;
            await Assert.That(Throws<CryptographicException>(() =>
                codec.VerifyAndParse(suite, svk, tampered))).IsTrue();
        }

        byte[] wrongKey = (byte[])svk.Clone();
        wrongKey[0] ^= 0x80;
        await Assert.That(Throws<CryptographicException>(() => codec.VerifyAndParse(suite, wrongKey, encoded))).IsTrue();
    }

    [Test]
    public async Task VerifiesTheMacBeforeParsingTheInnerEnvelope()
    {
        if (!FdoAesCtr.IsSupported)
        {
            return;
        }

        const int Suite = -17760704;
        (byte[] svk, _) = Keys(32, 16);
        var codec = new FdoCoseEncryptThenMacCodec();
        byte[] malformedInner = [0x00];

        byte[] badMac = EtmEnvelope.Mac0(5, svk, EtmEnvelope.Protected(5), malformedInner);
        badMac[^1] ^= 0x01;
        await Assert.That(Throws<CryptographicException>(() =>
            codec.VerifyAndParse((FdoCoseAeadAlgorithm)Suite, svk, badMac))).IsTrue();

        byte[] goodMac = EtmEnvelope.Mac0(5, svk, EtmEnvelope.Protected(5), malformedInner);
        await Assert.That(Throws<CborContentException>(() =>
            codec.VerifyAndParse((FdoCoseAeadAlgorithm)Suite, svk, goodMac))).IsTrue();
    }

    [Test]
    [Arguments("untagged-inner")]
    [Arguments("other-suite")]
    [Arguments("short-iv")]
    [Arguments("extra-header")]
    [Arguments("trailing-inner")]
    public async Task RejectsAuthenticatedButNonconformingInnerEnvelopes(string mutation)
    {
        if (!FdoAesCtr.IsSupported)
        {
            return;
        }

        const int Suite = -17760704;
        (byte[] svk, _) = Keys(32, 16);
        byte[] ciphertext = new byte[4];
        byte[] inner = mutation switch
        {
            "untagged-inner" => EtmEnvelope.Encrypt0(EtmEnvelope.Protected(Suite), CounterBlock, ciphertext, tagged: false),
            "other-suite" => EtmEnvelope.Encrypt0(EtmEnvelope.Protected(-17760706), CounterBlock, ciphertext),
            "short-iv" => EtmEnvelope.Encrypt0(EtmEnvelope.Protected(Suite), new byte[12], ciphertext),
            "extra-header" => EtmEnvelope.Encrypt0(EtmEnvelope.Protected(Suite), CounterBlock, ciphertext, extraHeader: true),
            "trailing-inner" => [.. EtmEnvelope.Encrypt0(EtmEnvelope.Protected(Suite), CounterBlock, ciphertext), 0x00],
            _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
        };
        byte[] encoded = EtmEnvelope.Mac0(5, svk, EtmEnvelope.Protected(5), inner);

        await Assert.That(Throws<CborContentException>(() =>
            new FdoCoseEncryptThenMacCodec().VerifyAndParse((FdoCoseAeadAlgorithm)Suite, svk, encoded))).IsTrue();
    }

    [Test]
    public async Task RejectsOuterHeaderAndKeyMismatchesBeforeComputingTheMac()
    {
        const int Suite = -17760704;
        (byte[] svk, byte[] sek) = Keys(32, 16);
        var codec = new FdoCoseEncryptThenMacCodec();
        byte[] inner = EtmEnvelope.Encrypt0(EtmEnvelope.Protected(Suite), CounterBlock, new byte[4]);

        byte[] wrongMacType = EtmEnvelope.Mac0(6, svk, EtmEnvelope.Protected(6), inner);
        byte[] untaggedOuter = EtmEnvelope.Mac0(5, svk, EtmEnvelope.Protected(5), inner, tagged: false);
        byte[] unprotectedEntry = EtmEnvelope.Mac0(5, svk, EtmEnvelope.Protected(5), inner, extraHeader: true);
        await Assert.That(Throws<CborContentException>(() =>
            codec.VerifyAndParse((FdoCoseAeadAlgorithm)Suite, svk, wrongMacType))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            codec.VerifyAndParse((FdoCoseAeadAlgorithm)Suite, svk, untaggedOuter))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            codec.VerifyAndParse((FdoCoseAeadAlgorithm)Suite, svk, unprotectedEntry))).IsTrue();

        await Assert.That(Throws<ArgumentException>(() =>
            codec.VerifyAndParse((FdoCoseAeadAlgorithm)Suite, new byte[48], wrongMacType))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            codec.Encrypt((FdoCoseAeadAlgorithm)Suite, svk, new byte[32], CounterBlock, Plaintext(1)))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            codec.Encrypt((FdoCoseAeadAlgorithm)(-17760706), new byte[48], new byte[32], CounterBlock, Plaintext(1)))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            codec.Encrypt((FdoCoseAeadAlgorithm)Suite, svk, sek, new byte[12], Plaintext(1)))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            codec.Encrypt(FdoCoseAeadAlgorithm.A128Gcm, svk, sek, CounterBlock, Plaintext(1)))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            new FdoCoseEncryptThenMacCodec(maxEncodedBytes: 100)
                .Encrypt((FdoCoseAeadAlgorithm)Suite, svk, sek, CounterBlock, Plaintext(40)))).IsTrue();
    }

    internal static (byte[] Svk, byte[] Sek) Keys(int svkLength, int sekLength)
    {
        byte[] svk = new byte[svkLength];
        byte[] sek = new byte[sekLength];
        for (int i = 0; i < svk.Length; i++)
        {
            svk[i] = (byte)(0xA0 + i);
        }

        for (int i = 0; i < sek.Length; i++)
        {
            sek[i] = (byte)(0x10 + i);
        }

        return (svk, sek);
    }

    internal static byte[] Plaintext(int contentLength)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        byte[] content = new byte[contentLength];
        for (int i = 0; i < content.Length; i++)
        {
            content[i] = (byte)i;
        }

        writer.WriteByteString(content);
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

/// <summary>
/// Builds paired encrypt-then-MAC envelopes directly from RFC 9052 structures so
/// tests can check the codec against an independent encoding.
/// </summary>
internal static class EtmEnvelope
{
    public static byte[] Protected(int algorithm)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteInt32(algorithm);
        writer.WriteEndMap();
        return writer.Encode();
    }

    public static byte[] Encrypt0(
        byte[] protectedHeader, byte[] iv, byte[] ciphertext, bool tagged = true, bool extraHeader = false)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        if (tagged)
        {
            writer.WriteTag((CborTag)16);
        }

        writer.WriteStartArray(3);
        writer.WriteByteString(protectedHeader);
        writer.WriteStartMap(extraHeader ? 2 : 1);
        writer.WriteInt32(5);
        writer.WriteByteString(iv);
        if (extraHeader)
        {
            writer.WriteInt32(6);
            writer.WriteByteString(new byte[1]);
        }

        writer.WriteEndMap();
        writer.WriteByteString(ciphertext);
        writer.WriteEndArray();
        return writer.Encode();
    }

    public static byte[] Mac0(
        int macType, byte[] svk, byte[] protectedHeader, byte[] payload, bool tagged = true, bool extraHeader = false)
    {
        var structure = new CborWriter(CborConformanceMode.Canonical);
        structure.WriteStartArray(4);
        structure.WriteTextString("MAC0");
        structure.WriteByteString(protectedHeader);
        structure.WriteByteString(Array.Empty<byte>());
        structure.WriteByteString(payload);
        structure.WriteEndArray();
        byte[] macInput = structure.Encode();
        byte[] tag = macType == 6 ? HMACSHA384.HashData(svk, macInput) : HMACSHA256.HashData(svk, macInput);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        if (tagged)
        {
            writer.WriteTag((CborTag)17);
        }

        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeader);
        writer.WriteStartMap(extraHeader ? 1 : 0);
        if (extraHeader)
        {
            writer.WriteInt32(4);
            writer.WriteByteString(new byte[1]);
        }

        writer.WriteEndMap();
        writer.WriteByteString(payload);
        writer.WriteByteString(tag);
        writer.WriteEndArray();
        return writer.Encode();
    }
}
