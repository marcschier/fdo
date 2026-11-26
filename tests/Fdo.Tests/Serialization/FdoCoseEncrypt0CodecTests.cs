// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Tests.Serialization;

[UnsupportedOSPlatform("browser")]
public sealed class FdoCoseEncrypt0CodecTests
{
    /// <summary>
    /// Generated independently with Python cryptography AESGCM/AESCCM and RFC 9052 CBOR.
    /// </summary>
    /// <param name="algorithmValue">The COSE algorithm identifier.</param>
    /// <param name="keyLength">The key length in bytes.</param>
    /// <param name="nonceLength">The nonce length in bytes.</param>
    /// <param name="expectedHex">The expected encoded message in hexadecimal.</param>
    /// <returns>A task that completes after the vector assertions.</returns>
    [Test]
    [Arguments(1, 16, 12, "D08343A10101A1054C000000000000000000000000538189D86A6598C9FE2ACE06607AF578ACFB8E8B")]
    [Arguments(3, 32, 12, "D08343A10103A1054C000000000000000000000000534CA6426826E625E27E357059CF1E52D8E6090E")]
    [Arguments(30, 16, 13, "D08344A101181EA1054D00000000000000000000000000535779F091BC749922D5A0113828EC5F1D34EA22")]
    [Arguments(31, 32, 13, "D08344A101181FA1054D00000000000000000000000000535F9F46B78D80F2E9DD0F9DDD48672BFE32AB20")]
    [Arguments(32, 16, 7, "D08344A1011820A105470000000000000053204777D2AC8FF8161C10E6E393DC517007B54F")]
    [Arguments(33, 32, 7, "D08344A1011821A105470000000000000053E6CD18BDF0C32D0EC3470CE4646ED50D8AC81D")]
    public async Task MatchesIndependentEncrypt0Vectors(int algorithmValue, int keyLength, int nonceLength, string expectedHex)
    {
        var algorithm = (FdoCoseAeadAlgorithm)algorithmValue;
        byte[] key = new byte[keyLength];
        byte[] nonce = new byte[nonceLength];
        byte[] plaintext = Convert.FromHexString("820102");
        byte[] expected = Convert.FromHexString(expectedHex);
        var codec = new FdoCoseEncrypt0Codec();
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() =>
                codec.Encrypt(algorithm, key, nonce, plaintext))).IsTrue();
            return;
        }

        ReadOnlyMemory<byte> encoded = codec.Encrypt(algorithm, key, nonce, plaintext);
        FdoCoseEncrypt0Codec.DecryptedMessage decrypted = codec.Decrypt(algorithm, key, expected);
        Array.Fill(expected, (byte)0xFF);

        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo(expectedHex);
        await Assert.That(Convert.ToHexString(decrypted.Nonce)).IsEqualTo(Convert.ToHexString(nonce));
        await Assert.That(Convert.ToHexString(decrypted.Plaintext)).IsEqualTo("820102");
    }

    [Test]
    public async Task MatchesIndependentProtectedDeviceReadyVector()
    {
        byte[] key = Convert.FromHexString("8F0FF9DD2FD395D341D763D981F3D7C3B75F20A0E0F0F5BABF46D2FC722A38E9");
        byte[] nonce = Convert.FromHexString("00112233445566778899AABB");
        byte[] plaintext = Convert.FromHexString("83F6F650000102030405060708090A0B0C0D0E0F");
        const string expected =
            "D08343A10103A1054C00112233445566778899AABB582486D06DAB88335CFE35CA51F49F45BDA836677B36FAB1D805A4DC4DE8ECB9687B4D48F703";
        var codec = new FdoCoseEncrypt0Codec();
        if (!FdoCoseAead.IsSupported(FdoCoseAeadAlgorithm.A256Gcm))
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() =>
                codec.Encrypt(FdoCoseAeadAlgorithm.A256Gcm, key, nonce, plaintext))).IsTrue();
            return;
        }

        ReadOnlyMemory<byte> encoded = codec.Encrypt(FdoCoseAeadAlgorithm.A256Gcm, key, nonce, plaintext);
        FdoCoseEncrypt0Codec.DecryptedMessage decrypted = codec.Decrypt(
            FdoCoseAeadAlgorithm.A256Gcm, key, Convert.FromHexString(expected));
        FdoTo2ServiceInfoCodec.DeviceServiceInfoReady ready =
            new FdoTo2ServiceInfoCodec().DecodeDeviceReady(decrypted.Plaintext);

        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo(expected);
        await Assert.That(Convert.ToHexString(decrypted.Nonce)).IsEqualTo("00112233445566778899AABB");
        await Assert.That(Convert.ToHexString(ready.Nonce.Span)).IsEqualTo("000102030405060708090A0B0C0D0E0F");
        await Assert.That(ready.MaxOwnerServiceInfoSize is null).IsTrue();
    }

    [Test]
    public async Task RejectsModifiedNonceCiphertextAndTag()
    {
        const FdoCoseAeadAlgorithm algorithm = FdoCoseAeadAlgorithm.A128Gcm;
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            return;
        }

        byte[] key = new byte[16];
        var codec = new FdoCoseEncrypt0Codec();
        byte[] encoded = codec.Encrypt(algorithm, key, new byte[12], new byte[] { 0x82, 0x01, 0x02 }).ToArray();
        foreach (int index in new[] { 9, 22, encoded.Length - 1 })
        {
            byte[] changed = encoded.AsSpan().ToArray();
            changed[index] ^= 1;
            await Assert.That(Throws<CryptographicException>(() => codec.Decrypt(algorithm, key, changed))).IsTrue();
        }

        await Assert.That(Throws<CryptographicException>(() => codec.Decrypt(
            algorithm, Convert.FromHexString("01000000000000000000000000000000"), encoded))).IsTrue();
    }

    [Test]
    public async Task AuthenticatesTheReceivedProtectedHeaderBytes()
    {
        const FdoCoseAeadAlgorithm algorithm = FdoCoseAeadAlgorithm.A256Gcm;
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            return;
        }

        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] ciphertext = new byte[1];
        byte[] tag = new byte[16];
        byte[] wrongAssociatedData = Convert.FromHexString("8368456E63727970743043A1010140");
        FdoCoseAead.Encrypt(algorithm, key, nonce, new byte[] { 0x80 }, ciphertext, tag, wrongAssociatedData);
        byte[] encrypted = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(encrypted, 0);
        tag.CopyTo(encrypted, ciphertext.Length);
        byte[] frame = Frame(
            Convert.FromHexString("A10103"), Convert.FromHexString("A1054C000000000000000000000000"), encrypted);

        await Assert.That(Throws<CryptographicException>(() =>
            new FdoCoseEncrypt0Codec().Decrypt(algorithm, key, frame))).IsTrue();
    }

    [Test]
    public async Task RejectsIncorrectTagShapeHeadersAndCiphertextLength()
    {
        var codec = new FdoCoseEncrypt0Codec();
        const FdoCoseAeadAlgorithm algorithm = FdoCoseAeadAlgorithm.A128Gcm;
        byte[] key = new byte[16];
        byte[] frame = Convert.FromHexString(
            "D08343A10101A1054C000000000000000000000000538189D86A6598C9FE2ACE06607AF578ACFB8E8B");
        byte[] wrongTag = frame.AsSpan().ToArray();
        wrongTag[0] = 0xD1;
        byte[] wrongArrayLength = frame.AsSpan().ToArray();
        wrongArrayLength[1] = 0x82;
        byte[] trailingData = new byte[frame.Length + 1];
        frame.CopyTo(trailingData, 0);
        byte[][] malformed =
        [
            frame.AsSpan(1).ToArray(),
            wrongTag,
            wrongArrayLength,
            trailingData,
            frame.AsSpan(0, frame.Length - 1).ToArray(),
            Frame([], Convert.FromHexString("A1054C000000000000000000000000"), new byte[16]),
            Frame(Convert.FromHexString("A10103"), Convert.FromHexString("A1054C000000000000000000000000"), new byte[16]),
            Frame(Convert.FromHexString("A1010100"), Convert.FromHexString("A1054C000000000000000000000000"), new byte[16]),
            Frame(Convert.FromHexString("A10101"), Convert.FromHexString("A0"), new byte[16]),
            Frame(Convert.FromHexString("A10101"), Convert.FromHexString("A1074C000000000000000000000000"), new byte[16]),
            Frame(Convert.FromHexString("A10101"), Convert.FromHexString("A1054B0000000000000000000000"), new byte[16]),
            Frame(Convert.FromHexString("A10101"), Convert.FromHexString("A20101054C000000000000000000000000"), new byte[16]),
            Frame(Convert.FromHexString("A10101"), Convert.FromHexString("A1054C000000000000000000000000"), new byte[15]),
        ];

        foreach (byte[] input in malformed)
        {
            await Assert.That(Throws<CborContentException>(() => codec.Decrypt(algorithm, key, input))).IsTrue();
        }
    }

    [Test]
    public async Task RejectsInvalidPlaintextEvenWhenTheTagIsValid()
    {
        const FdoCoseAeadAlgorithm algorithm = FdoCoseAeadAlgorithm.A128Gcm;
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            return;
        }

        byte[] key = new byte[16];
        byte[] nonce = new byte[12];
        byte[] invalidPlaintext = [0x00, 0x00];
        byte[] ciphertext = new byte[invalidPlaintext.Length];
        byte[] tag = new byte[16];
        byte[] associatedData = Convert.FromHexString("8368456E63727970743043A1010140");
        FdoCoseAead.Encrypt(algorithm, key, nonce, invalidPlaintext, ciphertext, tag, associatedData);
        byte[] encrypted = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(encrypted, 0);
        tag.CopyTo(encrypted, ciphertext.Length);
        byte[] frame = Frame(
            Convert.FromHexString("A10101"), Convert.FromHexString("A1054C000000000000000000000000"), encrypted);
        var codec = new FdoCoseEncrypt0Codec();

        await Assert.That(Throws<CborContentException>(() =>
            codec.Encrypt(algorithm, key, nonce, invalidPlaintext))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.Decrypt(algorithm, key, frame))).IsTrue();
    }

    [Test]
    [Arguments(1, 16, 12, 21)]
    [Arguments(30, 16, 13, 23)]
    [Arguments(32, 16, 7, 17)]
    public async Task EnforcesTheCompleteEnvelopeLimitAcrossByteStringLengthBoundaries(
        int algorithmValue, int keyLength, int nonceLength, int overhead)
    {
        var algorithm = (FdoCoseAeadAlgorithm)algorithmValue;
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            return;
        }

        byte[] key = new byte[keyLength];
        byte[] nonce = new byte[nonceLength];
        foreach ((byte[] plaintext, int ciphertextAndHeaderLength) in new[]
        {
            (new byte[] { 0x46, 0, 0, 0, 0, 0, 0 }, 24),
            (new byte[] { 0x47, 0, 0, 0, 0, 0, 0, 0 }, 26),
        })
        {
            int expectedLength = overhead + ciphertextAndHeaderLength;
            var atLimit = new FdoCoseEncrypt0Codec(maxEncodedBytes: expectedLength);
            var overLimit = new FdoCoseEncrypt0Codec(maxEncodedBytes: expectedLength - 1);
            ReadOnlyMemory<byte> encoded = atLimit.Encrypt(algorithm, key, nonce, plaintext);

            await Assert.That(encoded.Length).IsEqualTo(expectedLength);
            await Assert.That(Convert.ToHexString(atLimit.Decrypt(algorithm, key, encoded).Plaintext))
                .IsEqualTo(Convert.ToHexString(plaintext));
            await Assert.That(Throws<CborContentException>(() => overLimit.Encrypt(algorithm, key, nonce, plaintext))).IsTrue();
            await Assert.That(Throws<CborContentException>(() => overLimit.Decrypt(algorithm, key, encoded))).IsTrue();
        }
    }

    [Test]
    public async Task RejectsUnsupportedAlgorithmsAndIncorrectKeyOrNonceLengths()
    {
        var codec = new FdoCoseEncrypt0Codec();
        const FdoCoseAeadAlgorithm algorithm = FdoCoseAeadAlgorithm.A128Gcm;
        byte[] plaintext = [0x80];
        byte[] frame = Convert.FromHexString(
            "D08343A10101A1054C000000000000000000000000538189D86A6598C9FE2ACE06607AF578ACFB8E8B");

        await Assert.That(Throws<ArgumentOutOfRangeException>(() => codec.Encrypt(
            (FdoCoseAeadAlgorithm)2, new byte[16], new byte[13], plaintext))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => codec.Decrypt(
            (FdoCoseAeadAlgorithm)2, new byte[16], frame))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            codec.Encrypt(algorithm, new byte[16], new byte[11], plaintext))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            codec.Encrypt(algorithm, new byte[15], new byte[12], plaintext))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.Decrypt(algorithm, new byte[15], frame))).IsTrue();
    }

    private static byte[] Frame(byte[] protectedHeader, byte[] unprotectedHeader, byte[] ciphertext)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)16);
        writer.WriteStartArray(3);
        writer.WriteByteString(protectedHeader);
        writer.WriteEncodedValue(unprotectedHeader);
        writer.WriteByteString(ciphertext);
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
