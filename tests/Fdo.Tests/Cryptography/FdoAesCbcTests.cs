using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

[UnsupportedOSPlatform("browser")]
public sealed class FdoAesCbcTests
{
    private const string Key128 = "2B7E151628AED2A6ABF7158809CF4F3C";
    private const string Key256 = "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4";
    private static readonly byte[] Iv = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");

    // NIST SP 800-38A F.2.1 and F.2.5 supply the first two blocks.
    [Test]
    [Arguments(Key128, "7649ABAC8119B246CEE98E9B12E9197D5086CB9B507219EE95DB113A917678B2")]
    [Arguments(Key256, "F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D")]
    public async Task NistVectors_128And256_IncludeFullPaddingBlock(string keyHex, string ciphertextHex)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        byte[] key = Convert.FromHexString(keyHex);
        byte[] plaintext = Convert.FromHexString(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51");
        byte[] ciphertext = FdoAesCbc.Encrypt(key, Iv, plaintext);

        await Assert.That(ciphertext.Length).IsEqualTo(48);
        await Assert.That(ciphertext.AsSpan(0, 32).SequenceEqual(Convert.FromHexString(ciphertextHex))).IsTrue();
        await Assert.That(FdoAesCbc.Decrypt(key, Iv, ciphertext).AsSpan().SequenceEqual(plaintext)).IsTrue();

        byte[] padded = DecryptWithoutPadding(key, Iv, ciphertext);
        byte[] padding = new byte[16];
        Array.Fill(padding, (byte)0x10);
        await Assert.That(padded.Length).IsEqualTo(48);
        await Assert.That(padded.AsSpan(0, 32).SequenceEqual(plaintext)).IsTrue();
        await Assert.That(padded.AsSpan(32).SequenceEqual(padding)).IsTrue();
    }

    [Test]
    [Arguments(Key128)]
    [Arguments(Key256)]
    public async Task PaddingAndCiphertextLengths_AreExact(string keyHex)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        byte[] key = Convert.FromHexString(keyHex);
        (int PlaintextLength, int CiphertextLength)[] cases =
        [
            (0, 16), (1, 16), (15, 16), (16, 32), (17, 32),
        ];
        foreach (var item in cases)
        {
            byte[] plaintext = new byte[item.PlaintextLength];
            for (int i = 0; i < plaintext.Length; i++)
            {
                plaintext[i] = (byte)(0x21 + i * 7);
            }

            await Assert.That(FdoAesCbc.GetCiphertextLength(plaintext.Length)).IsEqualTo(item.CiphertextLength);
            byte[] ciphertext = FdoAesCbc.Encrypt(key, Iv, plaintext);
            await Assert.That(ciphertext.Length).IsEqualTo(item.CiphertextLength);
            await Assert.That(FdoAesCbc.Decrypt(key, Iv, ciphertext).AsSpan().SequenceEqual(plaintext)).IsTrue();

            byte[] expectedPadded = new byte[item.CiphertextLength];
            plaintext.CopyTo(expectedPadded, 0);
            byte padding = (byte)(16 - plaintext.Length % 16);
            Array.Fill(expectedPadded, padding, plaintext.Length, expectedPadded.Length - plaintext.Length);
            byte[] actualPadded = DecryptWithoutPadding(key, Iv, ciphertext);
            await Assert.That(actualPadded.AsSpan().SequenceEqual(expectedPadded)).IsTrue();
        }
    }

    [Test]
    public async Task GetCiphertextLength_RejectsNegativeAndOverflow()
    {
        await Assert.That(FdoAesCbc.GetCiphertextLength(2147483630)).IsEqualTo(2147483632);
        await Assert.That(FdoAesCbc.GetCiphertextLength(2147483631)).IsEqualTo(2147483632);
        foreach (int length in new[] { -1, 2147483632, int.MaxValue })
        {
            await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
                FdoAesCbc.GetCiphertextLength(length))).IsTrue();
        }
    }

    [Test]
    [Arguments(Key128)]
    [Arguments(Key256)]
    public async Task EncryptDecrypt_RejectInvalidKeyAndIvLengths(string keyHex)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        byte[] key = Convert.FromHexString(keyHex);
        byte[] plaintext = [0x40];
        byte[] ciphertext = FdoAesCbc.Encrypt(key, Iv, plaintext);
        foreach (int length in new[] { 0, 15, 17, 24, 31, 33 })
        {
            byte[] invalidKey = new byte[length];
            await Assert.That(Throws<ArgumentException>(() =>
                FdoAesCbc.Encrypt(invalidKey, Iv, plaintext))).IsTrue();
            await Assert.That(Throws<ArgumentException>(() =>
                FdoAesCbc.Decrypt(invalidKey, Iv, ciphertext))).IsTrue();
        }

        foreach (int length in new[] { 0, 15, 17 })
        {
            byte[] invalidIv = new byte[length];
            await Assert.That(Throws<ArgumentException>(() =>
                FdoAesCbc.Encrypt(key, invalidIv, plaintext))).IsTrue();
            await Assert.That(Throws<ArgumentException>(() =>
                FdoAesCbc.Decrypt(key, invalidIv, ciphertext))).IsTrue();
        }

        await Assert.That(FdoAesCbc.Decrypt(key, Iv, ciphertext).AsSpan().SequenceEqual(plaintext)).IsTrue();
    }

    [Test]
    [Arguments(Key128)]
    [Arguments(Key256)]
    public async Task Decrypt_RejectsEmptyOrUnalignedCiphertext(string keyHex)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        byte[] key = Convert.FromHexString(keyHex);
        foreach (int length in new[] { 0, 1, 15, 17, 31 })
        {
            byte[] ciphertext = new byte[length];
            await Assert.That(Throws<CryptographicException>(() =>
                FdoAesCbc.Decrypt(key, Iv, ciphertext))).IsTrue();
        }

        byte[] valid = FdoAesCbc.Encrypt(key, Iv, [0x40]);
        await Assert.That(FdoAesCbc.Decrypt(key, Iv, valid).AsSpan().SequenceEqual(new byte[] { 0x40 })).IsTrue();
    }

    [Test]
    [Arguments(Key128)]
    [Arguments(Key256)]
    public async Task Decrypt_RejectsDeterministicallyInvalidPadding(string keyHex)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        byte[] key = Convert.FromHexString(keyHex);
        byte[] plaintext = [0x40];
        byte[] ciphertext = FdoAesCbc.Encrypt(key, Iv, plaintext);
        byte[] badIv = (byte[])Iv.Clone();
        badIv[^1] ^= 0x0F;
        byte[] padded = DecryptWithoutPadding(key, badIv, ciphertext);

        await Assert.That(padded[0]).IsEqualTo((byte)0x40);
        await Assert.That(padded[^1]).IsEqualTo((byte)0x00);
        await Assert.That(Throws<CryptographicException>(() =>
            FdoAesCbc.Decrypt(key, badIv, ciphertext))).IsTrue();
        await Assert.That(FdoAesCbc.Decrypt(key, Iv, ciphertext).AsSpan().SequenceEqual(plaintext)).IsTrue();
    }

    [Test]
    public async Task PlatformSupport_ReportsAndEnforcesAvailability()
    {
        byte[] key = Convert.FromHexString(Key128);
        byte[] plaintext = Convert.FromHexString("6BC1BEE22E409F96E93D7E117393172A");
        byte[] firstBlock = Convert.FromHexString("7649ABAC8119B246CEE98E9B12E9197D");

        if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            await Assert.That(FdoAesCbc.IsSupported).IsTrue();
        }

        if (FdoAesCbc.IsSupported)
        {
            byte[] ciphertext = FdoAesCbc.Encrypt(key, Iv, plaintext);
            await Assert.That(ciphertext.AsSpan(0, 16).SequenceEqual(firstBlock)).IsTrue();
            await Assert.That(FdoAesCbc.Decrypt(key, Iv, ciphertext).AsSpan().SequenceEqual(plaintext)).IsTrue();
        }
        else
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() =>
                FdoAesCbc.Encrypt(key, Iv, plaintext))).IsTrue();
            await Assert.That(Throws<PlatformNotSupportedException>(() =>
                FdoAesCbc.Decrypt(key, Iv, firstBlock))).IsTrue();
        }
    }

    private static byte[] DecryptWithoutPadding(byte[] key, byte[] iv, byte[] ciphertext)
    {
        using Aes aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        aes.IV = iv;
        using ICryptoTransform decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
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
