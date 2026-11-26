// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

[UnsupportedOSPlatform("browser")]
public sealed class FdoAesCtrTests
{
    /// <summary>
    /// NIST SP 800-38A, F.5.1 and F.5.5.
    /// </summary>
    /// <param name="keyHex">The NIST AES key in hexadecimal.</param>
    /// <param name="ciphertextHex">The expected ciphertext in hexadecimal.</param>
    /// <returns>A task that completes after the vector assertions.</returns>
    [Test]
    [Arguments(
        "2B7E151628AED2A6ABF7158809CF4F3C",
        "874D6191B620E3261BEF6864990DB6CE9806F66B7970FDFF8617187BB9FFFDFF")]
    [Arguments(
        "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
        "601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C5")]
    public async Task MatchesNistVectorsForFullAndPartialBlocks(string keyHex, string ciphertextHex)
    {
        byte[] key = Convert.FromHexString(keyHex);
        byte[] counter = Convert.FromHexString("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
        byte[] input = Convert.FromHexString("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51");
        byte[] expected = Convert.FromHexString(ciphertextHex);
        if (!FdoAesCtr.IsSupported)
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() =>
                FdoAesCtr.Transform(key, counter, input, new byte[input.Length]))).IsTrue();
            return;
        }

        foreach (int length in new[] { 1, 16, 23, input.Length })
        {
            byte[] encrypted = new byte[length];
            byte[] decrypted = new byte[length];
            FdoAesCtr.Transform(key, counter, input.AsSpan(0, length), encrypted);
            FdoAesCtr.Transform(key, counter, encrypted, decrypted);
            await Assert.That(encrypted.AsSpan().SequenceEqual(expected.AsSpan(0, length))).IsTrue();
            await Assert.That(decrypted.AsSpan().SequenceEqual(input.AsSpan(0, length))).IsTrue();
        }
    }

    [Test]
    public async Task RejectsCounterWrapAndInvalidBuffersBeforeInvokingTheProvider()
    {
        byte[] key = new byte[16];
        byte[] counter = Convert.FromHexString("000000000000000000000000FFFFFFFF");
        byte[] input = new byte[17];
        byte[] output = new byte[17];

        await Assert.That(Throws<ArgumentException>(() =>
            FdoAesCtr.Transform(key, counter, input, output))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoAesCtr.Transform(new byte[24], counter, input, output))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoAesCtr.Transform(key, new byte[15], input, output))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoAesCtr.Transform(key, counter, input, new byte[16]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoAesCtr.Transform(key, new byte[16], input, input))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoAesCtr.Transform(key, new byte[16], new byte[65536], new byte[65536]))).IsTrue();

        if (FdoAesCtr.IsSupported)
        {
            FdoAesCtr.Transform(key, counter, input.AsSpan(0, 16), output.AsSpan(0, 16));
        }
        else
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() =>
                FdoAesCtr.Transform(key, counter, input.AsSpan(0, 16), output.AsSpan(0, 16)))).IsTrue();
        }
    }

    [Test]
    public async Task MatchesBlockCipherReferenceAcrossChunkBoundaries()
    {
        if (!FdoAesCtr.IsSupported)
        {
            return;
        }

        byte[] key = Convert.FromHexString("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4");
        byte[] counter = Convert.FromHexString("000102030405060708090A0BFFFFFF00");
        byte[] input = new byte[2500];
        for (int i = 0; i < input.Length; i++)
        {
            input[i] = (byte)(i * 7);
        }

        byte[] expected = ReferenceCtr(key, counter, input);
        byte[] actual = new byte[input.Length];
        FdoAesCtr.Transform(key, counter, input, actual);
        await Assert.That(actual.AsSpan().SequenceEqual(expected)).IsTrue();
    }

    [Test]
    public async Task ReservesAtLeastOneBlockAndRejectsExhaustion()
    {
        await Assert.That(FdoAesCtr.TryReserve(0, 0, out uint first, out ulong next)).IsTrue();
        await Assert.That(first).IsEqualTo(0u);
        await Assert.That(next).IsEqualTo(1UL);

        await Assert.That(FdoAesCtr.TryReserve(next, 17, out uint second, out next)).IsTrue();
        await Assert.That(second).IsEqualTo(1u);
        await Assert.That(next).IsEqualTo(3UL);

        await Assert.That(FdoAesCtr.TryReserve(next, 16, out uint third, out next)).IsTrue();
        await Assert.That(third).IsEqualTo(3u);
        await Assert.That(next).IsEqualTo(4UL);

        const ulong last = FdoAesCtr.CounterSpace - 2;
        await Assert.That(FdoAesCtr.TryReserve(last, 32, out uint final, out ulong end)).IsTrue();
        await Assert.That(final).IsEqualTo(uint.MaxValue - 1);
        await Assert.That(end).IsEqualTo(FdoAesCtr.CounterSpace);
        await Assert.That(FdoAesCtr.TryReserve(last, 33, out _, out ulong unchanged)).IsFalse();
        await Assert.That(unchanged).IsEqualTo(last);
        await Assert.That(FdoAesCtr.TryReserve(FdoAesCtr.CounterSpace, 0, out _, out _)).IsFalse();
    }

    internal static byte[] ReferenceCtr(byte[] key, byte[] counterBlock, byte[] input)
    {
        using System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
        aes.Key = key;
        int blocks = (input.Length + 15) / 16;
        byte[] counters = new byte[blocks * 16];
        uint counter = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(counterBlock.AsSpan(12));
        for (int i = 0; i < blocks; i++)
        {
            counterBlock.AsSpan(0, 12).CopyTo(counters.AsSpan(i * 16));
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(
                counters.AsSpan((i * 16) + 12), counter + (uint)i);
        }

        byte[] keystream = aes.EncryptEcb(counters, System.Security.Cryptography.PaddingMode.None);
        byte[] output = new byte[input.Length];
        for (int i = 0; i < input.Length; i++)
        {
            output[i] = (byte)(input[i] ^ keystream[i]);
        }

        return output;
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
