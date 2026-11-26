using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;
using Fdo.Tests.Serialization;

namespace Fdo.Tests.Cryptography;

[UnsupportedOSPlatform("browser")]
public sealed class FdoTo2PairedEtmChannelTests
{
    private const int Suite128 = -17760704;
    private const int Suite256 = -17760706;

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task SealedLengthMatchesEachSealedMessage(int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCtr.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        foreach (int contentLength in new[] { 0, 14, 15, 16, 22, 23, 24, 255, 256, 1300, 4096 })
        {
            // A channel seals once per turn, so each length uses a new channel.
            using var device = new FdoTo2PairedEtmChannel(
                FdoTo2PairedRole.Device, suite, SessionKey(svkLength + sekLength));
            byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(contentLength);
            await Assert.That(device.GetSealedLength(plaintext.Length)).IsEqualTo((long)device.Seal(plaintext).Length);
        }
    }

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task ReservesDisjointPerDirectionCounterRangesAcrossVariableLengthMessages(
        int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCtr.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        byte[] key = SessionKey(svkLength + sekLength);
        byte[] svk = key[..svkLength];
        using var device = new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Device, suite, key);
        using var owner = new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Owner, suite, key);
        var codec = new FdoCoseEncryptThenMacCodec();
        var deviceBlocks = new List<byte[]>();
        var ownerBlocks = new List<byte[]>();

        // Encoded lengths 1, 18, 42 and 15 bytes consume 1, 2, 3 and 1 blocks.
        int[] contentLengths = [0, 17, 40, 14];
        for (int i = 0; i < contentLengths.Length; i++)
        {
            byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(contentLengths[i]);
            ReadOnlyMemory<byte> sealedMessage = device.Seal(plaintext);
            deviceBlocks.Add(codec.VerifyAndParse(suite, svk, sealedMessage).CounterBlock);
            await Assert.That(owner.Open(sealedMessage).AsSpan().SequenceEqual(plaintext)).IsTrue();

            plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(contentLengths[(i + 1) % contentLengths.Length]);
            sealedMessage = owner.Seal(plaintext);
            ownerBlocks.Add(codec.VerifyAndParse(suite, svk, sealedMessage).CounterBlock);
            await Assert.That(device.Open(sealedMessage).AsSpan().SequenceEqual(plaintext)).IsTrue();
        }

        // The Device sends 1, 2, 3 and 1 blocks; the Owner sends 2, 3, 1 and 1.
        await Assert.That(Counters(deviceBlocks).AsSpan().SequenceEqual(new uint[] { 0, 1, 3, 6 })).IsTrue();
        await Assert.That(Counters(ownerBlocks).AsSpan().SequenceEqual(new uint[] { 0, 2, 5, 6 })).IsTrue();
        await Assert.That(device.SendCounter).IsEqualTo(7UL);
        await Assert.That(owner.ReceiveCounter).IsEqualTo(7UL);
        await Assert.That(owner.SendCounter).IsEqualTo(7UL);
        await Assert.That(device.ReceiveCounter).IsEqualTo(7UL);

        byte[] devicePrefix = deviceBlocks[0][..12];
        byte[] ownerPrefix = ownerBlocks[0][..12];
        await Assert.That(devicePrefix.AsSpan().SequenceEqual(ownerPrefix)).IsFalse();
        foreach (byte[] block in deviceBlocks)
        {
            await Assert.That(block.AsSpan(0, 12).SequenceEqual(devicePrefix)).IsTrue();
        }

        foreach (byte[] block in ownerBlocks)
        {
            await Assert.That(block.AsSpan(0, 12).SequenceEqual(ownerPrefix)).IsTrue();
        }
    }

    [Test]
    public async Task RejectsAPeerOrReflectedMessageThatUsesTheLocalPrefix()
    {
        if (!FdoAesCtr.IsSupported)
        {
            return;
        }

        byte[] key = SessionKey(48);
        byte[] prefix = Prefix(0x11);

        using var device = new FdoTo2PairedEtmChannel(
            FdoTo2PairedRole.Device, (FdoCoseAeadAlgorithm)Suite128, key, prefix);
        using var sameOwner = new FdoTo2PairedEtmChannel(
            FdoTo2PairedRole.Owner, (FdoCoseAeadAlgorithm)Suite128, key, prefix);
        ReadOnlyMemory<byte> first = device.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(1));
        await Assert.That(Throws<CryptographicException>(() => sameOwner.Open(first))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => sameOwner.Open(first))).IsTrue();

        // A Device message reflected back to the same Device.
        await Assert.That(Throws<CryptographicException>(() => device.Open(first))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => device.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(1)))).IsTrue();
    }

    [Test]
    public async Task RejectsSendExhaustionAndPermitsTheLastBlock()
    {
        if (!FdoAesCtr.IsSupported)
        {
            return;
        }

        byte[] key = SessionKey(48);
        var suite = (FdoCoseAeadAlgorithm)Suite128;

        using var tooLong = new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Device, suite, key)
        {
            SendCounter = uint.MaxValue,
        };
        await Assert.That(Throws<CryptographicException>(() =>
            tooLong.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(16)))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() =>
            tooLong.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(1)))).IsTrue();

        using var device = new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Device, suite, key)
        {
            SendCounter = uint.MaxValue,
        };
        using var owner = new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Owner, suite, key)
        {
            ReceiveCounter = uint.MaxValue,
        };
        byte[] lastBlock = FdoCoseEncryptThenMacCodecTests.Plaintext(14);
        byte[] opened = owner.Open(device.Seal(lastBlock));
        await Assert.That(opened.AsSpan().SequenceEqual(lastBlock)).IsTrue();
        await Assert.That(device.SendCounter).IsEqualTo(FdoAesCtr.CounterSpace);
        await Assert.That(owner.ReceiveCounter).IsEqualTo(FdoAesCtr.CounterSpace);

        device.Open(owner.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(0)));
        await Assert.That(Throws<CryptographicException>(() =>
            device.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(0)))).IsTrue();
    }

    [Test]
    public async Task RejectsAnAuthenticatedMessageThatWouldExhaustTheReceiveCounter()
    {
        if (!FdoAesCtr.IsSupported)
        {
            return;
        }

        byte[] key = SessionKey(48);
        using var owner = new FdoTo2PairedEtmChannel(
            FdoTo2PairedRole.Owner, (FdoCoseAeadAlgorithm)Suite128, key)
        {
            ReceiveCounter = uint.MaxValue,
        };
        byte[] counterBlock = new byte[16];
        Prefix(0x22).CopyTo(counterBlock, 0);
        BinaryPrimitives.WriteUInt32BigEndian(counterBlock.AsSpan(12), uint.MaxValue);
        byte[] inner = EtmEnvelope.Encrypt0(EtmEnvelope.Protected(Suite128), counterBlock, new byte[17]);
        byte[] crafted = EtmEnvelope.Mac0(5, key[..32], EtmEnvelope.Protected(5), inner);

        await Assert.That(Throws<CryptographicException>(() => owner.Open(crafted))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => owner.Open(crafted))).IsTrue();
    }

    [Test]
    [Arguments("replay")]
    [Arguments("counter")]
    [Arguments("prefix-change")]
    [Arguments("tamper")]
    public async Task RejectsReplayCounterPrefixAndTamperingAndCloses(string attack)
    {
        if (!FdoAesCtr.IsSupported)
        {
            return;
        }

        byte[] key = SessionKey(96);
        var suite = (FdoCoseAeadAlgorithm)Suite256;
        using var device = new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Device, suite, key);
        using var owner = new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Owner, suite, key);
        ReadOnlyMemory<byte> first = device.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(3));
        owner.Open(first);
        device.Open(owner.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(3)));
        ReadOnlyMemory<byte> second = device.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(3));

        ReadOnlyMemory<byte> attempt;
        switch (attack)
        {
            case "replay":
                attempt = first;
                break;
            case "counter":
                owner.ReceiveCounter += 1;
                attempt = second;
                break;
            case "prefix-change":
                using (var other = new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Device, suite, key)
                {
                    SendCounter = owner.ReceiveCounter,
                })
                {
                    attempt = other.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(3));
                }

                break;
            case "tamper":
                byte[] tampered = second.ToArray();
                tampered[^1] ^= 0x01;
                attempt = tampered;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(attack));
        }

        await Assert.That(Throws<CryptographicException>(() => owner.Open(attempt))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => owner.Open(second))).IsTrue();
    }

    [Test]
    public async Task EnforcesTurnOrderConstructionArgumentsAndFactorySelection()
    {
        byte[] key = SessionKey(48);
        var suite = (FdoCoseAeadAlgorithm)Suite128;
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Device, FdoCoseAeadAlgorithm.A128Gcm, key))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Device, suite, new byte[32]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Device, (FdoCoseAeadAlgorithm)Suite256, new byte[80]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Device, suite, key, new byte[11]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            new FdoTo2PairedEtmChannel((FdoTo2PairedRole)9, suite, key))).IsTrue();
        if (!FdoAesCtr.IsSupported)
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() =>
                new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Device, suite, key))).IsTrue();
            return;
        }

        using IFdoTo2PairedChannel created = FdoTo2PairedChannels.Create(FdoTo2PairedRole.Device, suite, key);
        await Assert.That(created is FdoTo2PairedEtmChannel).IsTrue();

        using var owner = new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Owner, suite, key);
        await Assert.That(Throws<InvalidOperationException>(() =>
            owner.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(1)))).IsTrue();
        using var device = new FdoTo2PairedEtmChannel(FdoTo2PairedRole.Device, suite, key);
        ReadOnlyMemory<byte> first = device.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(1));
        await Assert.That(Throws<InvalidOperationException>(() =>
            device.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(1)))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => device.Open(first))).IsTrue();
    }

    private static uint[] Counters(List<byte[]> blocks)
    {
        uint[] counters = new uint[blocks.Count];
        for (int i = 0; i < blocks.Count; i++)
        {
            counters[i] = BinaryPrimitives.ReadUInt32BigEndian(blocks[i].AsSpan(12));
        }

        return counters;
    }

    private static byte[] SessionKey(int length)
    {
        byte[] key = new byte[length];
        for (int i = 0; i < key.Length; i++)
        {
            key[i] = (byte)(0x40 + i);
        }

        return key;
    }

    private static byte[] Prefix(byte value)
    {
        byte[] prefix = new byte[12];
        prefix.AsSpan().Fill(value);
        return prefix;
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
