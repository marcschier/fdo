// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Tests.Cryptography;

[UnsupportedOSPlatform("browser")]
public sealed class FdoTo2PairedAeadChannelTests
{
    [Test]
    [Arguments(1, 16)]
    [Arguments(3, 32)]
    public async Task SealedLengthMatchesEachSealedMessage(int algorithmValue, int keyLength)
    {
        var algorithm = (FdoCoseAeadAlgorithm)algorithmValue;
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            return;
        }

        foreach (int contentLength in new[] { 0, 1, 15, 16, 22, 23, 24, 255, 256, 1300, 4096 })
        {
            // A channel seals once per turn, so each length uses a new channel.
            using var device = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, algorithm, new byte[keyLength]);
            byte[] plaintext = Fdo.Tests.Serialization.FdoCoseEncryptThenMacCodecTests.Plaintext(contentLength);
            await Assert.That(device.GetSealedLength(plaintext.Length)).IsEqualTo((long)device.Seal(plaintext).Length);
        }
    }

    [Test]
    [Arguments(1, 16)]
    [Arguments(3, 32)]
    public async Task ExchangesMessagesWithSeparateSequentialRoleNonces(int algorithmValue, int keyLength)
    {
        var algorithm = (FdoCoseAeadAlgorithm)algorithmValue;
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            return;
        }

        byte[] key = new byte[keyLength];
        using var device = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, algorithm, key);
        using var owner = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Owner, algorithm, key);
        var codec = new FdoCoseEncrypt0Codec();

        ReadOnlyMemory<byte> firstRequest = device.Seal(new byte[] { 0x80 });
        byte[] firstRequestNonce = codec.Decrypt(algorithm, key, firstRequest).Nonce;
        byte[] requestPlaintext = owner.Open(firstRequest);
        ReadOnlyMemory<byte> firstResponse = owner.Seal(new byte[] { 0x81, 0x01 });
        byte[] firstResponseNonce = codec.Decrypt(algorithm, key, firstResponse).Nonce;
        byte[] responsePlaintext = device.Open(firstResponse);
        ReadOnlyMemory<byte> secondRequest = device.Seal(new byte[] { 0x81, 0x02 });
        byte[] secondRequestNonce = codec.Decrypt(algorithm, key, secondRequest).Nonce;
        owner.Open(secondRequest);
        ReadOnlyMemory<byte> secondResponse = owner.Seal(new byte[] { 0x81, 0x03 });
        byte[] secondResponseNonce = codec.Decrypt(algorithm, key, secondResponse).Nonce;
        device.Open(secondResponse);

        await Assert.That(Convert.ToHexString(firstRequestNonce)).IsEqualTo("000000000000000000000000");
        await Assert.That(Convert.ToHexString(firstResponseNonce)).IsEqualTo("000000000000000100000000");
        await Assert.That(Convert.ToHexString(secondRequestNonce)).IsEqualTo("000000000000000000000001");
        await Assert.That(Convert.ToHexString(secondResponseNonce)).IsEqualTo("000000000000000100000001");
        await Assert.That(Convert.ToHexString(requestPlaintext)).IsEqualTo("80");
        await Assert.That(Convert.ToHexString(responsePlaintext)).IsEqualTo("8101");
    }

    [Test]
    public async Task RejectsReplaysAndReflectedMessagesBeforeReturningPlaintext()
    {
        var algorithm = FdoCoseAeadAlgorithm.A128Gcm;
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            return;
        }

        byte[] key = new byte[16];
        using var device = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, algorithm, key);
        using var owner = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Owner, algorithm, key);
        ReadOnlyMemory<byte> request = device.Seal(new byte[] { 0x80 });
        owner.Open(request);
        ReadOnlyMemory<byte> response = owner.Seal(new byte[] { 0x80 });
        device.Open(response);

        await Assert.That(Throws<CryptographicException>(() => owner.Open(request))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => owner.Open(request))).IsTrue();

        byte[] reflectedKey = new byte[16];
        reflectedKey[0] = 1;
        using var reflected = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, algorithm, reflectedKey);
        ReadOnlyMemory<byte> ownMessage = reflected.Seal(new byte[] { 0x80 });
        await Assert.That(Throws<CryptographicException>(() => reflected.Open(ownMessage))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => reflected.Open(ownMessage))).IsTrue();
    }

    [Test]
    public async Task RejectsSkippedCountersAndTagFailuresAndClosesTheChannel()
    {
        var algorithm = FdoCoseAeadAlgorithm.A128Gcm;
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            return;
        }

        byte[] key = new byte[16];
        var codec = new FdoCoseEncrypt0Codec();
        byte[] nonceOne = FdoTo2PairedAeadChannel.CreateNonce(FdoTo2PairedRole.Device, 1);
        ReadOnlyMemory<byte> skipped = codec.Encrypt(algorithm, key, nonceOne, new byte[] { 0x80 });
        using var skippedOwner = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Owner, algorithm, key);
        await Assert.That(Throws<CryptographicException>(() => skippedOwner.Open(skipped))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => skippedOwner.Open(skipped))).IsTrue();

        byte[] nonceZero = FdoTo2PairedAeadChannel.CreateNonce(FdoTo2PairedRole.Device, 0);
        byte[] tampered = codec.Encrypt(algorithm, key, nonceZero, new byte[] { 0x80 }).ToArray();
        tampered[^1] ^= 1;
        using var tamperedOwner = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Owner, algorithm, key);
        await Assert.That(Throws<CryptographicException>(() => tamperedOwner.Open(tampered))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => tamperedOwner.Open(tampered))).IsTrue();
    }

    [Test]
    public async Task AFailedEncryptionCannotReuseTheReservedNonce()
    {
        var algorithm = FdoCoseAeadAlgorithm.A128Gcm;
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            return;
        }

        using var device = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, algorithm, new byte[16]);
        await Assert.That(Throws<CborContentException>(() => device.Seal(new byte[] { 0x00, 0x00 }))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => device.Seal(new byte[] { 0x80 }))).IsTrue();
    }

    [Test]
    public async Task EnforcesSingleInFlightAlternatingMessages()
    {
        var algorithm = FdoCoseAeadAlgorithm.A128Gcm;
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            return;
        }

        using var device = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, algorithm, new byte[16]);
        ReadOnlyMemory<byte> request = device.Seal(new byte[] { 0x80 });
        await Assert.That(Throws<InvalidOperationException>(() => device.Seal(new byte[] { 0x80 }))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => device.Open(request))).IsTrue();

        using var owner = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Owner, algorithm, new byte[16]);
        await Assert.That(Throws<InvalidOperationException>(() => owner.Seal(new byte[] { 0x80 }))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => owner.Open(request))).IsTrue();
    }

    [Test]
    public async Task NonceEncodingIncludesTheMaximumCounterAndRejectsOverflow()
    {
        byte[] lastDeviceNonce = FdoTo2PairedAeadChannel.CreateNonce(FdoTo2PairedRole.Device, uint.MaxValue);
        byte[] lastOwnerNonce = FdoTo2PairedAeadChannel.CreateNonce(FdoTo2PairedRole.Owner, uint.MaxValue);

        await Assert.That(Convert.ToHexString(lastDeviceNonce)).IsEqualTo("0000000000000000FFFFFFFF");
        await Assert.That(Convert.ToHexString(lastOwnerNonce)).IsEqualTo("0000000000000001FFFFFFFF");
        await Assert.That(Throws<InvalidOperationException>(() =>
            FdoTo2PairedAeadChannel.CreateNonce(FdoTo2PairedRole.Device, (ulong)uint.MaxValue + 1))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoTo2PairedAeadChannel.CreateNonce((FdoTo2PairedRole)2, 0))).IsTrue();
    }

    [Test]
    public async Task RequiresAnExplicitSupportedSuiteAndKeySize()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            new FdoTo2PairedAeadChannel((FdoTo2PairedRole)2, FdoCoseAeadAlgorithm.A128Gcm, new byte[16]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, (FdoCoseAeadAlgorithm)2, new byte[16]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, FdoCoseAeadAlgorithm.A128Gcm, new byte[32]))).IsTrue();
    }

    [Test]
    [Arguments(30, 16, 13)]
    [Arguments(31, 32, 13)]
    [Arguments(32, 16, 7)]
    [Arguments(33, 32, 7)]
    public async Task CcmChannelsUseDistinctRoleNoncesAndRejectTampering(
        int algorithmValue, int keyLength, int nonceLength)
    {
        var algorithm = (FdoCoseAeadAlgorithm)algorithmValue;
        if (!FdoCoseAead.IsSupported(algorithm))
        {
            await Assert.That(Throws<PlatformNotSupportedException>(() =>
                new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, algorithm, new byte[keyLength]))).IsTrue();
            return;
        }

        byte[] key = new byte[keyLength];
        using var device = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Device, algorithm, key);
        using var owner = new FdoTo2PairedAeadChannel(FdoTo2PairedRole.Owner, algorithm, key);
        var codec = new FdoCoseEncrypt0Codec();
        ReadOnlyMemory<byte> request = device.Seal(new byte[] { 0x80 });
        byte[] requestNonce = codec.Decrypt(algorithm, key, request).Nonce;
        await Assert.That(Convert.ToHexString(owner.Open(request))).IsEqualTo("80");
        ReadOnlyMemory<byte> response = owner.Seal(new byte[] { 0x81, 0x01 });
        byte[] responseNonce = codec.Decrypt(algorithm, key, response).Nonce;
        await Assert.That(requestNonce.Length).IsEqualTo(nonceLength);
        await Assert.That(responseNonce.Length).IsEqualTo(nonceLength);
        await Assert.That(requestNonce.AsSpan().SequenceEqual(responseNonce)).IsFalse();
        byte[] changed = response.ToArray();
        changed[^1] ^= 1;
        await Assert.That(Throws<CryptographicException>(() => device.Open(changed))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => device.Open(response))).IsTrue();
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
