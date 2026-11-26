using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;
using Fdo.Tests.Serialization;

namespace Fdo.Tests.Cryptography;

[UnsupportedOSPlatform("browser")]
public sealed class FdoTo2PairedCbcEtmChannelTests
{
    private const int Suite128 = -17760703;
    private const int Suite256 = -17760705;
    private static readonly byte[] FixedIv = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task SealedLengthMatchesEachSealedMessageAcrossBlockBoundaries(
        int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        // Content lengths 14, 15 and 16 give plaintexts of 15, 16 and 17
        // bytes, so the padded ciphertext crosses a block boundary.
        foreach (int contentLength in new[] { 0, 14, 15, 16, 22, 23, 24, 30, 31, 255, 256, 1300, 4096 })
        {
            // A channel seals once per turn, so each length uses a new channel.
            using var device = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Device, suite, SessionKey(svk, sek));
            byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(contentLength);
            await Assert.That(device.GetSealedLength(plaintext.Length)).IsEqualTo((long)device.Seal(plaintext).Length);
        }
    }

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task PairedRoles_AlternateWithUniqueBidirectionalIvs(int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        using var device = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Device, suite, sessionKey);
        using var owner = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Owner, suite, sessionKey);
        var codec = new FdoCoseEncryptThenMacCodec();
        var seen = new HashSet<Guid>();
        var allIvs = new List<byte[]>();
        var deviceIvs = new List<byte[]>();
        var ownerIvs = new List<byte[]>();
        int[] deviceLengths = [0, 14, 15, 16];
        int[] ownerLengths = [1, 17, 23, 24];

        // This checks the IVs in this exchange, not the RNG's statistical quality.
        for (int i = 0; i < deviceLengths.Length; i++)
        {
            byte[] devicePlaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(deviceLengths[i]);
            ReadOnlyMemory<byte> request = device.Seal(devicePlaintext);
            FdoCoseEncryptThenMacCodec.AuthenticatedMessage requestMessage =
                codec.VerifyAndParse(suite, svk, request);
            await Assert.That(requestMessage.CounterBlock.Length).IsEqualTo(16);
            await Assert.That(seen.Add(new Guid(requestMessage.CounterBlock))).IsTrue();
            allIvs.Add(requestMessage.CounterBlock);
            deviceIvs.Add(requestMessage.CounterBlock);
            await Assert.That(requestMessage.Ciphertext.Length)
                .IsEqualTo(FdoAesCbc.GetCiphertextLength(devicePlaintext.Length));
            await Assert.That(codec.Decrypt(suite, sek, requestMessage).AsSpan().SequenceEqual(devicePlaintext)).IsTrue();
            await Assert.That(owner.Open(request).AsSpan().SequenceEqual(devicePlaintext)).IsTrue();

            byte[] ownerPlaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(ownerLengths[i]);
            ReadOnlyMemory<byte> reply = owner.Seal(ownerPlaintext);
            FdoCoseEncryptThenMacCodec.AuthenticatedMessage replyMessage =
                codec.VerifyAndParse(suite, svk, reply);
            await Assert.That(replyMessage.CounterBlock.Length).IsEqualTo(16);
            await Assert.That(seen.Add(new Guid(replyMessage.CounterBlock))).IsTrue();
            allIvs.Add(replyMessage.CounterBlock);
            ownerIvs.Add(replyMessage.CounterBlock);
            await Assert.That(replyMessage.Ciphertext.Length)
                .IsEqualTo(FdoAesCbc.GetCiphertextLength(ownerPlaintext.Length));
            await Assert.That(codec.Decrypt(suite, sek, replyMessage).AsSpan().SequenceEqual(ownerPlaintext)).IsTrue();
            await Assert.That(device.Open(reply).AsSpan().SequenceEqual(ownerPlaintext)).IsTrue();
        }

        await Assert.That(seen.Count).IsEqualTo(8);
        // Reject obvious counter sequences; this is not a statistical randomness test.
        await Assert.That(IsSimpleCounterSequence(allIvs)).IsFalse();
        await Assert.That(IsSimpleCounterSequence(deviceIvs)).IsFalse();
        await Assert.That(IsSimpleCounterSequence(ownerIvs)).IsFalse();
    }

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task ReplayAfterReply_ClosesAndErases(int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        Exception failure = await ReplayFailureAsync((FdoCoseAeadAlgorithm)suiteValue, sessionKey, svk, sek);
        await AssertNormalizedAsync(failure);
    }

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task ReflectOwnSend_ClosesAndErases(int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        Exception failure = await ReflectionFailureAsync((FdoCoseAeadAlgorithm)suiteValue, sessionKey, svk, sek);
        await AssertNormalizedAsync(failure);
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5)]
    [Arguments(Suite256, 64, 32, 6)]
    public async Task ReusedIvOnDistinctAuthenticatedEnvelope_ClosesAndErases(
        int suiteValue, int svkLength, int sekLength, int macType)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        using var device = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Device, suite, sessionKey);
        var keys = await CaptureKeysAsync(device, svk, sek);
        var codec = new FdoCoseEncryptThenMacCodec();
        byte[] firstPlaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(3);
        ReadOnlyMemory<byte> first = device.Seal(firstPlaintext);
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage firstMessage = codec.VerifyAndParse(suite, svk, first);

        byte[] otherPlaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(21);
        byte[] otherCiphertext = FdoCoseEncryptThenMacCbcTests.ReferenceEncrypt(
            sek, firstMessage.CounterBlock, otherPlaintext);
        byte[] reused = Envelope(suiteValue, macType, svk, firstMessage.CounterBlock, otherCiphertext);
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage verified = codec.VerifyAndParse(suite, svk, reused);
        await Assert.That(firstMessage.Ciphertext.Length).IsEqualTo(16);
        await Assert.That(verified.Ciphertext.Length).IsEqualTo(32);
        await Assert.That(first.Span.SequenceEqual(reused)).IsFalse();
        await Assert.That(verified.CounterBlock.AsSpan().SequenceEqual(firstMessage.CounterBlock)).IsTrue();
        await Assert.That(verified.Ciphertext.AsSpan().SequenceEqual(otherCiphertext)).IsTrue();
        await Assert.That(codec.Decrypt(suite, sek, verified).AsSpan().SequenceEqual(otherPlaintext)).IsTrue();

        Exception failure = Capture<CryptographicException>(() => device.Open(reused));
        await AssertClosedAndErasedAsync(device, keys, sessionKey, svk, sek);
        await AssertNormalizedAsync(failure);
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5)]
    [Arguments(Suite256, 64, 32, 6)]
    public async Task BadMacAndAuthenticatedBadPadding_HaveSameNormalizedFailure(
        int suiteValue, int svkLength, int sekLength, int macType)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(0);
        byte[] ciphertext = FdoCoseEncryptThenMacCbcTests.ReferenceEncrypt(sek, FixedIv, plaintext);
        byte[] valid = Envelope(suiteValue, macType, svk, FixedIv, ciphertext);
        var codec = new FdoCoseEncryptThenMacCodec();
        await Assert.That(plaintext.Length).IsEqualTo(1);
        await Assert.That(plaintext[0]).IsEqualTo((byte)0x40);
        await Assert.That(ciphertext.Length).IsEqualTo(16);
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage good = codec.VerifyAndParse(suite, svk, valid);
        await Assert.That(codec.Decrypt(suite, sek, good).AsSpan().SequenceEqual(plaintext)).IsTrue();

        byte[] badMac = (byte[])valid.Clone();
        badMac[^1] ^= 0x01;
        await Assert.That(Throws<CryptographicException>(() =>
            codec.VerifyAndParse(suite, svk, badMac))).IsTrue();

        // The original final padding byte is 0x0F; this IV change makes it 0x00.
        byte[] badIv = (byte[])FixedIv.Clone();
        badIv[^1] ^= 0x0F;
        byte[] badPadding = Envelope(suiteValue, macType, svk, badIv, ciphertext);
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage paddingMessage =
            codec.VerifyAndParse(suite, svk, badPadding);
        await Assert.That(paddingMessage.CounterBlock.AsSpan().SequenceEqual(badIv)).IsTrue();
        await Assert.That(paddingMessage.Ciphertext.AsSpan().SequenceEqual(ciphertext)).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decrypt(suite, sek, paddingMessage))).IsTrue();

        byte[] shortCiphertext = ciphertext[..15];
        byte[] badLength = Envelope(suiteValue, macType, svk, FixedIv, shortCiphertext);
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage lengthMessage =
            codec.VerifyAndParse(suite, svk, badLength);
        await Assert.That(lengthMessage.CounterBlock.AsSpan().SequenceEqual(FixedIv)).IsTrue();
        await Assert.That(lengthMessage.Ciphertext.AsSpan().SequenceEqual(shortCiphertext)).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Decrypt(suite, sek, lengthMessage))).IsTrue();

        Exception macFailure = await OpenFailureAsync<CryptographicException>(suite, sessionKey, svk, sek, badMac);
        Exception paddingFailure = await OpenFailureAsync<CryptographicException>(suite, sessionKey, svk, sek, badPadding);
        Exception lengthFailure = await OpenFailureAsync<CryptographicException>(suite, sessionKey, svk, sek, badLength);
        Exception replayFailure = await ReplayFailureAsync(suite, sessionKey, svk, sek);
        Exception reflectionFailure = await ReflectionFailureAsync(suite, sessionKey, svk, sek);

        // Equal exception type/message and null inner exception do not establish end-to-end timing conformance.
        foreach (Exception failure in new[]
        {
            macFailure, paddingFailure, lengthFailure, replayFailure, reflectionFailure,
        })
        {
            await AssertNormalizedAsync(failure);
            await Assert.That(failure.GetType() == macFailure.GetType()).IsTrue();
            await Assert.That(failure.Message).IsEqualTo(macFailure.Message);
        }
    }

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task Constructors_RejectInvalidRoleSuiteKeyAndLimits(int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        using var valid = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Device, suite, sessionKey);
        var keys = await CaptureKeysAsync(valid, svk, sek);
        await Assert.That(keys.VerificationKey.Length).IsEqualTo(svkLength);
        await Assert.That(keys.EncryptionKey.Length).IsEqualTo(sekLength);

        await Assert.That(RejectsConstructor<ArgumentOutOfRangeException>(() =>
            new FdoTo2PairedCbcEtmChannel((FdoTo2PairedRole)int.MaxValue, suite, sessionKey))).IsTrue();
        await Assert.That(RejectsConstructor<ArgumentOutOfRangeException>(() =>
            new FdoTo2PairedCbcEtmChannel(
                FdoTo2PairedRole.Device, (FdoCoseAeadAlgorithm)int.MaxValue, sessionKey))).IsTrue();
        await Assert.That(RejectsConstructor<ArgumentOutOfRangeException>(() =>
            new FdoTo2PairedCbcEtmChannel(
                FdoTo2PairedRole.Device, FdoCoseAeadAlgorithm.A128Gcm, sessionKey))).IsTrue();
        await Assert.That(RejectsConstructor<ArgumentOutOfRangeException>(() =>
            new FdoTo2PairedCbcEtmChannel(
                FdoTo2PairedRole.Device, FdoCoseAeadAlgorithm.AesCtr128HmacSha256, sessionKey))).IsTrue();

        foreach (int length in new[] { 0, sessionKey.Length - 1, sessionKey.Length + 1 })
        {
            byte[] invalidKey = new byte[length];
            await Assert.That(RejectsConstructor<ArgumentException>(() =>
                new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Device, suite, invalidKey))).IsTrue();
        }

        foreach (int limit in new[] { 0, -1 })
        {
            await Assert.That(RejectsConstructor<ArgumentOutOfRangeException>(() =>
                new FdoTo2PairedCbcEtmChannel(
                    FdoTo2PairedRole.Device, suite, sessionKey, maxEncodedBytes: limit))).IsTrue();
            await Assert.That(RejectsConstructor<ArgumentOutOfRangeException>(() =>
                new FdoTo2PairedCbcEtmChannel(
                    FdoTo2PairedRole.Device, suite, sessionKey, maxItems: limit))).IsTrue();
            await Assert.That(RejectsConstructor<ArgumentOutOfRangeException>(() =>
                new FdoTo2PairedCbcEtmChannel(
                    FdoTo2PairedRole.Device, suite, sessionKey, ushort.MaxValue, 32, ushort.MaxValue, limit))).IsTrue();
        }

        foreach (int depth in new[] { 0, 129 })
        {
            await Assert.That(RejectsConstructor<ArgumentOutOfRangeException>(() =>
                new FdoTo2PairedCbcEtmChannel(
                    FdoTo2PairedRole.Device, suite, sessionKey, maxDepth: depth))).IsTrue();
        }
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5)]
    [Arguments(Suite256, 64, 32, 6)]
    public async Task Open_RejectsAuthenticatedInvalidIvAndCiphertextLengths(
        int suiteValue, int svkLength, int sekLength, int macType)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(0);
        byte[] validCiphertext = FdoCoseEncryptThenMacCbcTests.ReferenceEncrypt(sek, FixedIv, plaintext);
        var codec = new FdoCoseEncryptThenMacCodec();

        foreach (int length in new[] { 0, 15, 17 })
        {
            byte[] signed = Envelope(suiteValue, macType, svk, new byte[length], validCiphertext);
            byte[] badMac = (byte[])signed.Clone();
            badMac[^1] ^= 0x01;
            await Assert.That(Throws<CryptographicException>(() =>
                codec.VerifyAndParse(suite, svk, badMac))).IsTrue();
            await Assert.That(Throws<CborContentException>(() =>
                codec.VerifyAndParse(suite, svk, signed))).IsTrue();

            Exception failure = await OpenFailureAsync<CborContentException>(suite, sessionKey, svk, sek, signed);
            await Assert.That(failure.GetType() == typeof(CborContentException)).IsTrue();
        }

        foreach (int length in new[] { 0, 1, 15, 17, 31 })
        {
            byte[] ciphertext = new byte[length];
            for (int i = 0; i < ciphertext.Length; i++)
            {
                ciphertext[i] = validCiphertext[i % validCiphertext.Length];
            }

            byte[] signed = Envelope(suiteValue, macType, svk, FixedIv, ciphertext);
            FdoCoseEncryptThenMacCodec.AuthenticatedMessage verified = codec.VerifyAndParse(suite, svk, signed);
            await Assert.That(verified.CounterBlock.AsSpan().SequenceEqual(FixedIv)).IsTrue();
            await Assert.That(verified.Ciphertext.AsSpan().SequenceEqual(ciphertext)).IsTrue();
            Exception failure = await OpenFailureAsync<CryptographicException>(suite, sessionKey, svk, sek, signed);
            await AssertNormalizedAsync(failure);
        }
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5)]
    [Arguments(Suite256, 64, 32, 6)]
    public async Task WrongTurn_IsRejected(int suiteValue, int svkLength, int sekLength, int macType)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(1);
        byte[] valid = EnvelopeForPlaintext(suiteValue, macType, svk, sek, FixedIv, plaintext);

        using var owner = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Owner, suite, sessionKey);
        var ownerKeys = await CaptureKeysAsync(owner, svk, sek);
        Exception ownerFailure = Capture<InvalidOperationException>(() => owner.Seal(plaintext));
        await Assert.That(ownerFailure.GetType() == typeof(InvalidOperationException)).IsTrue();
        await AssertClosedAndErasedAsync(owner, ownerKeys, sessionKey, svk, sek);

        using var device = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Device, suite, sessionKey);
        var deviceKeys = await CaptureKeysAsync(device, svk, sek);
        Exception deviceFailure = Capture<InvalidOperationException>(() => device.Open(valid));
        await Assert.That(deviceFailure.GetType() == typeof(InvalidOperationException)).IsTrue();
        await AssertClosedAndErasedAsync(device, deviceKeys, sessionKey, svk, sek);
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5)]
    [Arguments(Suite256, 64, 32, 6)]
    public async Task IvCapacity_ExhaustsOnSendAndReceive(int suiteValue, int svkLength, int sekLength, int macType)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        var codec = new FdoCoseEncryptThenMacCodec();
        byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(1);
        byte[] peerPlaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(2);

        using var sender = new FdoTo2PairedCbcEtmChannel(
            FdoTo2PairedRole.Device, suite, sessionKey, ushort.MaxValue, 32, ushort.MaxValue, 2);
        var senderKeys = await CaptureKeysAsync(sender, svk, sek);
        ReadOnlyMemory<byte> sent = sender.Seal(plaintext);
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage sentMessage = codec.VerifyAndParse(suite, svk, sent);
        byte[] secondIv = DistinctIv(sentMessage.CounterBlock, sentMessage.CounterBlock);
        await Assert.That(secondIv.AsSpan().SequenceEqual(sentMessage.CounterBlock)).IsFalse();
        byte[] peerMessage = EnvelopeForPlaintext(suiteValue, macType, svk, sek, secondIv, peerPlaintext);
        await Assert.That(sender.Open(peerMessage).AsSpan().SequenceEqual(peerPlaintext)).IsTrue();
        Exception sendFailure = Capture<CryptographicException>(() => sender.Seal(plaintext));
        await Assert.That(sendFailure.GetType() == typeof(CryptographicException)).IsTrue();
        await AssertClosedAndErasedAsync(sender, senderKeys, sessionKey, svk, sek);

        using var receiver = new FdoTo2PairedCbcEtmChannel(
            FdoTo2PairedRole.Owner, suite, sessionKey, ushort.MaxValue, 32, ushort.MaxValue, 2);
        var receiverKeys = await CaptureKeysAsync(receiver, svk, sek);
        byte[] firstIv = (byte[])FixedIv.Clone();
        byte[] first = EnvelopeForPlaintext(suiteValue, macType, svk, sek, firstIv, plaintext);
        await Assert.That(receiver.Open(first).AsSpan().SequenceEqual(plaintext)).IsTrue();
        ReadOnlyMemory<byte> reply = receiver.Seal(peerPlaintext);
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage replyMessage = codec.VerifyAndParse(suite, svk, reply);
        await Assert.That(replyMessage.CounterBlock.AsSpan().SequenceEqual(firstIv)).IsFalse();
        await Assert.That(codec.Decrypt(suite, sek, replyMessage).AsSpan().SequenceEqual(peerPlaintext)).IsTrue();

        byte[] thirdIv = DistinctIv(replyMessage.CounterBlock, firstIv);
        await Assert.That(thirdIv.AsSpan().SequenceEqual(firstIv)).IsFalse();
        await Assert.That(thirdIv.AsSpan().SequenceEqual(replyMessage.CounterBlock)).IsFalse();
        byte[] third = EnvelopeForPlaintext(suiteValue, macType, svk, sek, thirdIv, plaintext);
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage thirdMessage = codec.VerifyAndParse(suite, svk, third);
        await Assert.That(thirdMessage.CounterBlock.AsSpan().SequenceEqual(thirdIv)).IsTrue();
        await Assert.That(codec.Decrypt(suite, sek, thirdMessage).AsSpan().SequenceEqual(plaintext)).IsTrue();
        Exception receiveFailure = Capture<CryptographicException>(() => receiver.Open(third));
        await AssertNormalizedAsync(receiveFailure);
        await AssertClosedAndErasedAsync(receiver, receiverKeys, sessionKey, svk, sek);
    }

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task Dispose_ErasesKeysAndRejectsFurtherUse(int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        using var channel = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Device, suite, sessionKey);
        var keys = await CaptureKeysAsync(channel, svk, sek);
        channel.Dispose();
        await AssertClosedAndErasedAsync(channel, keys, sessionKey, svk, sek);
        channel.Dispose();
    }

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task Seal_RejectsInvalidPlaintextAndOversizedEnvelope(int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        byte[][] malformed = [Array.Empty<byte>(), [0x00, 0x01]];
        foreach (byte[] plaintext in malformed)
        {
            using var channel = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Device, suite, sessionKey);
            var keys = await CaptureKeysAsync(channel, svk, sek);
            byte[] original = (byte[])plaintext.Clone();
            _ = Capture<CborContentException>(() => channel.Seal(plaintext));
            await Assert.That(plaintext.AsSpan().SequenceEqual(original)).IsTrue();
            await AssertClosedAndErasedAsync(channel, keys, sessionKey, svk, sek);
        }

        using var limited = new FdoTo2PairedCbcEtmChannel(
            FdoTo2PairedRole.Device, suite, sessionKey, maxEncodedBytes: 32);
        var limitedKeys = await CaptureKeysAsync(limited, svk, sek);
        byte[] valid = FdoCoseEncryptThenMacCodecTests.Plaintext(0);
        await Assert.That(valid.Length).IsEqualTo(1);
        _ = Capture<CborContentException>(() => limited.Seal(valid));
        await AssertClosedAndErasedAsync(limited, limitedKeys, sessionKey, svk, sek);
    }

    [Test]
    [Arguments(Suite128, 32, 16, 5)]
    [Arguments(Suite256, 64, 32, 6)]
    public async Task Open_RejectsMalformedOuterAndCloses(
        int suiteValue, int svkLength, int sekLength, int macType)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        byte[] valid = EnvelopeForPlaintext(
            suiteValue, macType, svk, sek, FixedIv, FdoCoseEncryptThenMacCodecTests.Plaintext(1));
        byte[][] malformed = [Array.Empty<byte>(), [0x00], [.. valid, 0x00]];
        foreach (byte[] encoded in malformed)
        {
            Exception failure = await OpenFailureAsync<CborContentException>(suite, sessionKey, svk, sek, encoded);
            await Assert.That(failure.GetType() == typeof(CborContentException)).IsTrue();
        }
    }

    [Test]
    [Arguments(Suite128, 32, 16)]
    [Arguments(Suite256, 64, 32)]
    public async Task Factory_SelectsCbcChannelForBothSuites(int suiteValue, int svkLength, int sekLength)
    {
        if (!FdoAesCbc.IsSupported)
        {
            return;
        }

        var suite = (FdoCoseAeadAlgorithm)suiteValue;
        (byte[] svk, byte[] sek) = FdoCoseEncryptThenMacCodecTests.Keys(svkLength, sekLength);
        byte[] sessionKey = SessionKey(svk, sek);
        using IFdoTo2PairedChannel channel = FdoTo2PairedChannels.Create(
            FdoTo2PairedRole.Device, suite, sessionKey);
        await Assert.That(channel is FdoTo2PairedCbcEtmChannel).IsTrue();
        byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(1);
        ReadOnlyMemory<byte> encoded = channel.Seal(plaintext);
        var codec = new FdoCoseEncryptThenMacCodec();
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage message = codec.VerifyAndParse(suite, svk, encoded);
        await Assert.That(message.CounterBlock.Length).IsEqualTo(16);
        await Assert.That(codec.Decrypt(suite, sek, message).AsSpan().SequenceEqual(plaintext)).IsTrue();
    }

    private static async Task<Exception> ReplayFailureAsync(
        FdoCoseAeadAlgorithm suite, byte[] sessionKey, byte[] svk, byte[] sek)
    {
        using var device = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Device, suite, sessionKey);
        using var owner = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Owner, suite, sessionKey);
        var keys = await CaptureKeysAsync(owner, svk, sek);
        byte[] requestPlaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(3);
        ReadOnlyMemory<byte> request = device.Seal(requestPlaintext);
        await Assert.That(owner.Open(request).AsSpan().SequenceEqual(requestPlaintext)).IsTrue();
        byte[] replyPlaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(6);
        ReadOnlyMemory<byte> reply = owner.Seal(replyPlaintext);
        await Assert.That(device.Open(reply).AsSpan().SequenceEqual(replyPlaintext)).IsTrue();

        Exception failure = Capture<CryptographicException>(() => owner.Open(request));
        await AssertClosedAndErasedAsync(owner, keys, sessionKey, svk, sek);
        return failure;
    }

    private static async Task<Exception> ReflectionFailureAsync(
        FdoCoseAeadAlgorithm suite, byte[] sessionKey, byte[] svk, byte[] sek)
    {
        using var device = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Device, suite, sessionKey);
        var keys = await CaptureKeysAsync(device, svk, sek);
        byte[] plaintext = FdoCoseEncryptThenMacCodecTests.Plaintext(4);
        ReadOnlyMemory<byte> encoded = device.Seal(plaintext);
        var codec = new FdoCoseEncryptThenMacCodec();
        FdoCoseEncryptThenMacCodec.AuthenticatedMessage message = codec.VerifyAndParse(suite, svk, encoded);
        await Assert.That(codec.Decrypt(suite, sek, message).AsSpan().SequenceEqual(plaintext)).IsTrue();

        Exception failure = Capture<CryptographicException>(() => device.Open(encoded));
        await AssertClosedAndErasedAsync(device, keys, sessionKey, svk, sek);
        return failure;
    }

    private static async Task<TException> OpenFailureAsync<TException>(
        FdoCoseAeadAlgorithm suite, byte[] sessionKey, byte[] svk, byte[] sek, byte[] encoded)
        where TException : Exception
    {
        using var owner = new FdoTo2PairedCbcEtmChannel(FdoTo2PairedRole.Owner, suite, sessionKey);
        var keys = await CaptureKeysAsync(owner, svk, sek);
        TException failure = Capture<TException>(() => owner.Open(encoded));
        await AssertClosedAndErasedAsync(owner, keys, sessionKey, svk, sek);
        return failure;
    }

    private static async Task<(byte[] VerificationKey, byte[] EncryptionKey)> CaptureKeysAsync(
        FdoTo2PairedCbcEtmChannel channel, byte[] svk, byte[] sek)
    {
        const BindingFlags Flags = BindingFlags.Instance | BindingFlags.NonPublic;
        byte[] verificationKey = typeof(FdoTo2PairedCbcEtmChannel)
            .GetField("_verificationKey", Flags)?.GetValue(channel) as byte[]
            ?? throw new InvalidOperationException("The private verification key was not found.");
        byte[] encryptionKey = typeof(FdoTo2PairedCbcEtmChannel)
            .GetField("_encryptionKey", Flags)?.GetValue(channel) as byte[]
            ?? throw new InvalidOperationException("The private encryption key was not found.");
        await Assert.That(verificationKey.AsSpan().SequenceEqual(svk)).IsTrue();
        await Assert.That(encryptionKey.AsSpan().SequenceEqual(sek)).IsTrue();
        return (verificationKey, encryptionKey);
    }

    private static async Task AssertClosedAndErasedAsync(
        FdoTo2PairedCbcEtmChannel channel,
        (byte[] VerificationKey, byte[] EncryptionKey) keys,
        byte[] sessionKey,
        byte[] svk,
        byte[] sek)
    {
        await Assert.That(keys.VerificationKey.AsSpan().SequenceEqual(new byte[svk.Length])).IsTrue();
        await Assert.That(keys.EncryptionKey.AsSpan().SequenceEqual(new byte[sek.Length])).IsTrue();
        await Assert.That(sessionKey.AsSpan().SequenceEqual(SessionKey(svk, sek))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() =>
            channel.Seal(FdoCoseEncryptThenMacCodecTests.Plaintext(0)))).IsTrue();
        await Assert.That(Throws<ObjectDisposedException>(() => channel.Open(Array.Empty<byte>()))).IsTrue();
    }

    private static async Task AssertNormalizedAsync(Exception failure)
    {
        await Assert.That(failure.GetType() == typeof(CryptographicException)).IsTrue();
        await Assert.That(failure.InnerException is null).IsTrue();
    }

    private static byte[] SessionKey(byte[] svk, byte[] sek) => [.. svk, .. sek];

    private static byte[] EnvelopeForPlaintext(
        int suiteValue, int macType, byte[] svk, byte[] sek, byte[] iv, byte[] plaintext)
    {
        byte[] ciphertext = FdoCoseEncryptThenMacCbcTests.ReferenceEncrypt(sek, iv, plaintext);
        return Envelope(suiteValue, macType, svk, iv, ciphertext);
    }

    private static byte[] Envelope(int suiteValue, int macType, byte[] svk, byte[] iv, byte[] ciphertext)
    {
        byte[] inner = EtmEnvelope.Encrypt0(EtmEnvelope.Protected(suiteValue), iv, ciphertext);
        return EtmEnvelope.Mac0(macType, svk, EtmEnvelope.Protected(macType), inner);
    }

    private static byte[] DistinctIv(byte[] first, byte[] second)
    {
        byte[] result = (byte[])first.Clone();
        result[0] ^= 0x01;
        if (result.AsSpan().SequenceEqual(second))
        {
            result[0] ^= 0x02;
        }

        return result;
    }

    private static bool IsSimpleCounterSequence(List<byte[]> ivs)
    {
        bool bigEndian = true;
        bool littleEndian = true;
        for (int i = 1; i < ivs.Count; i++)
        {
            bigEndian &= IsNextCounter(ivs[i - 1], ivs[i], littleEndian: false);
            littleEndian &= IsNextCounter(ivs[i - 1], ivs[i], littleEndian: true);
        }

        return bigEndian || littleEndian;
    }

    private static bool IsNextCounter(byte[] previous, byte[] current, bool littleEndian)
    {
        byte[] next = (byte[])previous.Clone();
        for (int i = 0; i < next.Length; i++)
        {
            int index = littleEndian ? i : next.Length - 1 - i;
            next[index] = unchecked((byte)(next[index] + 1));
            if (next[index] != 0)
            {
                break;
            }
        }

        return next.AsSpan().SequenceEqual(current);
    }

    private static bool RejectsConstructor<TException>(Func<FdoTo2PairedCbcEtmChannel> create)
        where TException : Exception
    {
        try
        {
            using FdoTo2PairedCbcEtmChannel channel = create();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }

    private static TException Capture<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException("The operation unexpectedly accepted the input.");
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
