// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;
using Fdo.ServiceInfo;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.Tests.ServiceInfo;

[UnsupportedOSPlatform("browser")]
public sealed class FdoTo2ServiceInfoStateTests
{
    private static readonly byte[] Nonce = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
    private static readonly Entry Data = new("test:value", new byte[] { 0x01 });

    [Test]
    public async Task TracksAProtectedPairedExchangeWithMoreMessagesAndKeepalive()
    {
        if (!FdoCoseAead.IsSupported(FdoCoseAeadAlgorithm.A128Gcm))
        {
            return;
        }

        using var deviceChannel = new FdoTo2PairedAeadChannel(
            FdoTo2PairedRole.Device, FdoCoseAeadAlgorithm.A128Gcm, new byte[16]);
        using var ownerChannel = new FdoTo2PairedAeadChannel(
            FdoTo2PairedRole.Owner, FdoCoseAeadAlgorithm.A128Gcm, new byte[16]);
        var deviceState = new FdoTo2ServiceInfoState(Nonce);
        var ownerState = new FdoTo2ServiceInfoState(Nonce);

        TransferDevice(deviceState, ownerState, deviceChannel, ownerChannel, Device(true, Data));
        TransferOwner(deviceState, ownerState, deviceChannel, ownerChannel, Owner(false, false));
        TransferDevice(deviceState, ownerState, deviceChannel, ownerChannel, Device(false, Data));
        TransferOwner(deviceState, ownerState, deviceChannel, ownerChannel, Owner(true, false, Data));
        TransferDevice(deviceState, ownerState, deviceChannel, ownerChannel, Device(false));
        TransferOwner(deviceState, ownerState, deviceChannel, ownerChannel, Owner(false, true, Data));
        TransferDevice(deviceState, ownerState, deviceChannel, ownerChannel, Device(false));
        TransferOwner(deviceState, ownerState, deviceChannel, ownerChannel, Owner(false, true));

        ReadOnlyMemory<byte> done = new FdoTo2CompletionCodec().EncodeDone(Nonce, null);
        deviceState.RecordDone(done);
        byte[] receivedDone = ownerChannel.Open(deviceChannel.Seal(done));
        try
        {
            ownerState.RecordDone(receivedDone);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(receivedDone);
        }

        await Assert.That(Throws<InvalidOperationException>(() => deviceState.RecordDone(done))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => ownerState.RecordDevice(Device(false)))).IsTrue();
    }

    [Test]
    public async Task RequiresAnEmptyOwnerReplyWhileTheDeviceHasMore()
    {
        ReadOnlyMemory<byte>[] invalid =
        [
            Owner(true, false),
            Owner(false, true),
            Owner(false, false, Data),
        ];
        foreach (ReadOnlyMemory<byte> reply in invalid)
        {
            var state = new FdoTo2ServiceInfoState(Nonce);
            state.RecordDevice(Device(true, Data));

            await Assert.That(Throws<CborContentException>(() => state.RecordOwner(reply))).IsTrue();
            await Assert.That(Throws<InvalidOperationException>(() =>
                state.RecordOwner(Owner(false, false)))).IsTrue();
        }
    }

    [Test]
    public async Task RequiresAnEmptyDeviceReplyWhileTheOwnerHasMore()
    {
        foreach (ReadOnlyMemory<byte> reply in (ReadOnlyMemory<byte>[])[Device(true), Device(false, Data)])
        {
            var state = new FdoTo2ServiceInfoState(Nonce);
            state.RecordDevice(Device(false));
            state.RecordOwner(Owner(true, false, Data));

            await Assert.That(Throws<CborContentException>(() => state.RecordDevice(reply))).IsTrue();
            await Assert.That(Throws<InvalidOperationException>(() => state.RecordDevice(Device(false)))).IsTrue();
        }
    }

    [Test]
    public async Task FinishedServiceInfoCannotBeReopenedOrCarryLaterEntries()
    {
        var reopened = NewAfterOwnerDone();
        reopened.RecordDevice(Device(false));
        await Assert.That(Throws<CborContentException>(() =>
            reopened.RecordOwner(Owner(false, false)))).IsTrue();

        var deviceData = NewAfterOwnerDone();
        await Assert.That(Throws<CborContentException>(() =>
            deviceData.RecordDevice(Device(false, Data)))).IsTrue();

        var ownerData = NewAfterOwnerDone();
        ownerData.RecordDevice(Device(false));
        await Assert.That(Throws<CborContentException>(() =>
            ownerData.RecordOwner(Owner(false, true, Data)))).IsTrue();

        var contradictory = new FdoTo2ServiceInfoState(Nonce);
        contradictory.RecordDevice(Device(false));
        await Assert.That(Throws<CborContentException>(() =>
            contradictory.RecordOwner(Owner(true, true)))).IsTrue();
    }

    [Test]
    public async Task RequiresOwnerDoneMatchingChallengeAndNullReuseHmac()
    {
        var completion = new FdoTo2CompletionCodec();
        ReadOnlyMemory<byte> done = completion.EncodeDone(Nonce, null);
        var premature = new FdoTo2ServiceInfoState(Nonce);
        await Assert.That(Throws<InvalidOperationException>(() => premature.RecordDone(done))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => premature.RecordDevice(Device(false)))).IsTrue();

        byte[] wrongNonce = (byte[])Nonce.Clone();
        wrongNonce[0] ^= 1;
        var wrongChallenge = NewAfterOwnerDone();
        await Assert.That(Throws<CryptographicException>(() =>
            wrongChallenge.RecordDone(completion.EncodeDone(wrongNonce, null)))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => wrongChallenge.RecordDone(done))).IsTrue();

        var replacement = new FdoHashValue(FdoHashAlgorithm.HmacSha256, new byte[32]);
        var wrongDisposition = NewAfterOwnerDone();
        await Assert.That(Throws<CborContentException>(() =>
            wrongDisposition.RecordDone(completion.EncodeDone(Nonce, replacement)))).IsTrue();

        byte[] sourceNonce = (byte[])Nonce.Clone();
        var copied = new FdoTo2ServiceInfoState(sourceNonce);
        Array.Fill(sourceNonce, (byte)0);
        copied.RecordDevice(Device(false));
        copied.RecordOwner(Owner(false, true));
        copied.RecordDone(done);
    }

    [Test]
    public async Task AcceptsAndPreservesTheSelectedReplacementHmac()
    {
        var completion = new FdoTo2CompletionCodec();
        foreach (FdoHashAlgorithm algorithm in new[] { FdoHashAlgorithm.HmacSha256, FdoHashAlgorithm.HmacSha384 })
        {
            byte[] value = new byte[algorithm == FdoHashAlgorithm.HmacSha256 ? 32 : 48];
            Array.Fill(value, (byte)0xa5);
            var expected = new FdoHashValue(algorithm, value);
            var state = NewAfterOwnerDone();

            FdoHashValue? actual = state.RecordDone(completion.EncodeDone(Nonce, expected), algorithm);

            await Assert.That(actual is not null).IsTrue();
            await Assert.That(actual!.Encode().Span.SequenceEqual(expected.Encode().Span)).IsTrue();
            await Assert.That(Throws<InvalidOperationException>(() =>
                state.RecordDone(completion.EncodeDone(Nonce, expected), algorithm))).IsTrue();
        }
    }

    [Test]
    public async Task RejectsMissingOrWrongAlgorithmReplacementHmacAndEndsState()
    {
        var completion = new FdoTo2CompletionCodec();
        var missing = NewAfterOwnerDone();
        ReadOnlyMemory<byte> missingHmac = completion.EncodeDone(Nonce, null);
        await Assert.That(Throws<CborContentException>(() =>
            missing.RecordDone(missingHmac, FdoHashAlgorithm.HmacSha256))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            missing.RecordDone(missingHmac, FdoHashAlgorithm.HmacSha256))).IsTrue();

        var wrong = NewAfterOwnerDone();
        var hmac384 = new FdoHashValue(FdoHashAlgorithm.HmacSha384, new byte[48]);
        ReadOnlyMemory<byte> wrongHmac = completion.EncodeDone(Nonce, hmac384);
        await Assert.That(Throws<CborContentException>(() =>
            wrong.RecordDone(wrongHmac, FdoHashAlgorithm.HmacSha256))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            wrong.RecordDone(wrongHmac, FdoHashAlgorithm.HmacSha256))).IsTrue();
    }

    [Test]
    public async Task RejectsReplacementDoneWithWrongNonceAndEndsState()
    {
        byte[] nonce = (byte[])Nonce.Clone();
        nonce[0] ^= 1;
        var hmac = new FdoHashValue(FdoHashAlgorithm.HmacSha256, new byte[32]);
        ReadOnlyMemory<byte> done = new FdoTo2CompletionCodec().EncodeDone(nonce, hmac);
        var state = NewAfterOwnerDone();

        await Assert.That(Throws<CryptographicException>(() =>
            state.RecordDone(done, FdoHashAlgorithm.HmacSha256))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            state.RecordDone(done, FdoHashAlgorithm.HmacSha256))).IsTrue();
    }

    [Test]
    public async Task RejectsMalformedReplacementHmacAndEndsState()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(2);
        writer.WriteByteString(Nonce);
        writer.WriteStartArray(2);
        writer.WriteInt32((int)FdoHashAlgorithm.HmacSha256);
        writer.WriteByteString(new byte[31]);
        writer.WriteEndArray();
        writer.WriteEndArray();
        byte[] done = writer.Encode();
        var state = NewAfterOwnerDone();

        await Assert.That(Throws<CborContentException>(() =>
            state.RecordDone(done, FdoHashAlgorithm.HmacSha256))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            state.RecordDone(done, FdoHashAlgorithm.HmacSha256))).IsTrue();
    }

    [Test]
    public async Task EnforcesSeparateEncodedPlaintextBounds()
    {
        ReadOnlyMemory<byte> deviceMessage = Device(false, Data);
        ReadOnlyMemory<byte> ownerMessage = Owner(false, false, Data);
        var deviceAtLimit = new FdoTo2ServiceInfoState(Nonce, maxDevicePlaintextBytes: deviceMessage.Length);
        var deviceBelowLimit = new FdoTo2ServiceInfoState(Nonce, maxDevicePlaintextBytes: deviceMessage.Length - 1);
        var ownerAtLimit = new FdoTo2ServiceInfoState(Nonce, maxOwnerPlaintextBytes: ownerMessage.Length);
        var ownerBelowLimit = new FdoTo2ServiceInfoState(Nonce, maxOwnerPlaintextBytes: ownerMessage.Length - 1);

        deviceAtLimit.RecordDevice(deviceMessage);
        await Assert.That(Throws<CborContentException>(() => deviceBelowLimit.RecordDevice(deviceMessage))).IsTrue();
        ownerAtLimit.RecordDevice(Device(false));
        ownerAtLimit.RecordOwner(ownerMessage);
        ownerBelowLimit.RecordDevice(Device(false));
        await Assert.That(Throws<CborContentException>(() => ownerBelowLimit.RecordOwner(ownerMessage))).IsTrue();
    }

    [Test]
    public async Task CountsKeepalivesAndRejectsTheRoundAfterTheLimit()
    {
        var state = NewAfterOwnerDone();
        for (int round = 2; round <= FdoTo2ServiceInfoState.MaxRounds; round++)
        {
            state.RecordDevice(Device(false));
            state.RecordOwner(Owner(false, true));
        }

        await Assert.That(Throws<CborContentException>(() => state.RecordDevice(Device(false)))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => state.RecordDevice(Device(false)))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            state.RecordDone(new FdoTo2CompletionCodec().EncodeDone(Nonce, null)))).IsTrue();
    }

    [Test]
    public async Task CompletesAfterTheLastPermittedRound()
    {
        var state = NewAfterOwnerDone();
        for (int round = 2; round <= FdoTo2ServiceInfoState.MaxRounds; round++)
        {
            state.RecordDevice(Device(false));
            state.RecordOwner(Owner(false, true));
        }

        state.RecordDone(new FdoTo2CompletionCodec().EncodeDone(Nonce, null));
        await Assert.That(Throws<InvalidOperationException>(() => state.RecordDevice(Device(false)))).IsTrue();
    }

    [Test]
    public async Task RejectsOutOfOrderTurnsAndInvalidChallenges()
    {
        var ownerFirst = new FdoTo2ServiceInfoState(Nonce);
        await Assert.That(Throws<InvalidOperationException>(() =>
            ownerFirst.RecordOwner(Owner(false, false)))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => ownerFirst.RecordDevice(Device(false)))).IsTrue();

        var twice = new FdoTo2ServiceInfoState(Nonce);
        twice.RecordDevice(Device(false));
        await Assert.That(Throws<InvalidOperationException>(() => twice.RecordDevice(Device(false)))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new FdoTo2ServiceInfoState(new byte[15]))).IsTrue();
    }

    private static FdoTo2ServiceInfoState NewAfterOwnerDone()
    {
        var state = new FdoTo2ServiceInfoState(Nonce);
        state.RecordDevice(Device(false));
        state.RecordOwner(Owner(false, true));
        return state;
    }

    private static ReadOnlyMemory<byte> Device(bool more, params Entry[] entries) =>
        new FdoTo2ServiceInfoCodec().EncodeDevice(more, entries);

    private static ReadOnlyMemory<byte> Owner(bool more, bool done, params Entry[] entries) =>
        new FdoTo2ServiceInfoCodec().EncodeOwner(more, done, entries);

    private static void TransferDevice(
        FdoTo2ServiceInfoState deviceState,
        FdoTo2ServiceInfoState ownerState,
        FdoTo2PairedAeadChannel device,
        FdoTo2PairedAeadChannel owner,
        ReadOnlyMemory<byte> message)
    {
        deviceState.RecordDevice(message);
        byte[] plaintext = owner.Open(device.Seal(message));
        try
        {
            ownerState.RecordDevice(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static void TransferOwner(
        FdoTo2ServiceInfoState deviceState,
        FdoTo2ServiceInfoState ownerState,
        FdoTo2PairedAeadChannel device,
        FdoTo2PairedAeadChannel owner,
        ReadOnlyMemory<byte> message)
    {
        ownerState.RecordOwner(message);
        byte[] plaintext = device.Open(owner.Seal(message));
        try
        {
            deviceState.RecordOwner(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
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
