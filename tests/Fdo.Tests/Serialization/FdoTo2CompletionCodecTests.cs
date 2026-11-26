// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Tests.Serialization;

public sealed class FdoTo2CompletionCodecTests
{
    private const string NonceHex = "000102030405060708090A0B0C0D0E0F";
    private const string Hmac256Hex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    private const string Hmac384Hex =
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F";

    [Test]
    public async Task DoneForCredentialReuseEncodesNonceThenNull()
    {
        byte[] nonce = Convert.FromHexString(NonceHex);
        byte[] expected = Convert.FromHexString("8250" + NonceHex + "F6");

        ReadOnlyMemory<byte> encoded = FdoTo2CompletionCodec.EncodeDone(nonce, null);
        FdoTo2CompletionCodec.Done20 decoded = FdoTo2CompletionCodec.DecodeDone(expected);

        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo(Convert.ToHexString(expected));
        await Assert.That(Convert.ToHexString(decoded.Nonce.Span)).IsEqualTo(NonceHex);
        await Assert.That(decoded.ReplacementHmac).IsNull();
    }

    [Test]
    [Arguments(5, Hmac256Hex, "5820")]
    [Arguments(6, Hmac384Hex, "5830")]
    public async Task DoneForReplacementEncodesNonceThenHmac(
        int algorithm, string hmacHex, string byteStringHeader)
    {
        byte[] nonce = Convert.FromHexString(NonceHex);
        var hmac = new FdoHashValue((FdoHashAlgorithm)algorithm, Convert.FromHexString(hmacHex));
        string expected = "8250" + NonceHex + "820" + algorithm + byteStringHeader + hmacHex;

        ReadOnlyMemory<byte> encoded = FdoTo2CompletionCodec.EncodeDone(nonce, hmac);
        FdoTo2CompletionCodec.Done20 decoded = FdoTo2CompletionCodec.DecodeDone(Convert.FromHexString(expected));
        FdoHashValue decodedHmac = decoded.ReplacementHmac
            ?? throw new InvalidOperationException("The replacement HMAC was absent.");

        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo(expected);
        await Assert.That(Convert.ToHexString(decoded.Nonce.Span)).IsEqualTo(NonceHex);
        await Assert.That(decodedHmac.Algorithm).IsEqualTo((FdoHashAlgorithm)algorithm);
        await Assert.That(Convert.ToHexString(decodedHmac.Value)).IsEqualTo(hmacHex);
    }

    [Test]
    public async Task DoneAckContainsOnlyTheSetupNonce()
    {
        byte[] nonce = Convert.FromHexString(NonceHex);
        const string expected = "8150" + NonceHex;

        ReadOnlyMemory<byte> encoded = FdoTo2CompletionCodec.EncodeDoneAck(nonce);
        ReadOnlyMemory<byte> decoded = FdoTo2CompletionCodec.DecodeDoneAck(Convert.FromHexString(expected));

        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo(expected);
        await Assert.That(Convert.ToHexString(decoded.Span)).IsEqualTo(NonceHex);
    }

    [Test]
    [Arguments("")]
    [Arguments("80")]
    [Arguments("8150000102030405060708090A0B0C0D0E0F")]
    [Arguments("8350000102030405060708090A0B0C0D0E0FF600")]
    [Arguments("824F000102030405060708090A0B0C0D0EF6")]
    [Arguments("8251000102030405060708090A0B0C0D0E0F10F6")]
    [Arguments("8200F6")]
    [Arguments("8250000102030405060708090A0B0C0D0E0F00")]
    [Arguments("8250000102030405060708090A0B0C0D0E0F8205581F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E")]
    [Arguments("8250000102030405060708090A0B0C0D0E0F82075820000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")]
    [Arguments("8250000102030405060708090A0B0C0D0E0F822F5820000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")]
    [Arguments("980250000102030405060708090A0B0C0D0E0FF6")]
    [Arguments("8250000102030405060708090A0B0C0D0E0FF600")]
    public async Task DecodeDoneRejectsMalformedBodiesAndNonHmacAlgorithms(string hex)
    {
        await Assert.That(Throws<CborContentException>(() =>
            FdoTo2CompletionCodec.DecodeDone(Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    [Arguments("80")]
    [Arguments("8200F6")]
    [Arguments("8100")]
    [Arguments("814F000102030405060708090A0B0C0D0E")]
    [Arguments("8151000102030405060708090A0B0C0D0E0F10")]
    [Arguments("8150000102030405060708090A0B0C0D0E0F00")]
    public async Task DecodeDoneAckRejectsMalformedBodies(string hex)
    {
        await Assert.That(Throws<CborContentException>(() =>
            FdoTo2CompletionCodec.DecodeDoneAck(Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    public async Task EncodingRejectsWrongNonceLengthsAndDigestAsReplacementHmac()
    {
        var digest = new FdoHashValue(FdoHashAlgorithm.Sha256, new byte[32]);
        byte[] nonce = Convert.FromHexString(NonceHex);

        await Assert.That(Throws<ArgumentException>(() =>
            FdoTo2CompletionCodec.EncodeDone(new byte[15], null))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoTo2CompletionCodec.EncodeDone(new byte[17], null))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoTo2CompletionCodec.EncodeDoneAck(new byte[15]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoTo2CompletionCodec.EncodeDoneAck(new byte[17]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => FdoTo2CompletionCodec.EncodeDone(nonce, digest))).IsTrue();
    }

    [Test]
    public async Task DecodedNoncesAndEncodedBodiesOwnTheirInputBytes()
    {
        byte[] input = Convert.FromHexString("8250" + NonceHex + "F6");
        byte[] ackInput = Convert.FromHexString("8150" + NonceHex);
        byte[] nonce = Convert.FromHexString(NonceHex);

        FdoTo2CompletionCodec.Done20 decoded = FdoTo2CompletionCodec.DecodeDone(input);
        ReadOnlyMemory<byte> decodedAck = FdoTo2CompletionCodec.DecodeDoneAck(ackInput);
        ReadOnlyMemory<byte> encoded = FdoTo2CompletionCodec.EncodeDone(nonce, null);
        Array.Fill(input, (byte)0);
        Array.Fill(ackInput, (byte)0);
        Array.Fill(nonce, (byte)0);

        await Assert.That(Convert.ToHexString(decoded.Nonce.Span)).IsEqualTo(NonceHex);
        await Assert.That(Convert.ToHexString(decodedAck.Span)).IsEqualTo(NonceHex);
        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo("8250" + NonceHex + "F6");
    }

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException exception)
        {
            return exception.GetType() == typeof(TException);
        }
    }
}
