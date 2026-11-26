using System;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

public sealed class FdoOwnershipVoucherHeaderHmacTests
{
    [Test]
    [Arguments(5)]
    [Arguments(6)]
    public async Task ComputeUsesHeaderContentsWithoutTheOuterByteString(int algorithm)
    {
        var hmacAlgorithm = (FdoHashAlgorithm)algorithm;
        byte[] secret = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] header = Convert.FromHexString("8601500000000000000000000000000000008060A0F6");
        byte[] encodedHeaderTag = EncodeByteString(header);
        byte[] expected = algorithm == (int)FdoHashAlgorithm.HmacSha256
            ? HMACSHA256.HashData(secret, header)
            : HMACSHA384.HashData(secret, header);
        byte[] includesWrapper = algorithm == (int)FdoHashAlgorithm.HmacSha256
            ? HMACSHA256.HashData(secret, encodedHeaderTag)
            : HMACSHA384.HashData(secret, encodedHeaderTag);

        FdoHashValue actual = FdoOwnershipVoucherHeaderHmac.Compute(hmacAlgorithm, secret, encodedHeaderTag);

        await Assert.That(actual.Algorithm).IsEqualTo(hmacAlgorithm);
        await Assert.That(Convert.ToHexString(actual.Value)).IsEqualTo(Convert.ToHexString(expected));
        await Assert.That(Convert.ToHexString(actual.Value) != Convert.ToHexString(includesWrapper)).IsTrue();
    }

    [Test]
    [Arguments(5)]
    [Arguments(6)]
    public async Task VerifyChecksTheExpectedAlgorithmKeyAndHeaderContents(int algorithm)
    {
        var hmacAlgorithm = (FdoHashAlgorithm)algorithm;
        byte[] secret = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        byte[] header = Convert.FromHexString("8601500000000000000000000000000000008060A0F6");
        byte[] encodedHeaderTag = EncodeByteString(header);
        FdoHashValue expectedHmac = FdoOwnershipVoucherHeaderHmac.Compute(hmacAlgorithm, secret, encodedHeaderTag);
        byte[] changedSecret = (byte[])secret.Clone();
        changedSecret[0] ^= 0x01;
        byte[] changedHeader = (byte[])header.Clone();
        changedHeader[3] ^= 0x01;
        byte[] changedHeaderTag = EncodeByteString(changedHeader);

        await Assert.That(FdoOwnershipVoucherHeaderHmac.Verify(
            hmacAlgorithm, secret, encodedHeaderTag, expectedHmac)).IsTrue();
        await Assert.That(FdoOwnershipVoucherHeaderHmac.Verify(
            hmacAlgorithm, changedSecret, encodedHeaderTag, expectedHmac)).IsFalse();
        await Assert.That(FdoOwnershipVoucherHeaderHmac.Verify(
            hmacAlgorithm, secret, changedHeaderTag, expectedHmac)).IsFalse();

        FdoHashAlgorithm otherAlgorithm = hmacAlgorithm == FdoHashAlgorithm.HmacSha256
            ? FdoHashAlgorithm.HmacSha384
            : FdoHashAlgorithm.HmacSha256;
        await Assert.That(FdoOwnershipVoucherHeaderHmac.Verify(
            otherAlgorithm, secret, encodedHeaderTag, expectedHmac)).IsFalse();
    }

    [Test]
    [Arguments(5, "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7")]
    [Arguments(6, "AFD03944D84895626B0825F4AB46907F15F9DADBE4101EC682AA034C7CEBC59CFAEA9EA9076EDE7F4AF152E8B2FA9CB6")]
    public async Task ComputeAndVerifyAuthenticateOpaquePayloadWithKnownHmac(int algorithm, string expectedHex)
    {
        // The wrapped RFC 4231 case 1 data is opaque, not a complete CBOR value.
        byte[] secret = new byte[20];
        Array.Fill(secret, (byte)0x0B);
        byte[] encodedHeaderTag = Convert.FromHexString("484869205468657265");
        var type = (FdoHashAlgorithm)algorithm;
        var expectedHmac = new FdoHashValue(type, Convert.FromHexString(expectedHex));
        byte[] changedHmac = expectedHmac.Value;
        changedHmac[^1] ^= 0x01;
        var forgedHmac = new FdoHashValue(type, changedHmac);

        FdoHashValue actual = FdoOwnershipVoucherHeaderHmac.Compute(type, secret, encodedHeaderTag);

        await Assert.That(actual.Algorithm).IsEqualTo(type);
        await Assert.That(Convert.ToHexString(actual.Value)).IsEqualTo(expectedHex);
        await Assert.That(FdoOwnershipVoucherHeaderHmac.Verify(
            type, secret, encodedHeaderTag, expectedHmac)).IsTrue();
        await Assert.That(FdoOwnershipVoucherHeaderHmac.Verify(
            type, secret, encodedHeaderTag, forgedHmac)).IsFalse();
    }

    [Test]
    [Arguments(5)]
    [Arguments(6)]
    public async Task EmptyHeaderPayloadIsAuthenticatedWithoutTheWrapper(int algorithm)
    {
        byte[] secret = [0x01, 0x02, 0x03];
        byte[] emptyPayload = Array.Empty<byte>();
        byte[] encodedHeaderTag = [0x40];
        byte[] nonemptyHeaderTag = [0x41, 0x00];
        var type = (FdoHashAlgorithm)algorithm;
        byte[] expected = type == FdoHashAlgorithm.HmacSha256
            ? HMACSHA256.HashData(secret, emptyPayload)
            : HMACSHA384.HashData(secret, emptyPayload);
        var expectedHmac = new FdoHashValue(type, expected);

        FdoHashValue actual = FdoOwnershipVoucherHeaderHmac.Compute(type, secret, encodedHeaderTag);

        await Assert.That(actual.Algorithm).IsEqualTo(type);
        await Assert.That(Convert.ToHexString(actual.Value)).IsEqualTo(Convert.ToHexString(expected));
        await Assert.That(FdoOwnershipVoucherHeaderHmac.Verify(
            type, secret, encodedHeaderTag, expectedHmac)).IsTrue();
        await Assert.That(FdoOwnershipVoucherHeaderHmac.Verify(
            type, secret, nonemptyHeaderTag, expectedHmac)).IsFalse();
    }

    [Test]
    [Arguments("80")]
    [Arguments("5F4100FF")]
    [Arguments("410080")]
    [Arguments("FF")]
    public async Task ComputeRejectsInvalidOrNoncanonicalHeaderWrappers(string encodedHeaderTagHex)
    {
        byte[] secret = [0x01];
        byte[] encodedHeaderTag = Convert.FromHexString(encodedHeaderTagHex);

        await Assert.That(Throws<CborContentException>(() =>
            FdoOwnershipVoucherHeaderHmac.Compute(
                FdoHashAlgorithm.HmacSha256, secret, encodedHeaderTag))).IsTrue();
    }

    [Test]
    public async Task ComputeRejectsDigestAlgorithmsAndEmptySecrets()
    {
        byte[] secret = [0x01];
        byte[] encodedHeaderTag = EncodeByteString([0x80]);

        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoOwnershipVoucherHeaderHmac.Compute(
                FdoHashAlgorithm.Sha256, secret, encodedHeaderTag))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoOwnershipVoucherHeaderHmac.Compute(
                FdoHashAlgorithm.HmacSha256, ReadOnlySpan<byte>.Empty, encodedHeaderTag))).IsTrue();
    }

    [Test]
    [Arguments("")]
    [Arguments("80")]
    [Arguments("580100")]
    [Arguments("4200")]
    [Arguments("5F4100FF")]
    [Arguments("C04100")]
    [Arguments("410080")]
    public async Task HeaderOperationsRejectMalformedAndNoncanonicalWrappers(string encodedHeaderTagHex)
    {
        byte[] secret = [0x01];
        byte[] encodedHeaderTag = Convert.FromHexString(encodedHeaderTagHex);
        var expectedHmac = new FdoHashValue(FdoHashAlgorithm.HmacSha256, new byte[32]);

        await Assert.That(Throws<CborContentException>(() =>
            FdoOwnershipVoucherHeaderHmac.Compute(
                FdoHashAlgorithm.HmacSha256, secret, encodedHeaderTag))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            FdoOwnershipVoucherHeaderHmac.Verify(
                FdoHashAlgorithm.HmacSha256, secret, encodedHeaderTag, expectedHmac))).IsTrue();
    }

    [Test]
    [Arguments(-16)]
    [Arguments(-43)]
    [Arguments(0)]
    public async Task HeaderOperationsRejectNonHmacAlgorithms(int algorithm)
    {
        byte[] secret = [0x01];
        byte[] encodedHeaderTag = EncodeByteString([0x80]);
        var expectedHmac = new FdoHashValue(FdoHashAlgorithm.HmacSha256, new byte[32]);
        var type = (FdoHashAlgorithm)algorithm;

        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoOwnershipVoucherHeaderHmac.Compute(type, secret, encodedHeaderTag))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            FdoOwnershipVoucherHeaderHmac.Verify(type, secret, encodedHeaderTag, expectedHmac))).IsTrue();
    }

    [Test]
    [Arguments(5)]
    [Arguments(6)]
    public async Task VerifyRejectsNullHmacAndHeaderOperationsRejectEmptySecrets(int algorithm)
    {
        byte[] secret = [0x01];
        byte[] encodedHeaderTag = EncodeByteString([0x80]);
        var type = (FdoHashAlgorithm)algorithm;
        int valueLength = type == FdoHashAlgorithm.HmacSha256 ? 32 : 48;
        var expectedHmac = new FdoHashValue(type, new byte[valueLength]);

        await Assert.That(Throws<ArgumentNullException>(() =>
            FdoOwnershipVoucherHeaderHmac.Verify(type, secret, encodedHeaderTag, null!))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoOwnershipVoucherHeaderHmac.Compute(type, ReadOnlySpan<byte>.Empty, encodedHeaderTag))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            FdoOwnershipVoucherHeaderHmac.Verify(
                type, ReadOnlySpan<byte>.Empty, encodedHeaderTag, expectedHmac))).IsTrue();
    }

    [Test]
    [Arguments(5, 23, "57")]
    [Arguments(5, 24, "5818")]
    [Arguments(5, 255, "58FF")]
    [Arguments(5, 256, "590100")]
    [Arguments(6, 23, "57")]
    [Arguments(6, 24, "5818")]
    [Arguments(6, 255, "58FF")]
    [Arguments(6, 256, "590100")]
    public async Task HeaderTagAuthenticatesPayloadAcrossCborLengthBoundaries(
        int algorithm, int payloadLength, string wrapperHex)
    {
        byte[] secret = [0x01, 0x02, 0x03];
        byte[] payload = new byte[payloadLength];
        payload[0] = 0xA5;
        payload[^1] = 0x5A;
        byte[] wrapper = Convert.FromHexString(wrapperHex);
        byte[] encodedHeaderTag = new byte[wrapper.Length + payload.Length];
        wrapper.CopyTo(encodedHeaderTag, 0);
        payload.CopyTo(encodedHeaderTag, wrapper.Length);
        var type = (FdoHashAlgorithm)algorithm;
        byte[] expected = type == FdoHashAlgorithm.HmacSha256
            ? HMACSHA256.HashData(secret, payload)
            : HMACSHA384.HashData(secret, payload);
        var expectedHmac = new FdoHashValue(type, expected);

        FdoHashValue actual = FdoOwnershipVoucherHeaderHmac.Compute(type, secret, encodedHeaderTag);

        await Assert.That(actual.Algorithm).IsEqualTo(type);
        await Assert.That(Convert.ToHexString(actual.Value)).IsEqualTo(Convert.ToHexString(expected));
        await Assert.That(FdoOwnershipVoucherHeaderHmac.Verify(
            type, secret, encodedHeaderTag, expectedHmac)).IsTrue();
    }

    [Test]
    [Arguments(5)]
    [Arguments(6)]
    public async Task HeaderTagAcceptsTheSizeLimitAndRejectsTheNextByte(int algorithm)
    {
        byte[] secret = [0x01, 0x02, 0x03];
        byte[] payload = new byte[ushort.MaxValue - 3];
        payload[0] = 0xA5;
        payload[^1] = 0x5A;
        byte[] encodedHeaderTag = EncodeByteString(payload);
        byte[] oversizedPayload = new byte[payload.Length + 1];
        payload.CopyTo(oversizedPayload, 0);
        oversizedPayload[^1] = 0xC3;
        byte[] oversizedHeaderTag = EncodeByteString(oversizedPayload);
        var type = (FdoHashAlgorithm)algorithm;
        byte[] expected = type == FdoHashAlgorithm.HmacSha256
            ? HMACSHA256.HashData(secret, payload)
            : HMACSHA384.HashData(secret, payload);
        var expectedHmac = new FdoHashValue(type, expected);

        await Assert.That(encodedHeaderTag.Length).IsEqualTo((int)ushort.MaxValue);
        await Assert.That(oversizedHeaderTag.Length).IsEqualTo(ushort.MaxValue + 1);

        FdoHashValue actual = FdoOwnershipVoucherHeaderHmac.Compute(type, secret, encodedHeaderTag);

        await Assert.That(actual.Algorithm).IsEqualTo(type);
        await Assert.That(Convert.ToHexString(actual.Value)).IsEqualTo(Convert.ToHexString(expected));
        await Assert.That(FdoOwnershipVoucherHeaderHmac.Verify(
            type, secret, encodedHeaderTag, expectedHmac)).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            FdoOwnershipVoucherHeaderHmac.Compute(type, secret, oversizedHeaderTag))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            FdoOwnershipVoucherHeaderHmac.Verify(type, secret, oversizedHeaderTag, expectedHmac))).IsTrue();
    }

    private static byte[] EncodeByteString(ReadOnlySpan<byte> value)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteByteString(value);
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
        catch (TException exception)
        {
            return exception.GetType() == typeof(TException);
        }
    }
}
