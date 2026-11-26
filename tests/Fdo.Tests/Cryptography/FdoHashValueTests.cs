using System;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

public sealed class FdoHashValueTests
{
    [Test]
    [Arguments(-16, "822F5820",
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
    [Arguments(-43, "82382A5830",
        "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7")]
    [Arguments(5, "82055820",
        "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7")]
    [Arguments(6, "82065830",
        "AFD03944D84895626B0825F4AB46907F15F9DADBE4101EC682AA034C7CEBC59CFAEA9EA9076EDE7F4AF152E8B2FA9CB6")]
    public async Task HashAndHmacValuesUseTheSpecifiedIdentifiersAndWireShape(
        int algorithm, string encodedPrefix, string valueHex)
    {
        var type = (FdoHashAlgorithm)algorithm;
        var value = new FdoHashValue(type, Convert.FromHexString(valueHex));
        byte[] expected = Convert.FromHexString(encodedPrefix + valueHex);

        ReadOnlyMemory<byte> encoded = value.Encode();
        FdoHashValue decoded = FdoHashValue.Decode(expected);

        await Assert.That(encoded.Span.SequenceEqual(expected)).IsTrue();
        await Assert.That(decoded.Algorithm).IsEqualTo(type);
        await Assert.That(Convert.ToHexString(decoded.Value)).IsEqualTo(valueHex);
    }

    [Test]
    [Arguments(-16, "616263",
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
    [Arguments(-43, "616263",
        "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7")]
    [Arguments(-16, "",
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")]
    [Arguments(-43, "",
        "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B")]
    public async Task Sha2DigestMatchesKnownResults(int algorithm, string dataHex, string expectedHex)
    {
        // https://www.di-mgt.com.au/sha_testvectors.html
        var type = (FdoHashAlgorithm)algorithm;
        byte[] data = Convert.FromHexString(dataHex);

        FdoHashValue value = FdoHashValue.ComputeDigest(type, data);
        FdoHashValue decoded = FdoHashValue.Decode(value.Encode());

        await Assert.That(value.Algorithm).IsEqualTo(type);
        await Assert.That(Convert.ToHexString(value.Value)).IsEqualTo(expectedHex);
        await Assert.That(value.MatchesDigest(type, data)).IsTrue();
        await Assert.That(decoded.MatchesDigest(type, data)).IsTrue();
    }

    [Test]
    [Arguments(5, "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7")]
    [Arguments(6, "AFD03944D84895626B0825F4AB46907F15F9DADBE4101EC682AA034C7CEBC59CFAEA9EA9076EDE7F4AF152E8B2FA9CB6")]
    public async Task HmacMatchesRfc4231CaseOne(int algorithm, string expectedHex)
    {
        // RFC 4231 section 4.2 is a primitive vector, not an FDO interoperability vector.
        // https://www.rfc-editor.org/rfc/rfc4231.html#section-4.2
        byte[] key = new byte[20];
        Array.Fill(key, (byte)0x0B);
        byte[] data = Convert.FromHexString("4869205468657265");
        var type = (FdoHashAlgorithm)algorithm;

        FdoHashValue value = FdoHashValue.ComputeHmac(type, key, data);
        FdoHashValue decoded = FdoHashValue.Decode(value.Encode());

        await Assert.That(value.Algorithm).IsEqualTo(type);
        await Assert.That(Convert.ToHexString(value.Value)).IsEqualTo(expectedHex);
        await Assert.That(value.MatchesHmac(type, key, data)).IsTrue();
        await Assert.That(decoded.MatchesHmac(type, key, data)).IsTrue();
    }

    [Test]
    [Arguments(5, "60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54")]
    [Arguments(6, "4ECE084485813E9088D2C63A041BC5B44F9EF1012A2B588F3CD11F05033AC4C60C2EF6AB4030FE8296248DF163F44952")]
    public async Task HmacMatchesRfc4231ForAKeyLongerThanEitherBlockSize(int algorithm, string expectedHex)
    {
        // RFC 4231 section 4.7 uses a 131-byte key, exceeding both HMAC block sizes.
        byte[] key = new byte[131];
        Array.Fill(key, (byte)0xAA);
        byte[] data = System.Text.Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
        var type = (FdoHashAlgorithm)algorithm;

        FdoHashValue value = FdoHashValue.ComputeHmac(type, key, data);

        await Assert.That(value.Algorithm).IsEqualTo(type);
        await Assert.That(Convert.ToHexString(value.Value)).IsEqualTo(expectedHex);
        await Assert.That(value.MatchesHmac(type, key, data)).IsTrue();
        key[^1] ^= 0x01;
        await Assert.That(value.MatchesHmac(type, key, data)).IsFalse();
    }

    [Test]
    [Arguments(5)]
    [Arguments(6)]
    public async Task HmacAcceptsEmptyDataButDoesNotAuthenticateNonemptyData(int algorithm)
    {
        byte[] key = [0x01, 0x02, 0x03];
        byte[] data = Array.Empty<byte>();
        var type = (FdoHashAlgorithm)algorithm;
        byte[] expected = type == FdoHashAlgorithm.HmacSha256
            ? HMACSHA256.HashData(key, data)
            : HMACSHA384.HashData(key, data);

        FdoHashValue value = FdoHashValue.ComputeHmac(type, key, data);

        await Assert.That(value.Algorithm).IsEqualTo(type);
        await Assert.That(Convert.ToHexString(value.Value)).IsEqualTo(Convert.ToHexString(expected));
        await Assert.That(value.MatchesHmac(type, key, data)).IsTrue();
        await Assert.That(value.MatchesHmac(type, key, new byte[] { 0x00 })).IsFalse();
    }

    [Test]
    [Arguments(-16, -43)]
    [Arguments(-43, -16)]
    public async Task DigestVerificationRejectsChangedBytesAndUnexpectedAlgorithm(int algorithm, int otherAlgorithm)
    {
        var type = (FdoHashAlgorithm)algorithm;
        byte[] data = Convert.FromHexString("616263");
        FdoHashValue value = FdoHashValue.ComputeDigest(type, data);
        byte[] alteredValue = value.Value;
        alteredValue[^1] ^= 0x01;
        var altered = new FdoHashValue(type, alteredValue);

        await Assert.That(value.MatchesDigest(type, data)).IsTrue();
        await Assert.That(value.MatchesDigest(type, Convert.FromHexString("616264"))).IsFalse();
        await Assert.That(altered.MatchesDigest(type, data)).IsFalse();
        await Assert.That(value.MatchesDigest((FdoHashAlgorithm)otherAlgorithm, data)).IsFalse();
    }

    [Test]
    [Arguments(5, 6)]
    [Arguments(6, 5)]
    public async Task HmacVerificationRejectsChangedKeyDataValueAndAlgorithm(int algorithm, int otherAlgorithm)
    {
        var type = (FdoHashAlgorithm)algorithm;
        byte[] key = new byte[20];
        Array.Fill(key, (byte)0x0B);
        byte[] data = Convert.FromHexString("4869205468657265");
        FdoHashValue value = FdoHashValue.ComputeHmac(type, key, data);
        byte[] changedKey = key.ToArray();
        changedKey[0] ^= 0x01;
        byte[] changedData = data.ToArray();
        changedData[^1] ^= 0x01;
        byte[] changedValue = value.Value;
        changedValue[0] ^= 0x01;
        var altered = new FdoHashValue(type, changedValue);

        await Assert.That(value.MatchesHmac(type, key, data)).IsTrue();
        await Assert.That(value.MatchesHmac(type, changedKey, data)).IsFalse();
        await Assert.That(value.MatchesHmac(type, key, changedData)).IsFalse();
        await Assert.That(altered.MatchesHmac(type, key, data)).IsFalse();
        await Assert.That(value.MatchesHmac((FdoHashAlgorithm)otherAlgorithm, key, data)).IsFalse();
    }

    [Test]
    [Arguments(-16, 5)]
    [Arguments(-43, 6)]
    public async Task MatchingBytesCannotBypassTheExpectedAlgorithm(int digestAlgorithm, int hmacAlgorithm)
    {
        var digestType = (FdoHashAlgorithm)digestAlgorithm;
        var hmacType = (FdoHashAlgorithm)hmacAlgorithm;
        byte[] key = [0x01];
        byte[] data = Convert.FromHexString("616263");
        FdoHashValue digest = FdoHashValue.ComputeDigest(digestType, data);
        FdoHashValue hmac = FdoHashValue.ComputeHmac(hmacType, key, data);
        var mislabeledDigest = new FdoHashValue(hmacType, digest.Value);
        var mislabeledHmac = new FdoHashValue(digestType, hmac.Value);

        await Assert.That(mislabeledDigest.MatchesDigest(digestType, data)).IsFalse();
        await Assert.That(mislabeledHmac.MatchesHmac(hmacType, key, data)).IsFalse();
    }

    [Test]
    [Arguments(-16, "2F", 32)]
    [Arguments(-43, "382A", 48)]
    [Arguments(5, "05", 32)]
    [Arguments(6, "06", 48)]
    public async Task EveryAlgorithmRequiresItsFullOutputLength(
        int algorithm, string encodedAlgorithm, int expectedLength)
    {
        var type = (FdoHashAlgorithm)algorithm;
        var valid = new FdoHashValue(type, new byte[expectedLength]);

        await Assert.That(valid.Value.Length).IsEqualTo(expectedLength);
        foreach (int length in new[] { expectedLength - 1, expectedLength + 1 })
        {
            byte[] incorrect = new byte[length];
            byte[] encoded = EncodeWithLength(encodedAlgorithm, length);
            await Assert.That(Throws<ArgumentException>(() => new FdoHashValue(type, incorrect))).IsTrue();
            await Assert.That(Throws<CborContentException>(() => FdoHashValue.Decode(encoded))).IsTrue();
        }
    }

    [Test]
    [Arguments("")]
    [Arguments("A0")]
    [Arguments("80")]
    [Arguments("812F")]
    [Arguments("83050000")]
    [Arguments("82F640")]
    [Arguments("820140")]
    [Arguments("822E40")]
    [Arguments("82382B40")]
    [Arguments("821BFFFFFFFFFFFFFFFF40")]
    [Arguments("823BFFFFFFFFFFFFFFFF40")]
    [Arguments("82180540")]
    [Arguments("82380F40")]
    [Arguments("822F00")]
    [Arguments("822F40")]
    [Arguments("822F5F40FF")]
    [Arguments("9F2F40FF")]
    [Arguments("822F40F6")]
    public async Task MalformedUnsupportedAndNoncanonicalValuesAreRejected(string hex)
    {
        await Assert.That(Throws<CborContentException>(
            () => FdoHashValue.Decode(Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    [Arguments("04", 32)]
    [Arguments("07", 32)]
    [Arguments("2E", 32)]
    [Arguments("30", 32)]
    [Arguments("3829", 48)]
    [Arguments("382B", 48)]
    [Arguments("1BFFFFFFFFFFFFFFFF", 32)]
    [Arguments("3BFFFFFFFFFFFFFFFF", 32)]
    [Arguments("F6", 32)]
    public async Task DecodeRejectsUnsupportedOrNonIntegerAlgorithmsWithFullLengthValues(
        string encodedAlgorithm, int valueLength)
    {
        byte[] encoded = EncodeWithLength(encodedAlgorithm, valueLength);

        await Assert.That(Throws<CborContentException>(() => FdoHashValue.Decode(encoded))).IsTrue();
    }

    [Test]
    [Arguments("1805", 32)]
    [Arguments("1806", 48)]
    [Arguments("380F", 32)]
    public async Task DecodeRejectsNoncanonicalAlgorithmsWithFullLengthValues(
        string encodedAlgorithm, int valueLength)
    {
        byte[] encoded = EncodeWithLength(encodedAlgorithm, valueLength);

        await Assert.That(Throws<CborContentException>(() => FdoHashValue.Decode(encoded))).IsTrue();
    }

    [Test]
    public async Task DecodeRejectsNoncanonicalLengthsAndTrailingItemsAfterACompleteHash()
    {
        const string digestHex = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        byte[] complete = Convert.FromHexString("822F5820" + digestHex);
        byte[] noncanonicalLength = Convert.FromHexString("822F590020" + digestHex);
        byte[] trailingItem = Convert.FromHexString("822F5820" + digestHex + "F6");

        FdoHashValue decoded = FdoHashValue.Decode(complete);

        await Assert.That(decoded.Algorithm).IsEqualTo(FdoHashAlgorithm.Sha256);
        await Assert.That(Convert.ToHexString(decoded.Value)).IsEqualTo(digestHex);
        await Assert.That(Throws<CborContentException>(() => FdoHashValue.Decode(noncanonicalLength))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => FdoHashValue.Decode(trailingItem))).IsTrue();
    }

    [Test]
    public async Task ValuesDoNotShareMutableBuffersWithCallers()
    {
        const string expected = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        byte[] source = Convert.FromHexString(expected);
        var value = new FdoHashValue(FdoHashAlgorithm.Sha256, source);
        source[0] ^= 0xFF;
        byte[] exposed = value.Value;
        exposed[1] ^= 0xFF;
        byte[] encoded = value.Encode().ToArray();
        FdoHashValue decoded = FdoHashValue.Decode(encoded);
        Array.Fill(encoded, (byte)0);

        await Assert.That(Convert.ToHexString(value.Value)).IsEqualTo(expected);
        await Assert.That(Convert.ToHexString(decoded.Value)).IsEqualTo(expected);
        await Assert.That(value.MatchesDigest(FdoHashAlgorithm.Sha256, Convert.FromHexString("616263"))).IsTrue();
    }

    [Test]
    public async Task ComputationRequiresTheCorrectAlgorithmKindAndANonemptyHmacKey()
    {
        byte[] data = Convert.FromHexString("616263");
        byte[] key = [0x01];
        FdoHashValue digest = FdoHashValue.ComputeDigest(FdoHashAlgorithm.Sha256, data);
        FdoHashValue hmac = FdoHashValue.ComputeHmac(FdoHashAlgorithm.HmacSha256, key, data);

        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => new FdoHashValue((FdoHashAlgorithm)0, new byte[32]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => FdoHashValue.ComputeDigest(FdoHashAlgorithm.HmacSha256, data))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => FdoHashValue.ComputeHmac(FdoHashAlgorithm.Sha256, key, data))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => digest.MatchesDigest(FdoHashAlgorithm.HmacSha256, data))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => hmac.MatchesHmac(FdoHashAlgorithm.Sha256, key, data))).IsTrue();
        await Assert.That(Throws<ArgumentException>(
            () => FdoHashValue.ComputeHmac(FdoHashAlgorithm.HmacSha256, Array.Empty<byte>(), data))).IsTrue();
        await Assert.That(Throws<ArgumentException>(
            () => hmac.MatchesHmac(FdoHashAlgorithm.HmacSha256, Array.Empty<byte>(), data))).IsTrue();
    }

    [Test]
    [Arguments(0)]
    [Arguments(7)]
    [Arguments(-17)]
    public async Task UnknownAlgorithmIsRejectedByComputationsAndVerification(int algorithm)
    {
        var unknown = (FdoHashAlgorithm)algorithm;
        byte[] key = [0x01];
        byte[] data = [0x02];
        var digest = new FdoHashValue(FdoHashAlgorithm.Sha256, new byte[32]);
        var hmac = new FdoHashValue(FdoHashAlgorithm.HmacSha256, new byte[32]);

        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => new FdoHashValue(unknown, new byte[32]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => FdoHashValue.ComputeDigest(unknown, data))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => FdoHashValue.ComputeHmac(unknown, key, data))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => digest.MatchesDigest(unknown, data))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(
            () => hmac.MatchesHmac(unknown, key, data))).IsTrue();
    }

    private static byte[] EncodeWithLength(string encodedAlgorithm, int length)
    {
        byte[] algorithm = Convert.FromHexString(encodedAlgorithm);
        var encoded = new byte[1 + algorithm.Length + 2 + length];
        encoded[0] = 0x82;
        algorithm.CopyTo(encoded, 1);
        encoded[1 + algorithm.Length] = 0x58;
        encoded[2 + algorithm.Length] = (byte)length;
        return encoded;
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
