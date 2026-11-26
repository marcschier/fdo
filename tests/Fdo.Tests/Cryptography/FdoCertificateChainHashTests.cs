using System;
using System.Formats.Cbor;
using System.Threading.Tasks;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

public sealed class FdoCertificateChainHashTests
{
    [Test]
    [Arguments(-16, "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
    [Arguments(-43, "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7")]
    public async Task HashesOnlyTheOrderedCertificateContents(int algorithmValue, string expectedHex)
    {
        var algorithm = (FdoHashAlgorithm)algorithmValue;
        var hasher = new FdoCertificateChainHash();
        byte[] single = Convert.FromHexString("43616263");
        byte[] multiple = Convert.FromHexString("824161426263");
        byte[] reordered = Convert.FromHexString("824262634161");
        var expected = new FdoHashValue(algorithm, Convert.FromHexString(expectedHex));

        FdoHashValue singleHash = hasher.Compute(algorithm, single);
        FdoHashValue multipleHash = hasher.Compute(algorithm, multiple);

        await Assert.That(Convert.ToHexString(singleHash.Value)).IsEqualTo(expectedHex);
        await Assert.That(Convert.ToHexString(multipleHash.Value)).IsEqualTo(expectedHex);
        await Assert.That(hasher.Verify(algorithm, multiple, expected)).IsTrue();
        await Assert.That(hasher.Verify(algorithm, reordered, expected)).IsFalse();
    }

    [Test]
    public async Task RejectsUnexpectedDigestAlgorithmsAndChangedDigestValues()
    {
        var hasher = new FdoCertificateChainHash();
        byte[] encoded = Convert.FromHexString("43616263");
        FdoHashValue digest = hasher.Compute(FdoHashAlgorithm.Sha256, encoded);
        byte[] changed = digest.Value;
        changed[0] ^= 0x01;
        var changedDigest = new FdoHashValue(FdoHashAlgorithm.Sha256, changed);
        var otherAlgorithm = new FdoHashValue(FdoHashAlgorithm.Sha384, new byte[48]);

        await Assert.That(hasher.Verify(FdoHashAlgorithm.Sha256, encoded, changedDigest)).IsFalse();
        await Assert.That(hasher.Verify(FdoHashAlgorithm.Sha256, encoded, otherAlgorithm)).IsFalse();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            hasher.Compute(FdoHashAlgorithm.HmacSha256, encoded))).IsTrue();
    }

    [Test]
    [Arguments("F6")]
    [Arguments("80")]
    [Arguments("814161")]
    [Arguments("82416100")]
    public async Task RejectsNullAndMalformedX5Chains(string hex)
    {
        var hasher = new FdoCertificateChainHash();

        await Assert.That(Throws<CborContentException>(() =>
            hasher.Compute(FdoHashAlgorithm.Sha256, Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    public async Task EnforcesTheEncodedChainLimit()
    {
        byte[] chain = Convert.FromHexString("824161426263");
        var atLimit = new FdoCertificateChainHash(maxEncodedBytes: chain.Length);
        var overLimit = new FdoCertificateChainHash(maxEncodedBytes: chain.Length - 1);

        await Assert.That(atLimit.Compute(FdoHashAlgorithm.Sha256, chain).Value.Length).IsEqualTo(32);
        await Assert.That(Throws<CborContentException>(() =>
            overLimit.Compute(FdoHashAlgorithm.Sha256, chain))).IsTrue();
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
