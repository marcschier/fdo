using System;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Tests.Serialization;

public sealed class FdoCoseSign1CodecTests
{
    [Test]
    [Arguments(-7, "D28443A10126A0438201025840")]
    [Arguments(-35, "D28444A1013822A0438201025860")]
    [Arguments(-257, "D28445A101390100A043820102590100")]
    [Arguments(-258, "D28445A101390101A043820102590180")]
    public async Task SignsAndVerifiesTheTaggedEnvelope(int algorithmValue, string expectedPrefix)
    {
        var algorithm = (FdoCoseSignatureAlgorithm)algorithmValue;
        using AsymmetricAlgorithm key = CreateKey(algorithm);
        var codec = new FdoCoseSign1Codec();
        byte[] payload = [0x82, 0x01, 0x02];

        byte[] encoded = codec.Sign(FdoSignatureOperation.OVEntry, algorithm, key, payload).ToArray();
        ReadOnlyMemory<byte> verified = codec.Verify(FdoSignatureOperation.OVEntry, algorithm, key, encoded);
        bool prefixMatches = Convert.ToHexString(encoded).StartsWith(expectedPrefix, StringComparison.Ordinal);
        Array.Fill(payload, (byte)0);
        Array.Fill(encoded, (byte)0);

        await Assert.That(prefixMatches).IsTrue();
        await Assert.That(Convert.ToHexString(verified.Span)).IsEqualTo("820102");
    }

    [Test]
    public async Task RejectsChangedPayloadSignatureKeyAndOperation()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var codec = new FdoCoseSign1Codec();
        byte[] encoded = codec.Sign(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key,
            new byte[] { 0x82, 0x01, 0x02 }).ToArray();
        byte[] changedPayload = encoded.AsSpan().ToArray();
        changedPayload[10] ^= 0x01;
        byte[] changedSignature = encoded.AsSpan().ToArray();
        changedSignature[^1] ^= 0x01;

        await Assert.That(Throws<CryptographicException>(() => codec.Verify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key, changedPayload))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.Verify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key, changedSignature))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.Verify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, otherKey, encoded))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.Verify(
            FdoSignatureOperation.TO0OwnerSign, FdoCoseSignatureAlgorithm.ES256, key, encoded))).IsTrue();
    }

    [Test]
    [Arguments("8443A10126A0418040")]
    [Arguments("D18443A10126A0418040")]
    [Arguments("D28343A10126A04180")]
    [Arguments("D28443A10126A04180F6")]
    [Arguments("D28443A10126A0F640")]
    [Arguments("D28443A1012680418040")]
    [Arguments("D28443A10126A041804000")]
    public async Task RejectsInvalidTagShapeAndFieldTypes(string hex)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var codec = new FdoCoseSign1Codec();

        await Assert.That(Throws<CborContentException>(() => codec.Verify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256,
            key, Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    public async Task GuardsUnprotectedHeadersAndMismatchedAlgorithms()
    {
        using ECDsa p256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var codec = new FdoCoseSign1Codec();
        byte[] withUnprotectedHeader = Convert.FromHexString("D28443A10126A1044101418040");
        byte[] signed = codec.Sign(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, p256, new byte[] { 0x80 }).ToArray();

        await Assert.That(Throws<NotSupportedException>(() => codec.Verify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, p256, withUnprotectedHeader))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.Verify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES384, p384, signed))).IsTrue();
    }

    [Test]
    public async Task RejectsAnInvalidEmbeddedPayloadEvenWhenItsSignatureIsValid()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var codec = new FdoCoseSign1Codec();
        byte[] header = Convert.FromHexString("A10126");
        byte[] invalidPayload = [0x00, 0x00];
        byte[] signature = new FdoCoseSignature().Sign(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key, header, invalidPayload);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)18);
        writer.WriteStartArray(4);
        writer.WriteByteString(header);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString(invalidPayload);
        writer.WriteByteString(signature);
        writer.WriteEndArray();

        await Assert.That(Throws<CborContentException>(() => codec.Sign(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key, invalidPayload))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.Verify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key, writer.Encode()))).IsTrue();
    }

    [Test]
    public async Task EnforcesTheCompleteEnvelopeByteLimit()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] payload = [0x80];
        ReadOnlyMemory<byte> encoded = new FdoCoseSign1Codec().Sign(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key, payload);
        var atLimit = new FdoCoseSign1Codec(maxEncodedBytes: encoded.Length);
        var overLimit = new FdoCoseSign1Codec(maxEncodedBytes: encoded.Length - 1);

        await Assert.That(atLimit.Verify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key, encoded).Length).IsEqualTo(1);
        await Assert.That(atLimit.Sign(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key, payload).Length).IsEqualTo(encoded.Length);
        await Assert.That(Throws<CborContentException>(() => overLimit.Verify(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key, encoded))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => overLimit.Sign(
            FdoSignatureOperation.OVEntry, FdoCoseSignatureAlgorithm.ES256, key, payload))).IsTrue();
    }

    private static AsymmetricAlgorithm CreateKey(FdoCoseSignatureAlgorithm algorithm) => algorithm switch
    {
        FdoCoseSignatureAlgorithm.ES256 => ECDsa.Create(ECCurve.NamedCurves.nistP256),
        FdoCoseSignatureAlgorithm.ES384 => ECDsa.Create(ECCurve.NamedCurves.nistP384),
        FdoCoseSignatureAlgorithm.RS256 => RSA.Create(2048),
        FdoCoseSignatureAlgorithm.RS384 => RSA.Create(3072),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

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
