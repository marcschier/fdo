using System;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Tests.Serialization;

public sealed class FdoTo2DeviceProofCodecTests
{
    private static readonly byte[] Probe = Convert.FromHexString(
        "8641048050000102030405060708090A0B0C0D0E0F19FFFF822F382A50101112131415161718191A1B1C1D1E1F");
    private static readonly byte[] Ack = Convert.FromHexString(
        "8841048050000102030405060708090A0B0C0D0E0F19FFFF826745434448323536674543444833383482010350202122232425262728292A2B2C2D2E2F822F582043F7EC2CFA7686EF378707BFBA98A1C2DF78101B3A4039DDD121F060444C9277");
    private static readonly byte[] Guid = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
    private static readonly byte[] Nonce = Convert.FromHexString("202122232425262728292A2B2C2D2E2F");
    private static readonly byte[] OwnerNonce = Convert.FromHexString("303132333435363738393A3B3C3D3E3F");

    [Test]
    [Arguments(256, 0, 1)]
    [Arguments(384, 1, 3)]
    public async Task SignsAndChecksTheExactTranscriptAndOwnsReturnedFields(
        int curveSize, int exchangeValue, int cipherValue)
    {
        var exchange = (FdoKeyExchangeSuite)exchangeValue;
        var cipher = (FdoCoseAeadAlgorithm)cipherValue;
        using ECDsa deviceKey = CreateDeviceKey(curveSize);
        using FdoEcdhKeyExchange keyExchange = FdoEcdhKeyExchange.Create(exchange, FdoEcdhParty.Device);
        var codec = new FdoTo2DeviceProofCodec();
        byte[] parameter = keyExchange.ExportParameter();
        byte[] expectedParameter = (byte[])parameter.Clone();
        byte[] proof = codec.Sign(Probe, Ack, exchange, cipher, parameter, OwnerNonce, deviceKey).ToArray();

        FdoTo2DeviceProofCodec.DeviceProof verified = codec.Verify(Probe, Ack, proof, deviceKey);
        Array.Fill(parameter, (byte)0);
        Array.Fill(proof, (byte)0);

        await Assert.That(verified.Exchange).IsEqualTo(exchange);
        await Assert.That(verified.Cipher).IsEqualTo(cipher);
        await Assert.That(Convert.ToHexString(verified.Guid.Span)).IsEqualTo(Convert.ToHexString(Guid));
        await Assert.That(Convert.ToHexString(verified.DeviceParameter.Span))
            .IsEqualTo(Convert.ToHexString(expectedParameter));
        await Assert.That(Convert.ToHexString(verified.OwnerNonce.Span)).IsEqualTo(Convert.ToHexString(OwnerNonce));
    }

    [Test]
    public async Task RejectsChangedTranscriptNonceOffersAndProbe()
    {
        using ECDsa deviceKey = CreateDeviceKey(256);
        using FdoEcdhKeyExchange exchange = FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Device);
        var codec = new FdoTo2DeviceProofCodec();
        byte[] proof = codec.Sign(
            Probe, Ack, FdoKeyExchangeSuite.Ecdh256, FdoCoseAeadAlgorithm.A128Gcm,
            exchange.ExportParameter(), OwnerNonce, deviceKey).ToArray();
        var initial = new FdoTo2InitialCodec();
        FdoTo2InitialCodec.Acknowledgement decoded = initial.DecodeAcknowledgement(Ack);
        byte[] changedNonce = initial.EncodeAcknowledgement(decoded with { NonceTo2ProveDv = new byte[16] }).ToArray();
        byte[] changedOffers = initial.EncodeAcknowledgement(decoded with { CipherSuites = new long[] { 1 } }).ToArray();
        byte[] changedProbe = (byte[])Probe.Clone();
        changedProbe[^1] ^= 0x01;

        await Assert.That(Throws<CryptographicException>(() =>
            codec.Verify(Probe, changedNonce, proof, deviceKey))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Verify(Probe, changedOffers, proof, deviceKey))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Verify(changedProbe, Ack, proof, deviceKey))).IsTrue();
    }

    [Test]
    public async Task RejectsTheWrongDeviceKeySignatureAndDomain()
    {
        using ECDsa deviceKey = CreateDeviceKey(256);
        using ECDsa otherKey = CreateDeviceKey(256);
        using FdoEcdhKeyExchange exchange = FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Device);
        byte[] parameter = exchange.ExportParameter();
        var codec = new FdoTo2DeviceProofCodec();
        byte[] proof = codec.Sign(
            Probe, Ack, FdoKeyExchangeSuite.Ecdh256, FdoCoseAeadAlgorithm.A128Gcm,
            parameter, OwnerNonce, deviceKey).ToArray();
        byte[] changedSignature = (byte[])proof.Clone();
        changedSignature[^1] ^= 0x01;
        byte[] wrongDomain = CreateSignedProof(
            deviceKey, Guid, Nonce, parameter, OwnerNonce, Ack,
            FdoSignatureOperation.TO0OwnerSign);

        await Assert.That(Throws<CryptographicException>(() =>
            codec.Verify(Probe, Ack, proof, otherKey))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Verify(Probe, Ack, changedSignature, deviceKey))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Verify(Probe, Ack, wrongDomain, deviceKey))).IsTrue();
    }

    [Test]
    public async Task RejectsSignedProofsWithWrongGuidNonceOrUnofferedSuite()
    {
        using ECDsa deviceKey = CreateDeviceKey(256);
        using FdoEcdhKeyExchange exchange = FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Device);
        byte[] parameter = exchange.ExportParameter();
        byte[] wrongGuid = (byte[])Guid.Clone();
        wrongGuid[0] ^= 0x01;
        byte[] wrongNonce = (byte[])Nonce.Clone();
        wrongNonce[0] ^= 0x01;
        var initial = new FdoTo2InitialCodec();
        FdoTo2InitialCodec.Acknowledgement ack = initial.DecodeAcknowledgement(Ack);
        byte[] limitedAck = initial.EncodeAcknowledgement(ack with { CipherSuites = new long[] { 1 } }).ToArray();
        byte[] badGuid = CreateSignedProof(deviceKey, wrongGuid, Nonce, parameter, OwnerNonce, Ack);
        byte[] badNonce = CreateSignedProof(deviceKey, Guid, wrongNonce, parameter, OwnerNonce, Ack);
        byte[] unoffered = CreateSignedProof(deviceKey, Guid, Nonce, parameter, OwnerNonce, limitedAck, cipher: 3);
        var codec = new FdoTo2DeviceProofCodec();

        await Assert.That(Throws<CryptographicException>(() =>
            codec.Verify(Probe, Ack, badGuid, deviceKey))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Verify(Probe, Ack, badNonce, deviceKey))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.Verify(Probe, limitedAck, unoffered, deviceKey))).IsTrue();
    }

    [Test]
    public async Task RejectsMalformedSignedEcdhParametersAndNonceLengths()
    {
        using ECDsa deviceKey = CreateDeviceKey(256);
        using FdoEcdhKeyExchange exchange = FdoEcdhKeyExchange.Create(FdoKeyExchangeSuite.Ecdh256, FdoEcdhParty.Device);
        byte[] parameter = exchange.ExportParameter();
        byte[] malformed = (byte[])parameter.Clone();
        malformed[1] ^= 0x01;
        byte[] badParameter = CreateSignedProof(deviceKey, Guid, Nonce, malformed, OwnerNonce, Ack);
        byte[] badNonce = CreateSignedProof(deviceKey, Guid, Nonce, parameter, new byte[15], Ack);
        var codec = new FdoTo2DeviceProofCodec();

        await Assert.That(Throws<CryptographicException>(() =>
            codec.Verify(Probe, Ack, badParameter, deviceKey))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            codec.Verify(Probe, Ack, badNonce, deviceKey))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.Sign(
            Probe, Ack, FdoKeyExchangeSuite.Ecdh256, FdoCoseAeadAlgorithm.A128Gcm,
            malformed, OwnerNonce, deviceKey))).IsTrue();
    }

    [Test]
    [Arguments(2, 256)]
    [Arguments(3, 384)]
    [Arguments(4, 256)]
    [Arguments(5, 384)]
    public async Task ChecksSignedPairedRsaExchangeDeviceParameterWidths(int suiteValue, int expectedLength)
    {
        var suite = (FdoKeyExchangeSuite)suiteValue;
        using ECDsa deviceKey = CreateDeviceKey(256);
        var initial = new FdoTo2InitialCodec();
        byte[] acknowledgement = initial.EncodeAcknowledgement(
            initial.DecodeAcknowledgement(Ack) with
            {
                KeyExchangeSuites = new[] { FdoKeyExchangeSuites.GetName(suite) },
            }).ToArray();
        byte[] parameter = new byte[expectedLength];
        parameter[0] = 0x7f;
        parameter[^1] = 0xa5;
        var codec = new FdoTo2DeviceProofCodec();
        byte[] proof = codec.Sign(
            Probe, acknowledgement, suite, FdoCoseAeadAlgorithm.A128Gcm,
            parameter, OwnerNonce, deviceKey).ToArray();
        byte[] shorter = new byte[expectedLength - 1];
        byte[] longer = new byte[expectedLength + 1];

        FdoTo2DeviceProofCodec.DeviceProof checkedProof = codec.Verify(Probe, acknowledgement, proof, deviceKey);

        await Assert.That(checkedProof.Exchange).IsEqualTo(suite);
        await Assert.That(checkedProof.DeviceParameter.Span.SequenceEqual(parameter)).IsTrue();
        foreach (byte[] invalid in new[] { shorter, longer })
        {
            byte[] signed = CreateSignedProof(
                deviceKey, Guid, Nonce, invalid, OwnerNonce, acknowledgement,
                exchangeName: FdoKeyExchangeSuites.GetName(suite));
            await Assert.That(Throws<CryptographicException>(() =>
                codec.Verify(Probe, acknowledgement, signed, deviceKey))).IsTrue();
            await Assert.That(Throws<CryptographicException>(() => codec.Sign(
                Probe, acknowledgement, suite, FdoCoseAeadAlgorithm.A128Gcm,
                invalid, OwnerNonce, deviceKey))).IsTrue();
        }
    }

    private static byte[] CreateSignedProof(
        ECDsa deviceKey,
        byte[] guid,
        byte[] nonce,
        byte[] parameter,
        byte[] ownerNonce,
        byte[] acknowledgement,
        FdoSignatureOperation operation = FdoSignatureOperation.TO2ProveDevice,
        int cipher = 1,
        string exchangeName = "ECDH256")
    {
        byte[] ueid = new byte[17];
        ueid[0] = 1;
        guid.CopyTo(ueid, 1);
        FdoHashValue hash = FdoHashValue.ComputeDigest(FdoHashAlgorithm.Sha256, acknowledgement);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(10);
        writer.WriteByteString(nonce);
        writer.WriteInt32(256);
        writer.WriteByteString(ueid);
        writer.WriteInt32(-257);
        writer.WriteStartArray(5);
        writer.WriteTextString(exchangeName);
        writer.WriteInt32(cipher);
        writer.WriteByteString(parameter);
        writer.WriteByteString(ownerNonce);
        writer.WriteEncodedValue(hash.Encode().Span);
        writer.WriteEndArray();
        writer.WriteEndMap();
        return new FdoCoseSign1Codec().Sign(
            operation, FdoCoseSignatureAlgorithm.ES256, deviceKey, writer.Encode()).ToArray();
    }

    private static ECDsa CreateDeviceKey(int curveSize) => ECDsa.Create(
        curveSize == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);

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
