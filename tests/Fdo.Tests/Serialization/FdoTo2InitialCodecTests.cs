// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;
using Acknowledgement = Fdo.Serialization.FdoTo2InitialCodec.Acknowledgement;
using Probe = Fdo.Serialization.FdoTo2InitialCodec.Probe;

namespace Fdo.Tests.Serialization;

public sealed class FdoTo2InitialCodecTests
{
    private const string ProbeHex =
        "8641048050000102030405060708090A0B0C0D0E0F19FFFF822F382A50101112131415161718191A1B1C1D1E1F";
    private const string AckHex =
        "8841048050000102030405060708090A0B0C0D0E0F19FFFF826745434448323536674543444833383482010350202122232425262728292A2B2C2D2E2F822F582043F7EC2CFA7686EF378707BFBA98A1C2DF78101B3A4039DDD121F060444C9277";

    [Test]
    public async Task InitialMessagesMatchTheSpecifiedFieldOrder()
    {
        var codec = new FdoTo2InitialCodec();
        byte[] probeBytes = Convert.FromHexString(ProbeHex);
        byte[] ackBytes = Convert.FromHexString(AckHex);
        Probe probe = codec.DecodeProbe(probeBytes);
        Acknowledgement ack = codec.DecodeAcknowledgement(ackBytes);
        ReadOnlyMemory<byte> encodedProbe = codec.EncodeProbe(probe);
        ReadOnlyMemory<byte> encodedAck = codec.EncodeAcknowledgement(ack);
        Array.Fill(probeBytes, (byte)0);
        Array.Fill(ackBytes, (byte)0);

        await Assert.That(Convert.ToHexString(encodedProbe.Span)).IsEqualTo(ProbeHex);
        await Assert.That(Convert.ToHexString(encodedAck.Span)).IsEqualTo(AckHex);
        await Assert.That(Convert.ToHexString(probe.Guid.Span)).IsEqualTo("000102030405060708090A0B0C0D0E0F");
        await Assert.That(Convert.ToHexString(probe.Sugar.Span)).IsEqualTo("101112131415161718191A1B1C1D1E1F");
        await Assert.That(probe.MaxDeviceMessageSize).IsEqualTo(ushort.MaxValue);
        await Assert.That(probe.HashTypes.SequenceEqual(new long[] { -16, -43 })).IsTrue();
        await Assert.That(ack.KeyExchangeSuites.SequenceEqual(new[] { "ECDH256", "ECDH384" })).IsTrue();
        await Assert.That(ack.CipherSuites.SequenceEqual(new long[] { 1, 3 })).IsTrue();
        await Assert.That(Convert.ToHexString(ack.NonceTo2ProveDv.Span)).IsEqualTo("202122232425262728292A2B2C2D2E2F");
    }

    [Test]
    public async Task HashesExactProbeAndAcknowledgementBytesUsingTheSelectedOfferedHash()
    {
        var codec = new FdoTo2InitialCodec();
        byte[] probe = Convert.FromHexString(ProbeHex);
        byte[] ack = Convert.FromHexString(AckHex);
        FdoHashValue sha256 = codec.ComputeProbeHash(FdoHashAlgorithm.Sha256, probe);
        FdoHashValue sha384 = codec.ComputeProbeHash(FdoHashAlgorithm.Sha384, probe);
        FdoTo2InitialCodec.CheckedAcknowledgement checkedAck = codec.CheckAcknowledgement(probe, ack);
        codec.VerifyAcknowledgementHash(ack, checkedAck.HashPrev2);

        await Assert.That(Convert.ToHexString(sha256.Value))
            .IsEqualTo("43F7EC2CFA7686EF378707BFBA98A1C2DF78101B3A4039DDD121F060444C9277");
        await Assert.That(Convert.ToHexString(sha384.Value))
            .IsEqualTo("3F91288354C9C38A00FE4CAB304187A492984B4846F45628F27C6E6D25029BCC365DF7B10392A5CC01145699A4467B3E");
        await Assert.That(Convert.ToHexString(checkedAck.HashPrev2.Value))
            .IsEqualTo("7CA897975FFD7E8F330233F86433C2FBBD83F9F17FCFE148007A8629C3A69241");
        await Assert.That(checkedAck.HashPrev2.Algorithm).IsEqualTo(FdoHashAlgorithm.Sha256);
    }

    [Test]
    public async Task AcknowledgementRejectsChangedGuidVersionOrUnofferedHash()
    {
        var codec = new FdoTo2InitialCodec();
        byte[] probeBytes = Convert.FromHexString(ProbeHex);
        Probe probe = codec.DecodeProbe(probeBytes);
        Acknowledgement ack = codec.DecodeAcknowledgement(Convert.FromHexString(AckHex));
        Acknowledgement wrongGuid = ack with { Guid = new byte[16] };
        Acknowledgement wrongVersion = ack with { CapabilityFlags = new byte[] { 0x02 } };
        Probe wrongProbeVersion = probe with { CapabilityFlags = new byte[] { 0x02 } };
        byte[] onlySha256 = codec.EncodeProbe(probe with { HashTypes = new long[] { -16 } }).ToArray();
        Acknowledgement unoffered = ack with
        {
            HashPrev = FdoHashValue.ComputeDigest(FdoHashAlgorithm.Sha384, onlySha256),
        };
        Acknowledgement hmac = ack with
        {
            HashPrev = FdoHashValue.ComputeHmac(FdoHashAlgorithm.HmacSha256, new byte[] { 1 }, probeBytes),
        };

        await Assert.That(Throws<CryptographicException>(() =>
            codec.CheckAcknowledgement(probeBytes, codec.EncodeAcknowledgement(wrongGuid)))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.CheckAcknowledgement(probeBytes, codec.EncodeAcknowledgement(wrongVersion)))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.CheckAcknowledgement(codec.EncodeProbe(wrongProbeVersion), Convert.FromHexString(AckHex)))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.CheckAcknowledgement(onlySha256, codec.EncodeAcknowledgement(unoffered)))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.CheckAcknowledgement(probeBytes, codec.EncodeAcknowledgement(hmac)))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.ComputeProbeHash(FdoHashAlgorithm.Sha384, onlySha256))).IsTrue();
    }

    [Test]
    public async Task DoesNotRetryTheProbeHashWithTheManufacturerKeyHashAppended()
    {
        var codec = new FdoTo2InitialCodec();
        byte[] probe = Convert.FromHexString(ProbeHex);
        byte[] manufacturerHash = new FdoHashValue(FdoHashAlgorithm.Sha256, new byte[32]).Encode().ToArray();
        byte[] alternateInput = probe.Concat(manufacturerHash).ToArray();
        Acknowledgement ack = codec.DecodeAcknowledgement(Convert.FromHexString(AckHex)) with
        {
            HashPrev = FdoHashValue.ComputeDigest(FdoHashAlgorithm.Sha256, alternateInput),
        };

        await Assert.That(Throws<CryptographicException>(() =>
            codec.CheckAcknowledgement(probe, codec.EncodeAcknowledgement(ack)))).IsTrue();
    }

    [Test]
    public async Task AckHashDetectsChangedOffersAndWrongHashAlgorithms()
    {
        var codec = new FdoTo2InitialCodec();
        byte[] probe = Convert.FromHexString(ProbeHex);
        byte[] ackBytes = Convert.FromHexString(AckHex);
        FdoHashValue signedHash = codec.CheckAcknowledgement(probe, ackBytes).HashPrev2;
        Acknowledgement ack = codec.DecodeAcknowledgement(ackBytes);
        byte[] changedOffers = codec.EncodeAcknowledgement(ack with { CipherSuites = new long[] { 1 } }).ToArray();
        FdoHashValue wrongAlgorithm = FdoHashValue.ComputeDigest(FdoHashAlgorithm.Sha384, ackBytes);

        await Assert.That(Throws<CryptographicException>(() =>
            codec.VerifyAcknowledgementHash(changedOffers, signedHash))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.VerifyAcknowledgementHash(ackBytes, wrongAlgorithm))).IsTrue();
    }

    [Test]
    public async Task SelectedEcdhAndAeadSuitesMustHaveBeenOffered()
    {
        var codec = new FdoTo2InitialCodec();
        Acknowledgement ack = codec.DecodeAcknowledgement(Convert.FromHexString(AckHex));
        ReadOnlyMemory<byte> oneOfEach = codec.EncodeAcknowledgement(ack with
        {
            KeyExchangeSuites = new[] { "ECDH256" },
            CipherSuites = new long[] { 1 },
        });
        codec.RequireOfferedSuites(oneOfEach, FdoKeyExchangeSuite.Ecdh256, FdoCoseAeadAlgorithm.A128Gcm);
        ReadOnlyMemory<byte> ccmOffer = codec.EncodeAcknowledgement(ack with
        {
            KeyExchangeSuites = new[] { "ECDH256" },
            CipherSuites = new long[] { 30 },
        });
        codec.RequireOfferedSuites(ccmOffer, FdoKeyExchangeSuite.Ecdh256, FdoCoseAeadAlgorithm.AesCcm16_128_128);

        await Assert.That(Throws<CryptographicException>(() =>
            codec.RequireOfferedSuites(oneOfEach, FdoKeyExchangeSuite.Ecdh384, FdoCoseAeadAlgorithm.A128Gcm))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.RequireOfferedSuites(oneOfEach, FdoKeyExchangeSuite.Ecdh256, FdoCoseAeadAlgorithm.A256Gcm))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            codec.RequireOfferedSuites(oneOfEach, FdoKeyExchangeSuite.Ecdh256, FdoCoseAeadAlgorithm.AesCcm16_128_128))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            codec.RequireOfferedSuites(oneOfEach, FdoKeyExchangeSuite.Ecdh256, (FdoCoseAeadAlgorithm)(-1)))).IsTrue();
    }

    [Test]
    public async Task PreservesUnrecognizedOffersWithoutSelectingThem()
    {
        var codec = new FdoTo2InitialCodec();
        Probe probe = codec.DecodeProbe(Convert.FromHexString(ProbeHex)) with { HashTypes = new long[] { -16, 123 } };
        Acknowledgement ack = codec.DecodeAcknowledgement(Convert.FromHexString(AckHex)) with
        {
            KeyExchangeSuites = new[] { "future-kex", "ECDH256" },
            CipherSuites = new long[] { -17760703, 1 },
        };
        Probe decodedProbe = codec.DecodeProbe(codec.EncodeProbe(probe));
        Acknowledgement decodedAck = codec.DecodeAcknowledgement(codec.EncodeAcknowledgement(ack));

        await Assert.That(decodedProbe.HashTypes.SequenceEqual(new long[] { -16, 123 })).IsTrue();
        await Assert.That(decodedAck.KeyExchangeSuites.SequenceEqual(new[] { "future-kex", "ECDH256" })).IsTrue();
        await Assert.That(decodedAck.CipherSuites.SequenceEqual(new long[] { -17760703, 1 })).IsTrue();
    }

    [Test]
    public async Task RejectsMalformedInitialMessages()
    {
        var codec = new FdoTo2InitialCodec();
        byte[] guid = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        byte[] sugar = Convert.FromHexString("101112131415161718191A1B1C1D1E1F");
        byte[] probe = Convert.FromHexString(ProbeHex);
        byte[] ack = Convert.FromHexString(AckHex);
        byte[] wrongProbeShape = probe.AsSpan().ToArray();
        wrongProbeShape[0] = 0x85;
        byte[] wrongAckShape = ack.AsSpan().ToArray();
        wrongAckShape[0] = 0x87;
        byte[] trailing = probe.Concat(new byte[] { 0 }).ToArray();
        byte[][] malformedProbes =
        [
            wrongProbeShape,
            trailing,
            RawProbe(new byte[15], 0, new long[] { -16 }, sugar),
            RawProbe(guid, 65536, new long[] { -16 }, sugar),
            RawProbe(guid, 0, Array.Empty<long>(), sugar),
            RawProbe(guid, 0, new long[] { -16 }, new byte[15]),
        ];
        byte[][] malformedAcks =
        [
            wrongAckShape,
            RawAck(guid, Array.Empty<string>(), new long[] { 1 }, new byte[16]),
            RawAck(guid, new[] { "ECDH256" }, Array.Empty<long>(), new byte[16]),
            RawAck(guid, new[] { "ECDH256" }, new long[] { 1 }, new byte[15]),
        ];

        foreach (byte[] input in malformedProbes)
        {
            await Assert.That(Throws<CborContentException>(() => codec.DecodeProbe(input))).IsTrue();
        }

        foreach (byte[] input in malformedAcks)
        {
            await Assert.That(Throws<CborContentException>(() => codec.DecodeAcknowledgement(input))).IsTrue();
        }
    }

    [Test]
    public async Task EnforcesByteItemAndDepthLimitsBeforeReturningMessages()
    {
        var codec = new FdoTo2InitialCodec();
        Probe probe = codec.DecodeProbe(Convert.FromHexString(ProbeHex));
        var atLimit = new FdoTo2InitialCodec(maxEncodedBytes: 45, maxItems: 9);
        var byteLimited = new FdoTo2InitialCodec(maxEncodedBytes: 44);
        var itemLimited = new FdoTo2InitialCodec(maxItems: 8);
        var depthLimited = new FdoTo2InitialCodec(maxDepth: 2);

        await Assert.That(atLimit.EncodeProbe(probe).Length).IsEqualTo(45);
        await Assert.That(Throws<CborContentException>(() => byteLimited.EncodeProbe(probe))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            byteLimited.DecodeProbe(Convert.FromHexString(ProbeHex)))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => itemLimited.EncodeProbe(probe))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            itemLimited.DecodeProbe(Convert.FromHexString(ProbeHex)))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            depthLimited.DecodeProbe(Convert.FromHexString(ProbeHex)))).IsTrue();
    }

    private static byte[] RawProbe(byte[] guid, ulong size, long[] hashes, byte[] sugar)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(6);
        writer.WriteByteString(new byte[] { 4 });
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteByteString(guid);
        writer.WriteUInt64(size);
        writer.WriteStartArray(hashes.Length);
        foreach (long hash in hashes)
        {
            writer.WriteInt64(hash);
        }

        writer.WriteEndArray();
        writer.WriteByteString(sugar);
        writer.WriteEndArray();
        return writer.Encode();
    }

    private static byte[] RawAck(byte[] guid, string[] exchanges, long[] ciphers, byte[] nonce)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(8);
        writer.WriteByteString(new byte[] { 4 });
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteByteString(guid);
        writer.WriteUInt64(0);
        writer.WriteStartArray(exchanges.Length);
        foreach (string exchange in exchanges)
        {
            writer.WriteTextString(exchange);
        }

        writer.WriteEndArray();
        writer.WriteStartArray(ciphers.Length);
        foreach (long cipher in ciphers)
        {
            writer.WriteInt64(cipher);
        }

        writer.WriteEndArray();
        writer.WriteByteString(nonce);
        writer.WriteEncodedValue(new FdoHashValue(FdoHashAlgorithm.Sha256, new byte[32]).Encode().Span);
        writer.WriteEndArray();
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
        catch (TException)
        {
            return true;
        }
    }
}
