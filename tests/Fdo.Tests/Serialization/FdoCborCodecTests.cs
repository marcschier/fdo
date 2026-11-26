// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Linq;
using System.Threading.Tasks;
using Fdo.Serialization;
using Fdo.Transport;

namespace Fdo.Tests.Serialization;

public sealed class FdoCborCodecTests
{
    [Test]
    [Arguments("00")]
    [Arguments("20")]
    [Arguments("40")]
    [Arguments("60")]
    [Arguments("80")]
    [Arguments("A0")]
    [Arguments("F4")]
    [Arguments("F5")]
    [Arguments("F6")]
    [Arguments("F7")]
    [Arguments("F820")]
    [Arguments("F93C00")]
    [Arguments("F98000")]
    [Arguments("F97C00")]
    [Arguments("F97E00")]
    [Arguments("FA47C35000")]
    [Arguments("FB3FF199999999999A")]
    [Arguments("D8184180")]
    public async Task ValidDefiniteValuesRetainTheirExactEncoding(string hex)
    {
        byte[] bytes = Convert.FromHexString(hex);
        ReadOnlyMemory<byte> result = new FdoCborCodec().ValidateAndCopy(bytes);

        await Assert.That(result.ToArray().SequenceEqual(bytes)).IsTrue();
    }

    [Test]
    [Arguments("")]
    [Arguments("0000")]
    [Arguments("1800")]
    [Arguments("190018")]
    [Arguments("5F40FF")]
    [Arguments("7F60FF")]
    [Arguments("9F00FF")]
    [Arguments("BF0000FF")]
    [Arguments("61FF")]
    [Arguments("8200")]
    [Arguments("1A0000")]
    [Arguments("5A7FFFFFFF")]
    [Arguments("C0")]
    [Arguments("FC")]
    [Arguments("F814")]
    [Arguments("A200000001")]
    [Arguments("FA3F800000")]
    [Arguments("FB3FF0000000000000")]
    [Arguments("F97E01")]
    public async Task MalformedOrNondeterministicValuesAreRejected(string hex)
    {
        await Assert.That(Rejects(() => new FdoCborCodec().ValidateAndCopy(Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    public async Task MapKeysUseLengthFirstRatherThanCtap2Ordering()
    {
        var codec = new FdoCborCodec();
        byte[] lengthFirst = Convert.FromHexString("A26000181800");
        byte[] bytewise = Convert.FromHexString("A21818006000");

        await Assert.That(codec.ValidateAndCopy(lengthFirst).ToArray().SequenceEqual(lengthFirst)).IsTrue();
        await Assert.That(Rejects(() => codec.ValidateAndCopy(bytewise))).IsTrue();
    }

    [Test]
    public async Task CanonicalMapRejectsPositiveAndNegativeZeroAsDuplicateKeys()
    {
        byte[] encoded = Convert.FromHexString("A2F9000000F9800001");

        await Assert.That(Rejects(() => new FdoCborCodec().ValidateAndCopy(encoded))).IsTrue();
    }

    [Test]
    [Arguments("A20000180001")]
    [Arguments("A22000380001")]
    [Arguments("A241AA005801AA01")]
    [Arguments("A261610078016101")]
    [Arguments("A2F93C0000FA3F80000001")]
    [Arguments("A2F97E0000FA7FC0000001")]
    [Arguments("A2F97E0000F9FE0001")]
    public async Task EmbeddedMapsRejectEquivalentScalarKeysWithDifferentEncodings(string hex)
    {
        byte[] encoded = Convert.FromHexString(hex);

        await Assert.That(Rejects(() => new FdoCborCodec().ValidateEmbeddedValueAndCopy(encoded))).IsTrue();
    }

    [Test]
    [Arguments("A20000F9000001")]
    [Arguments("A2F97E0000F97E0101")]
    [Arguments("A300008000A000")]
    public async Task DistinctScalarAndCompoundKeyKindsRemainDistinct(string hex)
    {
        byte[] encoded = Convert.FromHexString(hex);

        await Assert.That(new FdoCborCodec().ValidateEmbeddedValueAndCopy(encoded).ToArray().SequenceEqual(encoded))
            .IsTrue();
    }

    [Test]
    [Arguments("A281000081180001")]
    [Arguments("A2D903E80000D903E8180001")]
    public async Task MultipleCompoundKeysOfOneKindAreExplicitlyUnsupported(string hex)
    {
        byte[] encoded = Convert.FromHexString(hex);

        await Assert.That(RejectsUnsupported(() =>
            new FdoCborCodec().ValidateEmbeddedValueAndCopy(encoded))).IsTrue();
    }

    [Test]
    public async Task NestedMapsAlsoCheckSemanticKeyUniqueness()
    {
        byte[] encoded = Convert.FromHexString("81A20000180001");

        await Assert.That(Rejects(() => new FdoCborCodec().ValidateEmbeddedValueAndCopy(encoded))).IsTrue();
    }

    [Test]
    public async Task ByteLimitAcceptsExactSizeAndRejectsOneMore()
    {
        var codec = new FdoCborCodec(maxEncodedBytes: 3);

        await Assert.That(codec.ValidateAndCopy(Convert.FromHexString("420001")).Length).IsEqualTo(3);
        await Assert.That(Rejects(() => codec.ValidateAndCopy(Convert.FromHexString("43000102")))).IsTrue();
    }

    [Test]
    [Arguments("81818100", "8181818100")]
    [Arguments("C0C0C000", "C0C0C0C000")]
    public async Task DepthLimitCountsContainersAndTags(string atLimit, string overLimit)
    {
        var codec = new FdoCborCodec(maxDepth: 4);

        await Assert.That(codec.ValidateAndCopy(Convert.FromHexString(atLimit)).Length).IsEqualTo(4);
        await Assert.That(Rejects(() => codec.ValidateAndCopy(Convert.FromHexString(overLimit)))).IsTrue();
    }

    [Test]
    public async Task ItemLimitCountsContainersAndEachMapKeyAndValue()
    {
        var codec = new FdoCborCodec(maxItems: 3);

        await Assert.That(codec.ValidateAndCopy(Convert.FromHexString("820001")).Length).IsEqualTo(3);
        await Assert.That(codec.ValidateAndCopy(Convert.FromHexString("A10001")).Length).IsEqualTo(3);
        await Assert.That(Rejects(() => codec.ValidateAndCopy(Convert.FromHexString("83000102")))).IsTrue();
        await Assert.That(Rejects(() => codec.ValidateAndCopy(Convert.FromHexString("A200010203")))).IsTrue();
    }

    [Test]
    public async Task SignedByteStringPayloadIsNeitherDecodedNorNormalized()
    {
        byte[] wrapped = Convert.FromHexString("431800FF");
        ReadOnlyMemory<byte> payload = new FdoCborCodec().ReadByteStringPayload(wrapped);
        wrapped[1] = 0;

        await Assert.That(Convert.ToHexString(payload.Span)).IsEqualTo("1800FF");
    }

    [Test]
    public async Task ByteStringPayloadRequiresOneDefiniteByteString()
    {
        var codec = new FdoCborCodec();

        await Assert.That(codec.ReadByteStringPayload(Convert.FromHexString("40")).Length).IsEqualTo(0);
        await Assert.That(Rejects(() => codec.ReadByteStringPayload(Convert.FromHexString("60")))).IsTrue();
        await Assert.That(Rejects(() => codec.ReadByteStringPayload(Convert.FromHexString("5F40FF")))).IsTrue();
        await Assert.That(Rejects(() => codec.ReadByteStringPayload(Convert.FromHexString("4000")))).IsTrue();
    }

    [Test]
    public async Task GenericServiceInfoValuePreservesTextAndBinaryWithoutTransferEncoding()
    {
        byte[] value = Convert.FromHexString("82636162634300FF80");
        ReadOnlyMemory<byte> retained = new FdoCborCodec().ValidateAndCopy(value);
        value[2] = 0;

        await Assert.That(Convert.ToHexString(retained.Span)).IsEqualTo("82636162634300FF80");
    }

    [Test]
    public async Task StreamMessageHasExactKnownEncoding()
    {
        var codec = new FdoCborCodec();
        ReadOnlyMemory<byte> encoded = codec.EncodeStreamMessage(30, FdoProtocolVersion.V20, null, new byte[] { 0x80 });

        await Assert.That(Convert.ToHexString(encoded.Span)).IsEqualTo("8508181E18C8A080");
        FdoCborCodec.StreamMessage decoded = codec.DecodeStreamMessage(encoded);
        await Assert.That(decoded.Length).IsEqualTo(8);
        await Assert.That(decoded.MessageType).IsEqualTo((ushort)30);
        await Assert.That(decoded.Version).IsEqualTo(FdoProtocolVersion.V20);
        await Assert.That(decoded.Authorization).IsNull();
        await Assert.That(Convert.ToHexString(decoded.Body.Span)).IsEqualTo("80");
    }

    [Test]
    public async Task StreamMessageRetainsTokenAndExactSignedBodyAfterSourceMutation()
    {
        var codec = new FdoCborCodec();
        byte[] body = Convert.FromHexString("81431800FF");
        byte[] frame = codec.EncodeStreamMessage(33, FdoProtocolVersion.V20, "token-1", body).ToArray();
        FdoCborCodec.StreamMessage result = codec.DecodeStreamMessage(frame);
        Array.Fill(frame, (byte)0);
        Array.Fill(body, (byte)0);

        await Assert.That(result.MessageType).IsEqualTo((ushort)33);
        await Assert.That(result.Authorization).IsEqualTo("token-1");
        await Assert.That(Convert.ToHexString(result.Body.Span)).IsEqualTo("81431800FF");
    }

    [Test]
    [Arguments(14, 22, 1)]
    [Arguments(15, 23, 1)]
    [Arguments(16, 25, 2)]
    [Arguments(244, 254, 2)]
    [Arguments(245, 255, 2)]
    [Arguments(246, 257, 3)]
    [Arguments(65522, 65534, 3)]
    [Arguments(65523, 65535, 3)]
    [Arguments(65524, 65538, 5)]
    public async Task StreamLengthIncludesItsOwnWidthAcrossEncodingBoundaries(
        int payloadLength, int expectedFrameLength, int expectedLengthBytes)
    {
        var bodyWriter = new CborWriter(CborConformanceMode.Canonical);
        bodyWriter.WriteByteString(new byte[payloadLength]);
        var codec = new FdoCborCodec(maxEncodedBytes: 100000);
        ReadOnlyMemory<byte> frame = codec.EncodeStreamMessage(30, FdoProtocolVersion.V20, null, bodyWriter.Encode());
        var reader = new CborReader(frame, CborConformanceMode.Canonical);
        reader.ReadStartArray();
        int beforeLength = reader.BytesRemaining;

        await Assert.That(reader.ReadUInt64()).IsEqualTo((ulong)frame.Length);
        await Assert.That(frame.Length).IsEqualTo(expectedFrameLength);
        await Assert.That(beforeLength - reader.BytesRemaining).IsEqualTo(expectedLengthBytes);
        await Assert.That(codec.DecodeStreamMessage(frame).Body.Length).IsEqualTo(bodyWriter.BytesWritten);
    }

    [Test]
    public async Task HttpMetadataReconstructsStreamMessageWithoutChangingTheBody()
    {
        byte[] body = Convert.FromHexString("81431800FF");
        FdoCborCodec.StreamMessage message = new FdoCborCodec().CreateStreamMessage(
            33, FdoProtocolVersion.V20, "token-1", body);
        body[1] = 0;

        await Assert.That(message.MessageType).IsEqualTo((ushort)33);
        await Assert.That(message.Length).IsEqualTo(27);
        await Assert.That(message.Version).IsEqualTo(FdoProtocolVersion.V20);
        await Assert.That(message.Authorization).IsEqualTo("token-1");
        await Assert.That(Convert.ToHexString(message.Body.Span)).IsEqualTo("81431800FF");
    }

    [Test]
    public async Task StreamFrameLimitIncludesEnvelopeOverhead()
    {
        var codec = new FdoCborCodec(maxEncodedBytes: 8);

        await Assert.That(codec.EncodeStreamMessage(30, FdoProtocolVersion.V20, null, new byte[] { 0x80 }).Length).IsEqualTo(8);
        await Assert.That(Rejects(() => codec.EncodeStreamMessage(
            30, FdoProtocolVersion.V20, null, new byte[] { 0x81, 0x00 }))).IsTrue();
    }

    [Test]
    [Arguments("840000A080")]
    [Arguments("8509181E18C8A080")]
    [Arguments("8520181E18C8A080")]
    [Arguments("8508181E18C8A08000")]
    [Arguments("850B1A0001000018C8A080")]
    [Arguments("850B181E1A00010000A080")]
    [Arguments("8507181E00A080")]
    [Arguments("8508181E18C88080")]
    [Arguments("850B181E18C8A161780080")]
    public async Task InvalidStreamFramesAreRejected(string hex)
    {
        await Assert.That(Rejects(() => new FdoCborCodec().DecodeStreamMessage(Convert.FromHexString(hex)))).IsTrue();
    }

    [Test]
    [Arguments("00")]
    [Arguments("F6")]
    [Arguments("420102")]
    [Arguments("D818431800FF")]
    public async Task UndefinedStreamTokenTypeRetainsItsOpaqueEncoding(string tokenHex)
    {
        var codec = new FdoCborCodec();
        byte[] token = Convert.FromHexString(tokenHex);
        byte[] frame = codec.EncodeStreamMessageWithEncodedToken(
            30, FdoProtocolVersion.V20, token, new byte[] { 0x80 }).ToArray();
        FdoCborCodec.StreamMessage decoded = codec.DecodeStreamMessage(frame);
        byte[] reencoded = codec.EncodeStreamMessageWithEncodedToken(
            decoded.MessageType, decoded.Version, decoded.EncodedToken, decoded.Body).ToArray();
        await Assert.That(reencoded.SequenceEqual(frame)).IsTrue();
        Array.Fill(frame, (byte)0);
        Array.Fill(token, (byte)0);

        await Assert.That(decoded.Authorization).IsNull();
        await Assert.That(Convert.ToHexString(decoded.EncodedToken!.Value.Span)).IsEqualTo(tokenHex);
        await Assert.That(codec.DecodeStreamMessage(reencoded).Length).IsEqualTo(decoded.Length);
        await Assert.That(Convert.ToHexString(codec.DecodeStreamMessage(reencoded).EncodedToken!.Value.Span)).IsEqualTo(tokenHex);
    }

    [Test]
    public async Task HttpBodyLimitDoesNotCountSeparateAuthorizationMetadata()
    {
        FdoCborCodec.StreamMessage message = new FdoCborCodec(maxEncodedBytes: 1).CreateStreamMessage(
            30, FdoProtocolVersion.V20, "token-1", new byte[] { 0x80 });

        await Assert.That(message.Body.Length).IsEqualTo(1);
        await Assert.That(message.Authorization).IsEqualTo("token-1");
        await Assert.That(Convert.ToHexString(message.EncodedToken!.Value.Span)).IsEqualTo("67746F6B656E2D31");
    }

    [Test]
    public async Task StreamTokenHasKnownOpaqueEncodingAndDistinguishesAbsenceFromNull()
    {
        var codec = new FdoCborCodec();
        ReadOnlyMemory<byte> frame = codec.EncodeStreamMessageWithEncodedToken(
            30, FdoProtocolVersion.V20, new byte[] { 0x42, 0x01, 0x02 }, new byte[] { 0x80 });
        await Assert.That(Convert.ToHexString(frame.Span)).IsEqualTo("8511181E18C8A165746F6B656E42010280");
        FdoCborCodec.StreamMessage absent = codec.DecodeStreamMessage(codec.EncodeStreamMessageWithEncodedToken(
            30, FdoProtocolVersion.V20, null, new byte[] { 0x80 }));
        FdoCborCodec.StreamMessage explicitNull = codec.DecodeStreamMessage(codec.EncodeStreamMessageWithEncodedToken(
            30, FdoProtocolVersion.V20, new byte[] { 0xf6 }, new byte[] { 0x80 }));

        await Assert.That(absent.EncodedToken.HasValue).IsFalse();
        await Assert.That(explicitNull.EncodedToken.HasValue).IsTrue();
        await Assert.That(Convert.ToHexString(explicitNull.EncodedToken!.Value.Span)).IsEqualTo("F6");
    }

    [Test]
    public async Task StreamWriterRejectsNoncanonicalBodyAndUninitializedVersion()
    {
        var codec = new FdoCborCodec();
        await Assert.That(Rejects(() => codec.EncodeStreamMessage(
            30, FdoProtocolVersion.V20, null, new byte[] { 0x18, 0x00 }))).IsTrue();
        bool rejected = false;
        try
        {
            codec.EncodeStreamMessage(30, default, null, new byte[] { 0x80 });
        }
        catch (ArgumentException)
        {
            rejected = true;
        }

        await Assert.That(rejected).IsTrue();
    }

    private static bool Rejects(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (CborContentException)
        {
            return true;
        }
    }

    private static bool RejectsUnsupported(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (NotSupportedException)
        {
            return true;
        }
    }
}
