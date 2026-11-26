using System;
using System.Formats.Cbor;
using System.Linq;
using System.Threading.Tasks;
using Fdo.Serialization;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.Tests.Serialization;

public sealed class FdoServiceInfoCodecTests
{
    [Test]
    public async Task EmptyServiceInfoRoundTrips()
    {
        var codec = new FdoServiceInfoCodec();
        var entries = codec.Decode(Convert.FromHexString("80"));

        await Assert.That(entries.Count).IsEqualTo(0);
        await Assert.That(Convert.ToHexString(codec.Encode(entries).Span)).IsEqualTo("80");
    }

    [Test]
    public async Task OrderedDuplicateKeysAndEncodedValuesSurviveRoundTrip()
    {
        const string wire = "8382636D3A784241FF82636D3A7842615882636D3A78421800";
        byte[] source = Convert.FromHexString(wire);
        var codec = new FdoServiceInfoCodec();
        var entries = codec.Decode(source);
        Array.Fill(source, (byte)0);

        await Assert.That(entries.Select(entry => entry.Key).SequenceEqual(new[] { "m:x", "m:x", "m:x" })).IsTrue();
        await Assert.That(Convert.ToHexString(entries[0].EncodedValue.Span)).IsEqualTo("41FF");
        await Assert.That(Convert.ToHexString(entries[1].EncodedValue.Span)).IsEqualTo("6158");
        await Assert.That(Convert.ToHexString(entries[2].EncodedValue.Span)).IsEqualTo("1800");
        await Assert.That(Convert.ToHexString(codec.Encode(entries).Span)).IsEqualTo(wire);
    }

    [Test]
    [Arguments("1800")]
    [Arguments("FA3F800000")]
    [Arguments("D903E800")]
    public async Task EncodedValuesRetainNonPreferredRepresentationsAndUnknownTags(string value)
    {
        var codec = new FdoServiceInfoCodec();
        Entry[] entries = [new Entry("m:x", Convert.FromHexString(value))];
        var decoded = codec.Decode(codec.Encode(entries));

        await Assert.That(Convert.ToHexString(decoded[0].EncodedValue.Span)).IsEqualTo(value);
    }

    [Test]
    [Arguments("00")]
    [Arguments("8100")]
    [Arguments("818163613A78")]
    [Arguments("818363613A78410000")]
    [Arguments("818263613A7800")]
    [Arguments("818263613A7840")]
    [Arguments("818263613A78420000")]
    [Arguments("818263613A784261FF")]
    [Arguments("818263613A78439F00FF")]
    [Arguments("818263613A784118")]
    [Arguments("9FFF")]
    public async Task InvalidEntryShapesAndEmbeddedValuesAreRejected(string wire)
    {
        var codec = new FdoServiceInfoCodec();

        await Assert.That(Throws<CborContentException>(() => codec.Decode(Convert.FromHexString(wire)))).IsTrue();
    }

    [Test]
    public async Task EncodingRejectsMissingEntriesKeysAndInvalidValues()
    {
        var codec = new FdoServiceInfoCodec();
        Entry[] nullEntry = [null!];
        Entry[] nullKey = [new Entry(null!, new byte[] { 0x00 })];
        Entry[] emptyValue = [new Entry("m:x", ReadOnlyMemory<byte>.Empty)];
        Entry[] trailingValue = [new Entry("m:x", new byte[] { 0x00, 0x00 })];
        Entry[] indefiniteValue = [new Entry("m:x", new byte[] { 0x9f, 0xff })];

        await Assert.That(Throws<ArgumentException>(() => codec.Encode(nullEntry))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.Encode(nullKey))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.Encode(emptyValue))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.Encode(trailingValue))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.Encode(indefiniteValue))).IsTrue();
    }

    [Test]
    public async Task RejectsEquivalentKeysInAnEmbeddedMapOnEncodeAndDecode()
    {
        var codec = new FdoServiceInfoCodec();
        Entry[] entries = [new Entry("m:x", Convert.FromHexString("A20000180001"))];
        byte[] encoded = Convert.FromHexString("8182636D3A7846A20000180001");

        await Assert.That(Throws<CborContentException>(() => codec.Encode(entries))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.Decode(encoded))).IsTrue();
    }

    [Test]
    public async Task ByteLimitIncludesKeysWrappersAndEncodedValues()
    {
        Entry[] entries = [new Entry("m:x", Convert.FromHexString("41FF"))];
        var atLimit = new FdoServiceInfoCodec(maxEncodedBytes: 9);
        var belowLimit = new FdoServiceInfoCodec(maxEncodedBytes: 8);
        byte[] encoded = atLimit.Encode(entries).ToArray();

        await Assert.That(encoded.Length).IsEqualTo(9);
        await Assert.That(atLimit.Decode(encoded).Count).IsEqualTo(1);
        await Assert.That(Throws<CborContentException>(() => belowLimit.Encode(entries))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => belowLimit.Decode(encoded))).IsTrue();
    }

    [Test]
    public async Task ItemAndDepthLimitsApplyToTheEnvelopeAndEachEmbeddedValue()
    {
        Entry[] fourInnerItems = [new Entry("m:x", Convert.FromHexString("83000000"))];
        Entry[] fiveInnerItems = [new Entry("m:x", Convert.FromHexString("8400000000"))];
        Entry[] threeLevels = [new Entry("m:x", Convert.FromHexString("818100"))];
        Entry[] fourLevels = [new Entry("m:x", Convert.FromHexString("81818100"))];
        var itemLimited = new FdoServiceInfoCodec(maxItems: 4);
        var depthLimited = new FdoServiceInfoCodec(maxDepth: 3);
        var unlimited = new FdoServiceInfoCodec();
        ReadOnlyMemory<byte> fiveItemValue = unlimited.Encode(fiveInnerItems);
        ReadOnlyMemory<byte> fourLevelValue = unlimited.Encode(fourLevels);

        await Assert.That(itemLimited.Decode(itemLimited.Encode(fourInnerItems)).Count).IsEqualTo(1);
        await Assert.That(Throws<CborContentException>(() => itemLimited.Encode(fiveInnerItems))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => itemLimited.Decode(fiveItemValue))).IsTrue();
        await Assert.That(Throws<CborContentException>(
            () => new FdoServiceInfoCodec(maxItems: 3).Encode(fourInnerItems))).IsTrue();
        await Assert.That(depthLimited.Decode(depthLimited.Encode(threeLevels)).Count).IsEqualTo(1);
        await Assert.That(Throws<CborContentException>(() => depthLimited.Encode(fourLevels))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => depthLimited.Decode(fourLevelValue))).IsTrue();
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
