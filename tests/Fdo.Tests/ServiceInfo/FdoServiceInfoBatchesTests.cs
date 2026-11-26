using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Fdo.Serialization;
using Fdo.ServiceInfo;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.Tests.ServiceInfo;

[UnsupportedOSPlatform("browser")]
public sealed class FdoServiceInfoBatchesTests
{
    private static readonly Func<int, long> Plain = length => length;

    [Test]
    [Arguments(0)]
    [Arguments(22)]
    [Arguments(23)]
    [Arguments(253)]
    [Arguments(254)]
    [Arguments(1300)]
    public async Task FramedSizeMatchesTheEncodedMessage(int contentLength)
    {
        Entry[] entries = [Value("devmod:a", contentLength), Value("fdo.csr:simpleenroll-req", 3)];
        var codec = new FdoTo2ServiceInfoCodec();
        long expected = 1 + entries.Sum(FdoServiceInfoBatches.GetFramedSize) + 3;

        await Assert.That((long)codec.EncodeOwner(false, false, entries).Length).IsEqualTo(expected);
        await Assert.That((long)codec.EncodeDevice(false, entries).Length).IsEqualTo(expected);
    }

    [Test]
    public async Task SplitsEntriesGreedilyInOrderWithinThePlaintextLimit()
    {
        Entry[] entries = Enumerable.Range(0, 5).Select(i => Value($"m:{i}", 10)).ToArray();
        int limit = MessageLength(entries[..2]);

        IReadOnlyList<IReadOnlyList<Entry>> batches = FdoServiceInfoBatches.Split(entries, limit, Plain, long.MaxValue);

        await Assert.That(batches.Select(batch => batch.Count).SequenceEqual(new[] { 2, 2, 1 })).IsTrue();
        await Assert.That(batches.SelectMany(batch => batch).SequenceEqual(entries)).IsTrue();
        foreach (IReadOnlyList<Entry> batch in batches)
        {
            await Assert.That(new FdoTo2ServiceInfoCodec().EncodeDevice(true, batch).Length).IsLessThanOrEqualTo(limit);
        }
    }

    [Test]
    public async Task UsesOneMessageAtTheExactLimitAndTwoOneByteBelowIt()
    {
        Entry[] entries = [Value("m:a", 40), Value("m:b", 40)];
        int exact = MessageLength(entries);

        await Assert.That(FdoServiceInfoBatches.Split(entries, exact, Plain, long.MaxValue).Count).IsEqualTo(1);
        await Assert.That(FdoServiceInfoBatches.Split(entries, exact - 1, Plain, long.MaxValue).Count).IsEqualTo(2);
    }

    [Test]
    public async Task AppliesThePeerLimitToTheSealedLength()
    {
        Entry[] entries = [Value("m:a", 40), Value("m:b", 40)];
        int plaintext = MessageLength(entries);
        Func<int, long> sealedLength = length => length + 100L;

        await Assert.That(FdoServiceInfoBatches.Split(entries, int.MaxValue, sealedLength, plaintext + 100L).Count)
            .IsEqualTo(1);
        await Assert.That(FdoServiceInfoBatches.Split(entries, int.MaxValue, sealedLength, plaintext + 99L).Count)
            .IsEqualTo(2);
    }

    [Test]
    public async Task ReturnsOneEmptyMessageForNoEntries()
    {
        IReadOnlyList<IReadOnlyList<Entry>> batches = FdoServiceInfoBatches.Split([], 4, Plain, 4);

        await Assert.That(batches.Count).IsEqualTo(1);
        await Assert.That(batches[0].Count).IsEqualTo(0);
        await Assert.That(Throws<CborContentException>(() => FdoServiceInfoBatches.Split([], 3, Plain, 4))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => FdoServiceInfoBatches.Split([], 4, Plain, 3))).IsTrue();
    }

    [Test]
    public async Task RejectsAValueThatCannotFitAnEmptyMessageWithoutSplittingIt()
    {
        Entry small = Value("m:a", 4);
        Entry large = Value("m:b", 200);
        int limit = MessageLength([large]);

        await Assert.That(FdoServiceInfoBatches.Split([small, large], limit, Plain, long.MaxValue).Count).IsEqualTo(2);
        await Assert.That(Throws<CborContentException>(() =>
            FdoServiceInfoBatches.Split([small, large], limit - 1, Plain, long.MaxValue))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            FdoServiceInfoBatches.Split([large], int.MaxValue, Plain, limit - 1))).IsTrue();
    }

    [Test]
    public async Task EnforcesTheTransferEntryLimit()
    {
        Entry[] entries = Enumerable.Range(0, FdoServiceInfoBatches.MaxAssembledEntries + 1)
            .Select(i => Value($"m:{i}", 0)).ToArray();

        await Assert.That(FdoServiceInfoBatches.Split(
            entries[..FdoServiceInfoBatches.MaxAssembledEntries], int.MaxValue, Plain, long.MaxValue).Count).IsEqualTo(1);
        await Assert.That(Throws<CborContentException>(() =>
            FdoServiceInfoBatches.Split(entries, int.MaxValue, Plain, long.MaxValue))).IsTrue();
    }

    [Test]
    public async Task EnforcesTheTransferByteLimitAcrossMessages()
    {
        // Each entry frames to 11 + contentLength bytes: the entry array, the key,
        // the byte-string wrapper and the inner byte string.
        Entry first = Value("m:a", 32000);
        int remaining = FdoServiceInfoBatches.MaxAssembledBytes - 1 - (int)FdoServiceInfoBatches.GetFramedSize(first);
        Entry fits = Value("m:b", remaining - 11);
        Entry over = Value("m:b", remaining - 10);

        await Assert.That(FdoServiceInfoBatches.GetFramedSize(fits)).IsEqualTo((long)remaining);
        await Assert.That(FdoServiceInfoBatches.Split([first, fits], 40000, Plain, long.MaxValue).Count).IsEqualTo(2);
        await Assert.That(Throws<CborContentException>(() =>
            FdoServiceInfoBatches.Split([first, over], 40000, Plain, long.MaxValue))).IsTrue();
    }

    [Test]
    public async Task AssemblerRejectsTheRoundThatExceedsTheEntryLimitAndKeepsEarlierEntries()
    {
        var assembler = new FdoServiceInfoBatches.Assembler();
        Entry[] entries = Enumerable.Range(0, FdoServiceInfoBatches.MaxAssembledEntries)
            .Select(i => Value($"m:{i}", 0)).ToArray();
        assembler.Append(entries[..32]);
        assembler.Append(entries[32..]);

        await Assert.That(Throws<CborContentException>(() => assembler.Append([Value("m:x", 0)]))).IsTrue();
        await Assert.That(assembler.Count).IsEqualTo(FdoServiceInfoBatches.MaxAssembledEntries);
        await Assert.That(assembler.Take().SequenceEqual(entries)).IsTrue();
        await Assert.That(assembler.Count).IsEqualTo(0);
    }

    [Test]
    public async Task AssemblerRejectsTheRoundThatExceedsTheByteLimit()
    {
        var assembler = new FdoServiceInfoBatches.Assembler();
        Entry first = Value("m:a", 32000);
        int remaining = FdoServiceInfoBatches.MaxAssembledBytes - 1 - (int)FdoServiceInfoBatches.GetFramedSize(first);
        assembler.Append([first]);

        await Assert.That(Throws<CborContentException>(() => assembler.Append([Value("m:b", remaining - 10)])))
            .IsTrue();
        assembler.Append([Value("m:b", remaining - 11)]);
        await Assert.That(assembler.Count).IsEqualTo(2);
    }

    [Test]
    public async Task AssemblerTakeStartsANewTransfer()
    {
        var assembler = new FdoServiceInfoBatches.Assembler();
        Entry[] entries = Enumerable.Range(0, FdoServiceInfoBatches.MaxAssembledEntries)
            .Select(i => Value($"m:{i}", 0)).ToArray();
        assembler.Append(entries);
        _ = assembler.Take();

        assembler.Append(entries);
        await Assert.That(assembler.Count).IsEqualTo(FdoServiceInfoBatches.MaxAssembledEntries);
    }

    [Test]
    public async Task AssemblerClearZeroesCollectedValues()
    {
        var assembler = new FdoServiceInfoBatches.Assembler();
        byte[] value = [0x43, 0x01, 0x02, 0x03];
        assembler.Append([new Entry("m:a", value)]);

        assembler.Clear();

        await Assert.That(value.All(b => b == 0)).IsTrue();
        await Assert.That(assembler.Count).IsEqualTo(0);
    }

    private static Entry Value(string key, int contentLength)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteByteString(new byte[contentLength]);
        return new Entry(key, writer.Encode());
    }

    private static int MessageLength(IReadOnlyList<Entry> entries) =>
        new FdoTo2ServiceInfoCodec().EncodeDevice(false, entries).Length;

    private static bool Throws<T>(Action action)
        where T : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (T)
        {
            return true;
        }
    }
}
