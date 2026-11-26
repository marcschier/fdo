using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Text;
using Fdo.Cryptography;
using Fdo.Serialization;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.ServiceInfo;

/// <summary>
/// Packs complete ServiceInfo entries into TO2 ServiceInfo messages and
/// reassembles the entries a peer sends across rounds. Neither direction
/// splits a single value; a value that cannot fit one message is rejected.
/// </summary>
internal static class FdoServiceInfoBatches
{
    /// <summary>
    /// The most entries one logical ServiceInfo transfer may carry, summed over
    /// every round that the IsMoreServiceInfo flag joins.
    /// </summary>
    public const int MaxAssembledEntries = 64;

    /// <summary>
    /// The most bytes the encoded ServiceInfo array of one logical transfer may
    /// occupy, counting the array header and every framed entry.
    /// </summary>
    public const int MaxAssembledBytes = ushort.MaxValue;

    // A TO2 ServiceInfo plaintext wraps the ServiceInfo array in a three-field
    // array whose header and two leading one-byte fields add three bytes.
    private const int MessageOverhead = 3;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>
    /// Returns the bytes one entry adds to an encoded ServiceInfo array.
    /// </summary>
    public static long GetFramedSize(Entry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(entry.Key);
        int keyLength = StrictUtf8.GetByteCount(entry.Key);
        int valueLength = entry.EncodedValue.Length;
        return 1L + FdoCborCodec.GetHeaderSize((ulong)keyLength) + keyLength +
            FdoCborCodec.GetHeaderSize((ulong)valueLength) + valueLength;
    }

    /// <summary>
    /// Splits the entries, in order, into the fewest messages that each meet
    /// the plaintext limit and, once sealed, the peer's message limit. An empty
    /// list yields one empty message.
    /// </summary>
    /// <exception cref="CborContentException">
    /// The transfer exceeds the assembly limits, or one entry cannot fit an
    /// otherwise empty message.
    /// </exception>
    public static IReadOnlyList<IReadOnlyList<Entry>> Split(
        IReadOnlyList<Entry> entries,
        int maxPlaintextBytes,
        Func<int, long> sealedLength,
        long maxSealedBytes)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(sealedLength);
        if (entries.Count > MaxAssembledEntries)
        {
            throw new CborContentException("The ServiceInfo transfer exceeds the entry limit.");
        }

        var batches = new List<IReadOnlyList<Entry>>();
        var current = new List<Entry>();
        long currentSize = 0;
        long totalSize = 0;
        foreach (Entry entry in entries)
        {
            long size = GetFramedSize(entry);
            totalSize += size;
            if (FdoCborCodec.GetHeaderSize((ulong)entries.Count) + totalSize > MaxAssembledBytes)
            {
                throw new CborContentException("The ServiceInfo transfer exceeds the byte limit.");
            }

            if (Fits(current.Count + 1, currentSize + size, maxPlaintextBytes, sealedLength, maxSealedBytes))
            {
                current.Add(entry);
                currentSize += size;
                continue;
            }

            if (current.Count == 0 || !Fits(1, size, maxPlaintextBytes, sealedLength, maxSealedBytes))
            {
                throw new CborContentException("A ServiceInfo entry does not fit one message.");
            }

            batches.Add(current.ToArray());
            current = [entry];
            currentSize = size;
        }

        if (!Fits(current.Count, currentSize, maxPlaintextBytes, sealedLength, maxSealedBytes))
        {
            throw new CborContentException("An empty ServiceInfo message does not fit the message limit.");
        }

        batches.Add(current.ToArray());
        return batches;
    }

    private static bool Fits(
        int count, long entriesSize, int maxPlaintextBytes, Func<int, long> sealedLength, long maxSealedBytes)
    {
        long plaintext = FdoCborCodec.GetHeaderSize((ulong)count) + entriesSize + MessageOverhead;
        return plaintext <= maxPlaintextBytes && sealedLength((int)plaintext) <= maxSealedBytes;
    }

    /// <summary>
    /// Collects the entries of one logical transfer as they arrive and rejects
    /// the round that would exceed the assembly limits, so a peer cannot grow
    /// the collection while it keeps IsMoreServiceInfo set.
    /// </summary>
    public sealed class Assembler
    {
        private readonly List<Entry> _entries = [];
        private long _size;

        public int Count => _entries.Count;

        /// <exception cref="CborContentException">The limits would be exceeded.</exception>
        public void Append(IReadOnlyList<Entry> entries)
        {
            ArgumentNullException.ThrowIfNull(entries);
            long count = (long)_entries.Count + entries.Count;
            long size = _size;
            foreach (Entry entry in entries)
            {
                size += GetFramedSize(entry);
            }

            if (count > MaxAssembledEntries ||
                FdoCborCodec.GetHeaderSize((ulong)count) + size > MaxAssembledBytes)
            {
                throw new CborContentException("The assembled ServiceInfo exceeds the assembly limit.");
            }

            _entries.AddRange(entries);
            _size = size;
        }

        /// <summary>Returns the collected entries and starts a new transfer.</summary>
        public IReadOnlyList<Entry> Take()
        {
            Entry[] result = _entries.ToArray();
            _entries.Clear();
            _size = 0;
            return Array.AsReadOnly(result);
        }

        /// <summary>
        /// Zeroes the values collected so far. Use only for entries decoded into
        /// buffers this process owns.
        /// </summary>
        public void Clear()
        {
            foreach (Entry entry in _entries)
            {
                FdoSecretBuffer.ClearOwned(entry.EncodedValue);
            }

            _entries.Clear();
            _size = 0;
        }
    }
}
