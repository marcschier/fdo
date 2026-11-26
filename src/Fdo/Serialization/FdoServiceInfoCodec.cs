// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Text;

namespace Fdo.Serialization;

/// <summary>
/// Reads and writes ordered ServiceInfo entries without interpreting modules,
/// authenticating the sender, or selecting a payload transfer encoding.
/// </summary>
internal sealed class FdoServiceInfoCodec
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private readonly FdoCborCodec _cbor;
    private readonly int _maxEncodedBytes;
    private readonly int _maxItems;

    public FdoServiceInfoCodec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _maxEncodedBytes = maxEncodedBytes;
        _maxItems = maxItems;
    }

    /// <summary>
    /// The enclosing array and each embedded CBOR value have independent depth
    /// and item limits. Values retain their original encoding.
    /// </summary>
    public IReadOnlyList<Entry> Decode(ReadOnlyMemory<byte> encoded)
    {
        ReadOnlyMemory<byte> copy = _cbor.ValidateAndCopy(encoded);
        var reader = new CborReader(copy, CborConformanceMode.Canonical);
        RequireState(reader, CborReaderState.StartArray);
        int count = reader.ReadStartArray()
            ?? throw new CborContentException("ServiceInfo must use a definite-length array.");
        var entries = new Entry[count];

        for (int i = 0; i < entries.Length; i++)
        {
            RequireState(reader, CborReaderState.StartArray);
            if (reader.ReadStartArray() != 2)
            {
                throw new CborContentException("A ServiceInfo entry must contain a key and a value.");
            }

            RequireState(reader, CborReaderState.TextString);
            string key = reader.ReadTextString();
            RequireState(reader, CborReaderState.ByteString);
            ReadOnlyMemory<byte> value = _cbor.ValidateEmbeddedValueAndCopy(reader.ReadDefiniteLengthByteString());
            reader.ReadEndArray();
            entries[i] = new Entry(key, value);
        }

        reader.ReadEndArray();
        return Array.AsReadOnly(entries);
    }

    /// <summary>
    /// Writes each value as an encoded CBOR item inside its byte-string wrapper.
    /// Duplicate keys and their order are retained.
    /// </summary>
    public ReadOnlyMemory<byte> Encode(IReadOnlyList<Entry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        int count = entries.Count;
        if (count < 0 || count > _maxEncodedBytes || 1L + (3L * count) > _maxItems)
        {
            throw new CborContentException("ServiceInfo exceeds the item or byte limit.");
        }

        long encodedSize = HeaderSize(count);
        CheckEncodedSize(encodedSize);
        var validated = new Entry[count];
        for (int i = 0; i < validated.Length; i++)
        {
            Entry entry = entries[i]
                ?? throw new ArgumentException("ServiceInfo entries cannot be null.", nameof(entries));
            string key = entry.Key
                ?? throw new ArgumentException("ServiceInfo keys cannot be null.", nameof(entries));
            int keyLength = StrictUtf8.GetByteCount(key);
            int valueLength = entry.EncodedValue.Length;
            encodedSize += 1L + HeaderSize(keyLength) + keyLength + HeaderSize(valueLength) + valueLength;
            CheckEncodedSize(encodedSize);
            validated[i] = new Entry(key, _cbor.ValidateEmbeddedValueAndCopy(entry.EncodedValue));
        }

        var writer = new CborWriter(CborConformanceMode.Canonical, initialCapacity: (int)encodedSize);
        writer.WriteStartArray(validated.Length);
        foreach (Entry entry in validated)
        {
            writer.WriteStartArray(2);
            writer.WriteTextString(entry.Key);
            writer.WriteByteString(entry.EncodedValue.Span);
            writer.WriteEndArray();
        }

        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    private void CheckEncodedSize(long size)
    {
        if (size > _maxEncodedBytes)
        {
            throw new CborContentException("ServiceInfo exceeds the encoded byte limit.");
        }
    }

    private static int HeaderSize(int value) => value switch
    {
        <= 23 => 1,
        <= byte.MaxValue => 2,
        <= ushort.MaxValue => 3,
        _ => 5,
    };

    private static void RequireState(CborReader reader, CborReaderState expected)
    {
        if (reader.PeekState() != expected)
        {
            throw new CborContentException($"Expected CBOR {expected} in ServiceInfo.");
        }
    }

    /// <summary>
    /// One key and the encoded CBOR item inside its byte-string wrapper.
    /// The key's module semantics and value are not interpreted here.
    /// </summary>
    public sealed record Entry(string Key, ReadOnlyMemory<byte> EncodedValue);
}
