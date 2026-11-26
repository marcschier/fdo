// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Text;

namespace Fdo.Serialization;

/// <summary>Reads and writes the shared capability and vendor fields.</summary>
internal static class FdoCapabilityFields
{
    private const byte ReservedFirstByteMask = 0x78;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static Parsed Read(CborReader reader)
    {
        RequireState(reader, CborReaderState.ByteString);
        ReadOnlyMemory<byte> flags = reader.ReadDefiniteLengthByteString();
        if (HasReservedFlags(flags.Span))
        {
            throw new CborContentException("Reserved capability flags in the first byte must be zero.");
        }

        RequireState(reader, CborReaderState.StartArray);
        int vendorCount = reader.ReadStartArray()
            ?? throw new CborContentException("Vendor capabilities must use a definite-length array.");
        var vendors = new string[vendorCount];
        for (int i = 0; i < vendors.Length; i++)
        {
            RequireState(reader, CborReaderState.TextString);
            vendors[i] = reader.ReadTextString();
        }

        reader.ReadEndArray();
        return new Parsed(flags, Array.AsReadOnly(vendors));
    }

    public static Prepared Prepare(
        ReadOnlyMemory<byte> capabilityFlags,
        IReadOnlyList<string> vendorCapabilities,
        int maxEncodedBytes,
        int maxItems,
        int additionalItems,
        long additionalEncodedBytes)
    {
        ArgumentNullException.ThrowIfNull(vendorCapabilities);
        if (capabilityFlags.Length > maxEncodedBytes)
        {
            throw new CborContentException("The capability fields exceed the encoded byte limit.");
        }

        byte[] flags = capabilityFlags.ToArray();
        if (HasReservedFlags(flags))
        {
            throw new ArgumentException("Reserved capability flags in the first byte must be zero.", nameof(capabilityFlags));
        }

        int vendorCount = vendorCapabilities.Count;
        if (vendorCount < 0 || vendorCount > maxEncodedBytes ||
            3L + vendorCount + additionalItems > maxItems)
        {
            throw new CborContentException("The message exceeds the item or byte limit.");
        }

        long encodedSize = 1L + HeaderSize(flags.Length) + flags.Length +
            HeaderSize(vendorCount) + additionalEncodedBytes;
        CheckEncodedSize(encodedSize, maxEncodedBytes);
        var vendors = new string[vendorCount];
        for (int i = 0; i < vendors.Length; i++)
        {
            string vendor = vendorCapabilities[i]
                ?? throw new ArgumentException("Vendor capability names cannot be null.", nameof(vendorCapabilities));
            int utf8Length = StrictUtf8.GetByteCount(vendor);
            encodedSize += HeaderSize(utf8Length) + (long)utf8Length;
            CheckEncodedSize(encodedSize, maxEncodedBytes);
            vendors[i] = vendor;
        }

        return new Prepared(flags, vendors, (int)encodedSize);
    }

    public static void Write(CborWriter writer, Prepared fields)
    {
        writer.WriteByteString(fields.Flags);
        writer.WriteStartArray(fields.Vendors.Length);
        foreach (string vendor in fields.Vendors)
        {
            writer.WriteTextString(vendor);
        }

        writer.WriteEndArray();
    }

    private static bool HasReservedFlags(ReadOnlySpan<byte> flags) =>
        !flags.IsEmpty && (flags[0] & ReservedFirstByteMask) != 0;

    private static int HeaderSize(int value) => FdoCborCodec.GetHeaderSize((ulong)value);

    private static void CheckEncodedSize(long size, int maxEncodedBytes)
    {
        if (size > maxEncodedBytes)
        {
            throw new CborContentException("The message exceeds the encoded byte limit.");
        }
    }

    private static void RequireState(CborReader reader, CborReaderState expected)
    {
        if (reader.PeekState() != expected)
        {
            throw new CborContentException($"Expected CBOR {expected} in the capability fields.");
        }
    }

    public sealed record Parsed(ReadOnlyMemory<byte> Flags, IReadOnlyList<string> Vendors);

    public sealed record Prepared(byte[] Flags, string[] Vendors, int EncodedSize);
}
