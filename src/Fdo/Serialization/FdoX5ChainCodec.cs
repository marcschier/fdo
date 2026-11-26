// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;

namespace Fdo.Serialization;

/// <summary>
/// Reads and writes the COSE x5chain representation. Certificate bytes remain
/// opaque; this codec does not check certificate integrity, validity, or trust.
/// </summary>
internal sealed class FdoX5ChainCodec
{
    private readonly FdoCborCodec _cbor;
    private readonly int _maxEncodedBytes;
    private readonly int _maxItems;

    public FdoX5ChainCodec(int maxEncodedBytes = ushort.MaxValue, int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth: 2, maxItems: maxItems);
        _maxEncodedBytes = maxEncodedBytes;
        _maxItems = maxItems;
    }

    /// <summary>
    /// Returns certificate byte-string contents in wire order, backed by an
    /// owned copy of the input.
    /// </summary>
    /// <param name="encoded">The encoded CBOR value to read or verify.</param>
    /// <exception cref="CborContentException">
    /// An x5chain array must contain at least two certificates. An x5chain array must have a definite length.
    /// </exception>
    public IReadOnlyList<ReadOnlyMemory<byte>> Decode(ReadOnlyMemory<byte> encoded)
    {
        ReadOnlyMemory<byte> copy = _cbor.ValidateAndCopy(encoded);
        var reader = new CborReader(copy, CborConformanceMode.Canonical);

        if (reader.PeekState() == CborReaderState.ByteString)
        {
            return Array.AsReadOnly(new[] { reader.ReadDefiniteLengthByteString() });
        }

        RequireState(reader, CborReaderState.StartArray);
        int count = reader.ReadStartArray()
            ?? throw new CborContentException("An x5chain array must have a definite length.");
        if (count < 2)
        {
            throw new CborContentException("An x5chain array must contain at least two certificates.");
        }

        var certificates = new ReadOnlyMemory<byte>[count];
        for (int i = 0; i < certificates.Length; i++)
        {
            RequireState(reader, CborReaderState.ByteString);
            certificates[i] = reader.ReadDefiniteLengthByteString();
        }

        reader.ReadEndArray();
        return Array.AsReadOnly(certificates);
    }

    /// <summary>
    /// Writes one certificate as a byte string or multiple certificates as an
    /// array of byte strings, retaining their supplied order.
    /// </summary>
    /// <param name="certificates">The ordered certificates to process.</param>
    /// <exception cref="ArgumentException">An x5chain must contain at least one certificate.</exception>
    /// <exception cref="CborContentException">
    /// The x5chain exceeds the encoded byte limit. The x5chain exceeds the item or byte limit.
    /// </exception>
    public ReadOnlyMemory<byte> Encode(IReadOnlyList<ReadOnlyMemory<byte>> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        int count = certificates.Count;
        if (count <= 0)
        {
            throw new ArgumentException("An x5chain must contain at least one certificate.", nameof(certificates));
        }

        if (count > _maxEncodedBytes || (count == 1 ? 1L : 1L + count) > _maxItems)
        {
            throw new CborContentException("The x5chain exceeds the item or byte limit.");
        }

        long encodedSize = count == 1 ? 0 : FdoCborCodec.GetHeaderSize((ulong)count);
        var snapshot = new ReadOnlyMemory<byte>[count];
        for (int i = 0; i < snapshot.Length; i++)
        {
            ReadOnlyMemory<byte> certificate = certificates[i];
            encodedSize += FdoCborCodec.GetHeaderSize((ulong)certificate.Length) + (long)certificate.Length;
            if (encodedSize > _maxEncodedBytes)
            {
                throw new CborContentException("The x5chain exceeds the encoded byte limit.");
            }

            snapshot[i] = certificate.ToArray();
        }

        var writer = new CborWriter(CborConformanceMode.Canonical, initialCapacity: (int)encodedSize);
        if (count > 1)
        {
            writer.WriteStartArray(count);
        }

        foreach (ReadOnlyMemory<byte> certificate in snapshot)
        {
            writer.WriteByteString(certificate.Span);
        }

        if (count > 1)
        {
            writer.WriteEndArray();
        }

        return _cbor.ValidateAndCopy(writer.Encode());
    }

    private static void RequireState(CborReader reader, CborReaderState expected)
    {
        if (reader.PeekState() != expected)
        {
            throw new CborContentException($"Expected CBOR {expected} in x5chain.");
        }
    }
}
