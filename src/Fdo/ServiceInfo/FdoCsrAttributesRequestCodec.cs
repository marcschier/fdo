// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.ServiceInfo;

internal static class FdoCsrAttributesRequestCodec
{
    public static Entry Encode() => new("fdo.csr:csrattrs-req", new byte[] { 0x00 });

    public static void Validate(Entry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (!string.Equals(entry.Key, "fdo.csr:csrattrs-req", StringComparison.Ordinal))
        {
            throw new ArgumentException("The ServiceInfo key does not identify a CSR attributes request.", nameof(entry));
        }

        var reader = new CborReader(entry.EncodedValue, CborConformanceMode.Strict);
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("A CSR attributes request must contain an unsigned integer.");
        }

        _ = reader.ReadUInt64();
        if (reader.BytesRemaining != 0)
        {
            throw new CborContentException("The CSR attributes request contains trailing CBOR data.");
        }
    }
}
