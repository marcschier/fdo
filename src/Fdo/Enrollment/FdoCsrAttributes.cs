// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Fdo.Cryptography;

namespace Fdo.Enrollment;

/// <summary>Detached RFC 8951 CSR attribute information.</summary>
/// <remarks>
/// The outer structure and DER framing are checked. Attribute values remain
/// opaque; the host interprets values it recognizes and ignores unknown
/// identifiers or attributes. These values do not authorize enrollment.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoCsrAttributes
{
    private readonly byte[] _encoded;

    /// <summary>Snapshots one DER CsrAttrs sequence, including an empty sequence.</summary>
    /// <param name="encoded">The encoded CBOR value to read or verify.</param>
    public FdoCsrAttributes(ReadOnlyMemory<byte> encoded)
    {
        if (encoded.IsEmpty || encoded.Length > ushort.MaxValue)
        {
            throw new CryptographicException("CSR attributes are empty or exceed the FDO message limit.");
        }

        _encoded = encoded.ToArray();
        try
        {
            var reader = new AsnReader(_encoded, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            var entries = new List<FdoCsrAttribute>();
            while (sequence.HasData)
            {
                Asn1Tag tag = sequence.PeekTag();
                if (tag.HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.ObjectIdentifier)))
                {
                    entries.Add(new FdoCsrAttribute(sequence.ReadObjectIdentifier(), false, []));
                }
                else if (tag.HasSameClassAndValue(Asn1Tag.Sequence))
                {
                    AsnReader attribute = sequence.ReadSequence();
                    string oid = attribute.ReadObjectIdentifier();
                    AsnReader values = attribute.ReadSetOf();
                    if (!values.HasData)
                    {
                        throw new CryptographicException("A CSR attribute must contain at least one value.");
                    }

                    var encodedValues = new List<ReadOnlyMemory<byte>>();
                    while (values.HasData)
                    {
                        ReadOnlyMemory<byte> value = values.ReadEncodedValue();
                        FdoDerEncoding.ValidateEncodedValue(value, validateUniversalValues: true);
                        encodedValues.Add(value);
                    }

                    attribute.ThrowIfNotEmpty();
                    entries.Add(new FdoCsrAttribute(oid, true, encodedValues));
                }
                else
                {
                    throw new CryptographicException("A CSR attribute entry must be an OID or an Attribute.");
                }
            }

            reader.ThrowIfNotEmpty();
            Entries = entries.AsReadOnly();
        }
        catch (AsnContentException exception)
        {
            throw new CryptographicException("The CSR attributes are not a supported DER CsrAttrs sequence.", exception);
        }
    }

    /// <summary>The exact DER CsrAttrs sequence, returned as a detached copy.</summary>
    public ReadOnlyMemory<byte> EncodedValue => (byte[])_encoded.Clone();

    /// <summary>The OID and Attribute choices in their original order.</summary>
    public IReadOnlyList<FdoCsrAttribute> Entries { get; }

    internal ReadOnlyMemory<byte> EncodedData => _encoded;
}

/// <summary>An OID or Attribute choice within a CSR attributes sequence.</summary>
public sealed class FdoCsrAttribute
{
    private readonly ReadOnlyMemory<byte>[] _values;

    internal FdoCsrAttribute(string objectIdentifier, bool isAttribute, IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        ObjectIdentifier = objectIdentifier;
        IsAttribute = isAttribute;
        _values = new ReadOnlyMemory<byte>[values.Count];
        for (int i = 0; i < values.Count; i++)
        {
            _values[i] = values[i].ToArray();
        }
    }

    /// <summary>The OID of this choice or the type OID of an Attribute.</summary>
    public string ObjectIdentifier { get; }

    /// <summary>True for an Attribute; false for a standalone OID.</summary>
    public bool IsAttribute { get; }

    /// <summary>Exact DER Attribute values as detached copies, or an empty list for an OID.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Values
    {
        get
        {
            var result = new ReadOnlyMemory<byte>[_values.Length];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = _values[i].ToArray();
            }

            return Array.AsReadOnly(result);
        }
    }
}
