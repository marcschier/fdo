using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Fdo.Enrollment;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.ServiceInfo;

/// <summary>
/// Encodes and reads the supported DER certs-only CMS form. It does not
/// establish trust in the contained certificates or revocation lists.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal static class FdoCsrCaCertificatesCodec
{
    public const ulong CertsOnlyFormat = 281;
    private const string SignedDataOid = "1.2.840.113549.1.7.2";
    private const string DataOid = "1.2.840.113549.1.7.1";
    private static readonly Asn1Tag ExplicitContent = new(TagClass.ContextSpecific, 0, true);
    private static readonly Asn1Tag CertificatesTag = new(TagClass.ContextSpecific, 0, true);
    private static readonly Asn1Tag RevocationListsTag = new(TagClass.ContextSpecific, 1, true);

    public static Entry EncodeRequest()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteUInt64(CertsOnlyFormat);
        return new Entry("fdo.csr:cacerts-req", writer.Encode());
    }

    public static ulong DecodeRequest(Entry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (!string.Equals(entry.Key, "fdo.csr:cacerts-req", StringComparison.Ordinal))
        {
            throw new ArgumentException("The ServiceInfo key does not identify a CA request.", nameof(entry));
        }

        var reader = new CborReader(entry.EncodedValue, CborConformanceMode.Strict);
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("The CA certificate format must be an unsigned integer.");
        }

        ulong format = reader.ReadUInt64();
        if (reader.BytesRemaining != 0)
        {
            throw new CborContentException("The CA certificate request contains trailing CBOR data.");
        }

        return format;
    }

    public static byte[] Encode(FdoCaCertificates certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteObjectIdentifier(SignedDataOid);
        writer.PushSequence(ExplicitContent);
        writer.PushSequence();
        writer.WriteInteger(1);
        writer.PushSetOf();
        writer.PopSetOf();
        writer.PushSequence();
        writer.WriteObjectIdentifier(DataOid);
        writer.PopSequence();
        WriteValues(writer, CertificatesTag, certificates.CertificateData);
        WriteValues(writer, RevocationListsTag, certificates.CertificateRevocationListData);
        writer.PushSetOf();
        writer.PopSetOf();
        writer.PopSequence();
        writer.PopSequence(ExplicitContent);
        writer.PopSequence();
        return writer.Encode();
    }

    public static FdoCaCertificates Decode(ReadOnlyMemory<byte> encoded)
    {
        if (encoded.IsEmpty || encoded.Length > ushort.MaxValue)
        {
            throw new CryptographicException("The CA certificate container exceeds the FDO message limit or is empty.");
        }

        try
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);
            AsnReader contentInfo = reader.ReadSequence();
            if (contentInfo.ReadObjectIdentifier() != SignedDataOid)
            {
                throw new CryptographicException("The CA certificate container must contain CMS SignedData.");
            }

            AsnReader explicitContent = contentInfo.ReadSequence(ExplicitContent);
            AsnReader signedData = explicitContent.ReadSequence();
            if (signedData.ReadInteger() != 1)
            {
                throw new CryptographicException("The supported certs-only CMS form requires version 1.");
            }

            AsnReader algorithms = signedData.ReadSetOf();
            while (algorithms.HasData)
            {
                AsnReader algorithm = algorithms.ReadSequence();
                _ = algorithm.ReadObjectIdentifier();
                if (algorithm.HasData)
                {
                    _ = algorithm.ReadEncodedValue();
                }

                algorithm.ThrowIfNotEmpty();
            }

            AsnReader content = signedData.ReadSequence();
            if (content.ReadObjectIdentifier() != DataOid || content.HasData)
            {
                throw new CryptographicException("The certs-only CMS content must be absent and use id-data.");
            }

            List<ReadOnlyMemory<byte>> certificates = ReadValues(signedData, CertificatesTag);
            List<ReadOnlyMemory<byte>> crls = ReadValues(signedData, RevocationListsTag);
            AsnReader signers = signedData.ReadSetOf();
            if (signers.HasData)
            {
                throw new CryptographicException("The certs-only CMS container cannot contain signers.");
            }

            signedData.ThrowIfNotEmpty();
            explicitContent.ThrowIfNotEmpty();
            contentInfo.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            return new FdoCaCertificates(certificates, crls);
        }
        catch (AsnContentException exception)
        {
            throw new CryptographicException("The CA certificate container is not supported DER CMS.", exception);
        }
    }

    private static void WriteValues(
        AsnWriter writer, Asn1Tag tag, IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        if (values.Count == 0)
        {
            return;
        }

        writer.PushSetOf(tag);
        foreach (ReadOnlyMemory<byte> value in values)
        {
            writer.WriteEncodedValue(value.Span);
        }

        writer.PopSetOf(tag);
    }

    private static List<ReadOnlyMemory<byte>> ReadValues(AsnReader signedData, Asn1Tag tag)
    {
        var values = new List<ReadOnlyMemory<byte>>();
        if (!signedData.HasData || !signedData.PeekTag().HasSameClassAndValue(tag))
        {
            return values;
        }

        AsnReader set = signedData.ReadSetOf(tag);
        while (set.HasData)
        {
            if (!set.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            {
                throw new NotSupportedException("The CA container includes an unsupported certificate or revocation choice.");
            }

            values.Add(set.ReadEncodedValue());
        }

        return values;
    }
}
