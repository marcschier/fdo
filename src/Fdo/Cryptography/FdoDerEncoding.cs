using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Fdo.Cryptography;

[UnsupportedOSPlatform("browser")]
internal static class FdoDerEncoding
{
    public static X509Certificate2 LoadCertificate(ReadOnlyMemory<byte> encoded)
    {
        RequireSingleSequence(encoded);
        X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(encoded.Span);
        if (!certificate.RawData.AsSpan().SequenceEqual(encoded.Span))
        {
            certificate.Dispose();
            throw new CryptographicException("The payload must contain exactly one DER certificate.");
        }

        return certificate;
    }

    public static void RequireSigningKeyUsage(X509Certificate2 certificate)
    {
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension.Oid?.Value != "2.5.29.15")
            {
                continue;
            }

            var usage = new X509KeyUsageExtension();
            usage.CopyFrom(extension);
            if ((usage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
            {
                throw new CryptographicException("The Device certificate does not permit digital signatures.");
            }
        }
    }

    public static void RequireSingleSequence(ReadOnlyMemory<byte> encoded)
    {
        try
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);
            _ = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
        }
        catch (AsnContentException exception)
        {
            throw new CryptographicException("The payload must contain exactly one DER sequence.", exception);
        }
    }

    public static void ValidateEncodedValue(ReadOnlyMemory<byte> encoded, bool validateUniversalValues = false) =>
        ValidateEncodedValues(new AsnReader(encoded, AsnEncodingRules.DER), validateUniversalValues);

    public static void ValidateSubject(AsnReader subject)
    {
        while (subject.HasData)
        {
            AsnReader rdn = subject.ReadSetOf();
            if (!rdn.HasData)
            {
                throw new CryptographicException("A relative distinguished name must contain an attribute.");
            }

            while (rdn.HasData)
            {
                AsnReader attribute = rdn.ReadSequence();
                _ = attribute.ReadObjectIdentifier();
                ValidateEncodedValue(attribute.ReadEncodedValue());
                attribute.ThrowIfNotEmpty();
            }
        }
    }

    public static void ValidateEncodedValues(AsnReader reader, bool validateUniversalValues = false)
    {
        var pending = new Stack<AsnReader>();
        pending.Push(reader);
        while (pending.Count != 0)
        {
            AsnReader current = pending.Peek();
            if (!current.HasData)
            {
                pending.Pop();
                continue;
            }

            Asn1Tag next = current.PeekTag();
            if (validateUniversalValues && next.TagClass == TagClass.Universal)
            {
                switch ((UniversalTagNumber)next.TagValue)
                {
                    case UniversalTagNumber.Boolean:
                        _ = current.ReadBoolean();
                        continue;
                    case UniversalTagNumber.Integer:
                        _ = current.ReadIntegerBytes();
                        continue;
                    case UniversalTagNumber.BitString:
                        _ = current.ReadBitString(out _);
                        continue;
                    case UniversalTagNumber.OctetString:
                        _ = current.ReadOctetString();
                        continue;
                    case UniversalTagNumber.Null:
                        current.ReadNull();
                        continue;
                    case UniversalTagNumber.ObjectIdentifier:
                        _ = current.ReadObjectIdentifier();
                        continue;
                    case UniversalTagNumber.Sequence:
                        pending.Push(current.ReadSequence());
                        continue;
                    case UniversalTagNumber.SetOf:
                        // The open value can be either SET or SET OF; its schema owns ordering.
                        pending.Push(current.ReadSetOf(skipSortOrderValidation: true));
                        continue;
                }
            }

            ReadOnlyMemory<byte> value = current.ReadEncodedValue();
            Asn1Tag tag = AsnDecoder.ReadEncodedValue(
                value.Span, AsnEncodingRules.DER, out int offset, out int length, out _);
            if (tag.IsConstructed)
            {
                pending.Push(new AsnReader(value.Slice(offset, length), AsnEncodingRules.DER));
            }
        }
    }
}
