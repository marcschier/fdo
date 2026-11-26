// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fdo.Cryptography;
using Fdo.Enrollment;

namespace Fdo.ServiceInfo;

/// <summary>Checks re-enrollment identity against the host-selected certificate.</summary>
[UnsupportedOSPlatform("browser")]
internal static class FdoCsrReenrollment
{
    private const string SubjectAlternativeNameOid = "2.5.29.17";
    private const string ChangeSubjectNameOid = "1.3.6.1.5.5.7.7.36";
    private static readonly byte[] EmptyName = [0x30, 0x00];

    public static FdoReenrollmentDetails CheckRequest(
        ReadOnlyMemory<byte> request,
        ReadOnlyMemory<byte> priorCertificate)
    {
        if (priorCertificate.IsEmpty || priorCertificate.Length > ushort.MaxValue)
        {
            throw new CryptographicException("The prior certificate is empty or exceeds the FDO message limit.");
        }

        byte[] priorSnapshot = priorCertificate.ToArray();
        using X509Certificate2 prior = FdoDerEncoding.LoadCertificate(priorSnapshot);
        CertificateRequest parsed = FdoCsrSimpleEnrollment.ReadRequest(request, includeExtensions: true);
        byte[]? priorNames = SubjectAlternativeNames(prior.Extensions.Cast<X509Extension>());
        byte[]? requestNames = SubjectAlternativeNames(parsed.CertificateExtensions);
        if (!parsed.SubjectName.RawData.AsSpan().SequenceEqual(prior.SubjectName.RawData) ||
            !SameOptionalBytes(requestNames, priorNames))
        {
            throw new CryptographicException("The re-enrollment CSR identity does not match the prior certificate.");
        }

        FdoReenrollmentKind kind = parsed.PublicKey.ExportSubjectPublicKeyInfo().AsSpan()
            .SequenceEqual(prior.PublicKey.ExportSubjectPublicKeyInfo())
                ? FdoReenrollmentKind.Renewal : FdoReenrollmentKind.Rekey;
        FdoReenrollmentIdentityChange? change = ReadIdentityChange(parsed.OtherRequestAttributes);
        return new FdoReenrollmentDetails(kind, priorSnapshot, change);
    }

    public static void CheckResponse(FdoReenrollmentDetails details, ReadOnlyMemory<byte> certificate)
    {
        ArgumentNullException.ThrowIfNull(details);
        using X509Certificate2 issued = FdoDerEncoding.LoadCertificate(certificate);
        using X509Certificate2 prior = FdoDerEncoding.LoadCertificate(details.PriorCertificate);
        FdoReenrollmentIdentityChange? change = details.IdentityChange;
        ReadOnlyMemory<byte> subject = change?.SubjectName ?? prior.SubjectName.RawData;
        byte[]? names = change is null
            ? SubjectAlternativeNames(prior.Extensions.Cast<X509Extension>())
            : change.SubjectAlternativeNames?.ToArray();
        if (!issued.SubjectName.RawData.AsSpan().SequenceEqual(subject.Span) ||
            !SameOptionalBytes(SubjectAlternativeNames(issued.Extensions.Cast<X509Extension>()), names))
        {
            throw new CryptographicException("The issued certificate identity does not match the approved re-enrollment.");
        }
    }

    private static byte[]? SubjectAlternativeNames(IEnumerable<X509Extension> extensions)
    {
        byte[]? value = null;
        foreach (X509Extension extension in extensions)
        {
            if (extension.Oid?.Value != SubjectAlternativeNameOid)
            {
                continue;
            }

            if (value is not null)
            {
                throw new CryptographicException("A certificate or CSR contains duplicate subject alternative names.");
            }

            value = (byte[])extension.RawData.Clone();
        }

        return value;
    }

    private static bool SameOptionalBytes(byte[]? first, byte[]? second) =>
        first is null ? second is null : second is not null && first.AsSpan().SequenceEqual(second);

    private static FdoReenrollmentIdentityChange? ReadIdentityChange(IEnumerable<AsnEncodedData> attributes)
    {
        byte[]? value = null;
        foreach (AsnEncodedData attribute in attributes)
        {
            if (attribute.Oid?.Value != ChangeSubjectNameOid)
            {
                continue;
            }

            if (value is not null)
            {
                throw new CryptographicException("The CSR contains more than one ChangeSubjectName value.");
            }

            value = (byte[])attribute.RawData.Clone();
        }

        if (value is null)
        {
            return null;
        }

        try
        {
            var reader = new AsnReader(value, AsnEncodingRules.DER);
            AsnReader change = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            if (!change.HasData)
            {
                throw new CryptographicException("ChangeSubjectName must contain a subject or subject alternative names.");
            }

            ReadOnlyMemory<byte> first = change.ReadEncodedValue();
            var firstReader = new AsnReader(first, AsnEncodingRules.DER);
            AsnReader contents = firstReader.ReadSequence();
            firstReader.ThrowIfNotEmpty();
            bool isSubject = !contents.HasData ||
                contents.PeekTag().HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.SetOf));
            byte[] subject = EmptyName;
            byte[]? names;
            if (isSubject)
            {
                FdoDerEncoding.ValidateSubject(contents);
                subject = first.ToArray();
                names = change.HasData ? ReadGeneralNames(change.ReadEncodedValue()) : null;
            }
            else
            {
                names = ReadGeneralNames(first);
            }

            change.ThrowIfNotEmpty();
            return new FdoReenrollmentIdentityChange(value, subject, names);
        }
        catch (AsnContentException exception)
        {
            throw new CryptographicException("ChangeSubjectName is not a supported DER value.", exception);
        }
    }

    private static byte[] ReadGeneralNames(ReadOnlyMemory<byte> encoded)
    {
        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        AsnReader names = reader.ReadSequence();
        reader.ThrowIfNotEmpty();
        if (!names.HasData)
        {
            throw new CryptographicException("Subject alternative names must not be empty.");
        }

        while (names.HasData)
        {
            Asn1Tag tag = names.PeekTag();
            if (tag.TagClass != TagClass.ContextSpecific || tag.TagValue is < 0 or > 8)
            {
                throw new CryptographicException("A subject alternative name has an unsupported tag.");
            }

            switch (tag.TagValue)
            {
                case 0:
                    ReadOtherName(names, tag);
                    break;
                case 1:
                case 2:
                case 6:
                    _ = names.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                    break;
                case 3:
                    ReadX400Address(names, tag);
                    break;
                case 4:
                    AsnReader directoryName = names.ReadSequence(tag);
                    FdoDerEncoding.ValidateSubject(directoryName.ReadSequence());
                    directoryName.ThrowIfNotEmpty();
                    break;
                case 5:
                    ReadEdiPartyName(names, tag);
                    break;
                case 7:
                    byte[] address = names.ReadOctetString(tag);
                    if (address.Length is not (4 or 16))
                    {
                        throw new CryptographicException("An IP subject alternative name has an invalid length.");
                    }

                    break;
                case 8:
                    _ = names.ReadObjectIdentifier(tag);
                    break;
            }
        }

        return encoded.ToArray();
    }

    private static void ReadOtherName(AsnReader names, Asn1Tag tag)
    {
        AsnReader otherName = names.ReadSequence(tag);
        _ = otherName.ReadObjectIdentifier();
        AsnReader value = otherName.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        FdoDerEncoding.ValidateEncodedValue(value.ReadEncodedValue());
        value.ThrowIfNotEmpty();
        otherName.ThrowIfNotEmpty();
    }

    private static void ReadX400Address(AsnReader names, Asn1Tag tag)
    {
        AsnReader address = names.ReadSequence(tag);
        FdoDerEncoding.ValidateEncodedValues(address.ReadSequence());
        if (address.HasData &&
            address.PeekTag().HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.Sequence)))
        {
            AsnReader domainAttributes = address.ReadSequence();
            if (!domainAttributes.HasData)
            {
                throw new CryptographicException("X.400 domain attributes must not be empty.");
            }

            FdoDerEncoding.ValidateEncodedValues(domainAttributes);
        }

        if (address.HasData)
        {
            AsnReader extensionAttributes = address.ReadSetOf();
            if (!extensionAttributes.HasData)
            {
                throw new CryptographicException("X.400 extension attributes must not be empty.");
            }

            FdoDerEncoding.ValidateEncodedValues(extensionAttributes);
        }

        address.ThrowIfNotEmpty();
    }

    private static void ReadEdiPartyName(AsnReader names, Asn1Tag tag)
    {
        AsnReader party = names.ReadSequence(tag);
        var assignerTag = new Asn1Tag(TagClass.ContextSpecific, 0);
        if (party.HasData && party.PeekTag().HasSameClassAndValue(assignerTag))
        {
            ReadDirectoryString(party, assignerTag);
        }

        ReadDirectoryString(party, new Asn1Tag(TagClass.ContextSpecific, 1));
        party.ThrowIfNotEmpty();
    }

    private static void ReadDirectoryString(AsnReader reader, Asn1Tag tag)
    {
        AsnReader wrapper = reader.ReadSequence(tag);
        Asn1Tag stringTag = wrapper.PeekTag();
        if (stringTag.TagClass != TagClass.Universal || stringTag.IsConstructed ||
            (UniversalTagNumber)stringTag.TagValue is not (
                UniversalTagNumber.UTF8String or UniversalTagNumber.PrintableString or
                UniversalTagNumber.TeletexString or UniversalTagNumber.UniversalString or
                UniversalTagNumber.BMPString))
        {
            throw new CryptographicException("An EDI party name must contain a DirectoryString.");
        }

        ReadOnlyMemory<byte> encoded = wrapper.ReadEncodedValue();
        _ = AsnDecoder.ReadEncodedValue(encoded.Span, AsnEncodingRules.DER, out _, out int length, out _);
        if (length == 0)
        {
            throw new CryptographicException("An EDI party name must not be empty.");
        }

        wrapper.ThrowIfNotEmpty();
    }

}
