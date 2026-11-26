// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Asn1;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Fdo.Enrollment;
using Fdo.ServiceInfo;

namespace Fdo.Tests.ServiceInfo;

[UnsupportedOSPlatform("browser")]
public sealed class FdoCsrReenrollmentTests
{
    [Test]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task ChangeSubjectNameAppliesRfc6402PresenceSemantics(bool hasSubject, bool hasNames)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Extension oldNames = DnsNames("old.example.invalid");
        X509Extension newNames = DnsNames("new.example.invalid");
        var oldSubject = new X500DistinguishedName("CN=old");
        var newSubject = new X500DistinguishedName("CN=new");
        var original = Request(oldSubject, key, oldNames);
        using X509Certificate2 prior = SelfSigned(original);
        byte[] encodedChange = Change(hasSubject ? newSubject.RawData : null, hasNames ? newNames.RawData : null);
        original.OtherRequestAttributes.Add(new AsnEncodedData("1.3.6.1.5.5.7.7.36", encodedChange));
        byte[] csr = original.CreateSigningRequest();
        var expectedSubject = new X500DistinguishedName(hasSubject ? newSubject.RawData : [0x30, 0x00]);
        var resultRequest = Request(expectedSubject, key, hasNames ? newNames : null);
        using X509Certificate2 issued = SelfSigned(resultRequest);

        FdoReenrollmentDetails details = FdoCsrReenrollment.CheckRequest(csr, prior.RawData);
        await Assert.That(details.Kind).IsEqualTo(FdoReenrollmentKind.Renewal);
        await Assert.That(details.IdentityChange!.EncodedValue.Span.SequenceEqual(encodedChange)).IsTrue();
        await Assert.That(details.IdentityChange.SubjectName.Span.SequenceEqual(expectedSubject.RawData)).IsTrue();
        await Assert.That(issued.SubjectName.RawData.AsSpan().SequenceEqual(expectedSubject.RawData)).IsTrue();
        if (hasNames)
        {
            await Assert.That(details.IdentityChange.SubjectAlternativeNames!.Value.Span
                .SequenceEqual(newNames.RawData)).IsTrue();
        }
        else
        {
            await Assert.That(details.IdentityChange.SubjectAlternativeNames).IsNull();
        }

        FdoCsrSimpleEnrollment.ValidateResponse(csr, issued.RawData);
        FdoCsrReenrollment.CheckResponse(details, issued.RawData);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    public async Task RejectsMalformedOrDuplicateChangeSubjectNameAttributes(int scenario)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = Request(new X500DistinguishedName("CN=prior"), key, null);
        using X509Certificate2 prior = SelfSigned(request);
        byte[] valid = Change(new X500DistinguishedName("CN=new").RawData, null);
        byte[] value = scenario switch
        {
            0 => [0x30, 0x00],
            1 => [0x30, 0x03, 0x02, 0x01, 0x00],
            2 => [0x30, 0x04, 0x30, 0x00, 0x30, 0x00],
            3 => [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00],
            4 => Change(new X500DistinguishedName("CN=new").RawData, new X500DistinguishedName("CN=wrong").RawData),
            _ => valid,
        };
        request.OtherRequestAttributes.Add(new AsnEncodedData("1.3.6.1.5.5.7.7.36", value));
        if (scenario == 5)
        {
            request.OtherRequestAttributes.Add(new AsnEncodedData("1.3.6.1.5.5.7.7.36", valid));
        }

        byte[] csr = request.CreateSigningRequest();

        await Assert.That(Throws<CryptographicException>(() =>
            FdoCsrReenrollment.CheckRequest(csr, prior.RawData))).IsTrue();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    [Arguments(9)]
    [Arguments(10)]
    public async Task RejectsMalformedConstructedGeneralNames(int scenario)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = Request(new X500DistinguishedName("CN=prior"), key, null);
        using X509Certificate2 prior = SelfSigned(request);
        byte[] names = scenario switch
        {
            0 => [0x30, 0x02, 0xA0, 0x00],
            1 => [0x30, 0x05, 0xA0, 0x03, 0x06, 0x01, 0x2A],
            2 => [0x30, 0x07, 0xA0, 0x05, 0x06, 0x01, 0x2A, 0xA0, 0x00],
            3 => [0x30, 0x0B, 0xA0, 0x09, 0x06, 0x01, 0x2A, 0xA0, 0x04, 0x30, 0x02, 0x04, 0x00],
            4 => [0x30, 0x02, 0xA4, 0x00],
            5 => [0x30, 0x05, 0xA4, 0x03, 0x02, 0x01, 0x00],
            6 => [0x30, 0x06, 0xA4, 0x04, 0x30, 0x02, 0x31, 0x00],
            7 => [0x30, 0x02, 0xA5, 0x00],
            8 => [0x30, 0x04, 0xA5, 0x02, 0xA1, 0x00],
            9 => [0x30, 0x07, 0xA5, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00],
            _ => [0x30, 0x02, 0xA3, 0x00],
        };
        request.OtherRequestAttributes.Add(new AsnEncodedData("1.3.6.1.5.5.7.7.36", Change(null, names)));
        byte[] csr = request.CreateSigningRequest();
        if (scenario == 3)
        {
            csr = CorruptNestedLengthAndResign(csr, names, key);
        }

        await Assert.That(Throws<CryptographicException>(() =>
            FdoCsrReenrollment.CheckRequest(csr, prior.RawData))).IsTrue();
    }

    [Test]
    public async Task PreservesConstructedGeneralNamesInTheApprovedIdentity()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var original = Request(new X500DistinguishedName("CN=prior"), key, null);
        using X509Certificate2 prior = SelfSigned(original);
        byte[] names = ConstructedNames();
        byte[] change = Change(null, names);
        original.OtherRequestAttributes.Add(new AsnEncodedData("1.3.6.1.5.5.7.7.36", change));
        byte[] csr = original.CreateSigningRequest();
        var issuedRequest = Request(new X500DistinguishedName([0x30, 0x00]), key,
            new X509Extension("2.5.29.17", names, false));
        using X509Certificate2 issued = SelfSigned(issuedRequest);

        FdoReenrollmentDetails details = FdoCsrReenrollment.CheckRequest(csr, prior.RawData);
        FdoCsrReenrollment.CheckResponse(details, issued.RawData);

        await Assert.That(details.IdentityChange!.SubjectAlternativeNames!.Value.Span.SequenceEqual(names)).IsTrue();
        await Assert.That(details.IdentityChange.EncodedValue.Span.SequenceEqual(change)).IsTrue();
    }

    [Test]
    public async Task RejectsDuplicateRequestedSubjectAlternativeNameExtensions()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Extension names = DnsNames("prior.example.invalid");
        var request = Request(new X500DistinguishedName("CN=prior"), key, names);
        using X509Certificate2 prior = SelfSigned(request);
        request.CertificateExtensions.Add(DnsNames("prior.example.invalid"));
        byte[] csr = request.CreateSigningRequest();

        await Assert.That(Throws<CryptographicException>(() =>
            FdoCsrReenrollment.CheckRequest(csr, prior.RawData))).IsTrue();
    }

    [Test]
    public async Task RejectsATamperedCsrSignatureBeforeComparingIdentity()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = Request(new X500DistinguishedName("CN=prior"), key, null);
        using X509Certificate2 prior = SelfSigned(request);
        byte[] csr = request.CreateSigningRequest();
        csr[^1] ^= 1;

        await Assert.That(Throws<CryptographicException>(() =>
            FdoCsrReenrollment.CheckRequest(csr, prior.RawData))).IsTrue();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task RejectsIssuedCertificatesThatChangeTheUnapprovedSan(int scenario)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var subject = new X500DistinguishedName("CN=prior");
        X509Extension? priorNames = scenario == 2 ? null : DnsNames("prior.example.invalid");
        X509Extension? issuedNames = scenario switch
        {
            0 => null,
            1 => DnsNames("different.example.invalid"),
            _ => DnsNames("unexpected.example.invalid"),
        };
        var priorRequest = Request(subject, key, priorNames);
        using X509Certificate2 prior = SelfSigned(priorRequest);
        byte[] csr = priorRequest.CreateSigningRequest();
        using X509Certificate2 issued = SelfSigned(Request(subject, key, issuedNames));
        FdoReenrollmentDetails details = FdoCsrReenrollment.CheckRequest(csr, prior.RawData);

        await Assert.That(Throws<CryptographicException>(() =>
            FdoCsrReenrollment.CheckResponse(details, issued.RawData))).IsTrue();
    }

    private static CertificateRequest Request(X500DistinguishedName subject, ECDsa key, X509Extension? names)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        if (names is not null)
        {
            request.CertificateExtensions.Add(names);
        }

        return request;
    }

    private static X509Extension DnsNames(string dns)
    {
        var builder = new SubjectAlternativeNameBuilder();
        builder.AddDnsName(dns);
        return builder.Build();
    }

    private static X509Certificate2 SelfSigned(CertificateRequest request) =>
        request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddHours(1));

    private static byte[] Change(byte[]? subject, byte[]? names)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        if (subject is not null)
        {
            writer.WriteEncodedValue(subject);
        }

        if (names is not null)
        {
            writer.WriteEncodedValue(names);
        }

        writer.PopSequence();
        return writer.Encode();
    }

    private static byte[] ConstructedNames()
    {
        var other = new Asn1Tag(TagClass.ContextSpecific, 0, true);
        var x400 = new Asn1Tag(TagClass.ContextSpecific, 3, true);
        var directory = new Asn1Tag(TagClass.ContextSpecific, 4, true);
        var edi = new Asn1Tag(TagClass.ContextSpecific, 5, true);
        var party = new Asn1Tag(TagClass.ContextSpecific, 1, true);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSequence(other);
        writer.WriteObjectIdentifier("1.2.3.4");
        writer.PushSequence(other);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, "device");
        writer.PopSequence(other);
        writer.PopSequence(other);
        writer.PushSequence(x400);
        writer.PushSequence();
        writer.PopSequence();
        writer.PopSequence(x400);
        writer.PushSequence(directory);
        writer.WriteEncodedValue(new X500DistinguishedName("CN=device").RawData);
        writer.PopSequence(directory);
        writer.PushSequence(edi);
        writer.PushSequence(party);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, "device");
        writer.PopSequence(party);
        writer.PopSequence(edi);
        writer.PopSequence();
        return writer.Encode();
    }

    private static byte[] CorruptNestedLengthAndResign(byte[] csr, byte[] names, ECDsa key)
    {
        var reader = new AsnReader(csr, AsnEncodingRules.DER);
        AsnReader outer = reader.ReadSequence();
        byte[] requestInfo = outer.ReadEncodedValue().ToArray();
        ReadOnlyMemory<byte> algorithm = outer.ReadEncodedValue();
        _ = outer.ReadBitString(out _);
        outer.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();
        int index = requestInfo.AsSpan().IndexOf(names);
        if (index < 0)
        {
            throw new InvalidOperationException("The generated CSR does not contain the expected names.");
        }

        requestInfo[index + names.Length - 1] = 0x80;
        byte[] signature = key.SignData(
            requestInfo, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteEncodedValue(requestInfo);
        writer.WriteEncodedValue(algorithm.Span);
        writer.WriteBitString(signature);
        writer.PopSequence();
        return writer.Encode();
    }

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }
}
