// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Asn1;
using System.Formats.Cbor;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Fdo.Enrollment;
using Fdo.Serialization;
using Fdo.ServiceInfo;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.Tests.ServiceInfo;

[UnsupportedOSPlatform("browser")]
public sealed class FdoCsrCaCertificatesTests
{
    [Test]
    public async Task RoundTripsCertificatesAndCrlsAsDetachedExactDer()
    {
        using var fixture = new Fixture();
        byte[] sourceCertificate = (byte[])fixture.Certificate.Clone();
        byte[] sourceCrl = (byte[])fixture.Crl.Clone();
        var source = new FdoCaCertificates([sourceCertificate], [sourceCrl]);
        Array.Clear(sourceCertificate);
        Array.Clear(sourceCrl);

        byte[] encoded = FdoCsrCaCertificatesCodec.Encode(source);
        FdoCaCertificates decoded = FdoCsrCaCertificatesCodec.Decode(encoded);
        Array.Clear(encoded);
        ClearExposedMemory(decoded.Certificates[0]);
        ClearExposedMemory(decoded.CertificateRevocationLists[0]);

        await Assert.That(decoded.Certificates.Count).IsEqualTo(1);
        await Assert.That(decoded.CertificateRevocationLists.Count).IsEqualTo(1);
        await Assert.That(decoded.Certificates[0].Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(decoded.CertificateRevocationLists[0].Span.SequenceEqual(fixture.Crl)).IsTrue();
        await Assert.That(source.Certificates[0].Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(source.CertificateRevocationLists[0].Span.SequenceEqual(fixture.Crl)).IsTrue();
    }

    [Test]
    public async Task AcceptsCertsOnlyCmsWithAbsentEncapsulatedContent()
    {
        using var fixture = new Fixture();
        // RFC 8551 section 3.8 requires absent eContent, not an empty OCTET STRING.
        byte[] encoded = CreateContainer(fixture.Certificate);

        FdoCaCertificates decoded = FdoCsrCaCertificatesCodec.Decode(encoded);

        await Assert.That(decoded.Certificates.Count).IsEqualTo(1);
        await Assert.That(decoded.Certificates[0].Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(decoded.CertificateRevocationLists.Count).IsEqualTo(0);
    }

    [Test]
    public async Task PreservesEveryCertificateAndCrlInTheCmsSets()
    {
        using var first = new Fixture();
        using var second = new Fixture();
        var source = new FdoCaCertificates(
            [first.Certificate, second.Certificate], [first.Crl, second.Crl]);

        FdoCaCertificates decoded = FdoCsrCaCertificatesCodec.Decode(
            FdoCsrCaCertificatesCodec.Encode(source));

        await Assert.That(decoded.Certificates.Count).IsEqualTo(2);
        await Assert.That(decoded.CertificateRevocationLists.Count).IsEqualTo(2);
        await Assert.That(decoded.Certificates.Any(value => value.Span.SequenceEqual(first.Certificate))).IsTrue();
        await Assert.That(decoded.Certificates.Any(value => value.Span.SequenceEqual(second.Certificate))).IsTrue();
        await Assert.That(decoded.CertificateRevocationLists.Any(value => value.Span.SequenceEqual(first.Crl))).IsTrue();
        await Assert.That(decoded.CertificateRevocationLists.Any(value => value.Span.SequenceEqual(second.Crl))).IsTrue();
    }

    [Test]
    public async Task AcceptsCrlOnlyCmsIncludingAV1CrlWithoutANumber()
    {
        using var fixture = new Fixture();
        byte[] v1Crl = fixture.CreateV1Crl();
        var source = new FdoCaCertificates([], [v1Crl]);

        FdoCaCertificates decoded = FdoCsrCaCertificatesCodec.Decode(
            FdoCsrCaCertificatesCodec.Encode(source));

        _ = CertificateRevocationListBuilder.Load(decoded.CertificateRevocationLists[0].Span, out BigInteger number, out int consumed);
        await Assert.That(number).IsEqualTo(BigInteger.Zero);
        await Assert.That(consumed).IsEqualTo(v1Crl.Length);
        await Assert.That(decoded.Certificates.Count).IsEqualTo(0);
        await Assert.That(decoded.CertificateRevocationLists[0].Span.SequenceEqual(v1Crl)).IsTrue();
    }

    [Test]
    public async Task PreservesAnUnauthenticatedCrlForHostPolicy()
    {
        using var fixture = new Fixture();
        byte[] changed = (byte[])fixture.Crl.Clone();
        changed[^1] ^= 1;
        var source = new FdoCaCertificates([], [changed]);

        FdoCaCertificates decoded = FdoCsrCaCertificatesCodec.Decode(
            FdoCsrCaCertificatesCodec.Encode(source));

        await Assert.That(decoded.CertificateRevocationLists[0].Span.SequenceEqual(changed)).IsTrue();
    }

    [Test]
    public async Task AcceptsUnusedDigestAlgorithmsInCertsOnlyCms()
    {
        using var fixture = new Fixture();
        byte[] encoded = CreateContainer(fixture.Certificate, digestAlgorithm: true);

        FdoCaCertificates decoded = FdoCsrCaCertificatesCodec.Decode(encoded);

        await Assert.That(decoded.Certificates[0].Span.SequenceEqual(fixture.Certificate)).IsTrue();
    }

    [Test]
    [Arguments("wrong-outer-oid")]
    [Arguments("wrong-version")]
    [Arguments("wrong-content-oid")]
    [Arguments("content")]
    [Arguments("empty-content")]
    [Arguments("signer")]
    [Arguments("extra-field")]
    [Arguments("trailing")]
    public async Task RejectsInvalidOrNonCertsOnlyCms(string mutation)
    {
        using var fixture = new Fixture();
        byte[] encoded = CreateContainer(
            fixture.Certificate,
            outerOid: mutation == "wrong-outer-oid" ? "1.2.840.113549.1.7.1" : "1.2.840.113549.1.7.2",
            version: mutation == "wrong-version" ? 3 : 1,
            contentOid: mutation == "wrong-content-oid" ? "1.2.840.113549.1.7.2" : "1.2.840.113549.1.7.1",
            content: mutation switch
            {
                "content" => [0],
                "empty-content" => [],
                _ => null,
            },
            signer: mutation == "signer",
            extraField: mutation == "extra-field");
        if (mutation == "trailing")
        {
            encoded = [.. encoded, 0];
        }

        await Assert.That(Throws<CryptographicException>(() => FdoCsrCaCertificatesCodec.Decode(encoded))).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RejectsUnsupportedCertificateAndRevocationChoices(bool revocationChoice)
    {
        using var fixture = new Fixture();
        byte[] encoded = CreateContainer(
            fixture.Certificate, otherCertificate: !revocationChoice, otherRevocation: revocationChoice);

        await Assert.That(Throws<NotSupportedException>(() => FdoCsrCaCertificatesCodec.Decode(encoded))).IsTrue();
    }

    [Test]
    public async Task RejectsEmptyOversizedAndMalformedDerObjects()
    {
        using var fixture = new Fixture();
        byte[] trailingCrl = [.. fixture.Crl, 0];
        byte[] malformedCertificate = [0x30, 0x00];
        byte[] malformedCrl = [0x30, 0x00];

        await Assert.That(Throws<ArgumentException>(() => _ = new FdoCaCertificates([]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            _ = new FdoCaCertificates([new byte[ushort.MaxValue + 1]]))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            _ = new FdoCaCertificates([malformedCertificate]))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => _ = new FdoCaCertificates([], [malformedCrl]))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => _ = new FdoCaCertificates([], [trailingCrl]))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() =>
            FdoCsrCaCertificatesCodec.Decode(new byte[ushort.MaxValue + 1]))).IsTrue();
    }

    [Test]
    public async Task RequestUsesUint281AndRejectsWrongOrTrailingCbor()
    {
        Entry request = FdoCsrCaCertificatesCodec.EncodeRequest();

        await Assert.That(Convert.ToHexString(request.EncodedValue.Span)).IsEqualTo("190119");
        await Assert.That(FdoCsrCaCertificatesCodec.DecodeRequest(request)).IsEqualTo(281UL);
        await Assert.That(Throws<ArgumentException>(() => FdoCsrCaCertificatesCodec.DecodeRequest(
            new Entry("fdo.csr:other", request.EncodedValue)))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => FdoCsrCaCertificatesCodec.DecodeRequest(
            new Entry("fdo.csr:cacerts-req", new byte[] { 0x20 })))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => FdoCsrCaCertificatesCodec.DecodeRequest(
            new Entry("fdo.csr:cacerts-req", new byte[] { 0x01, 0x00 })))).IsTrue();
    }

    [Test]
    [Arguments("Zg")]
    [Arguments("Zg== ")]
    [Arguments("Zh==")]
    [Arguments("_w==")]
    public async Task RejectsNonCanonicalCaResponseBase64(string text)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString(text);
        var entry = new Entry("fdo.csr:cacerts-res", writer.Encode());

        await Assert.That(Throws<FormatException>(() =>
            new FdoCsrBase64TextCodec(1024).DecodeCaCertificates(entry))).IsTrue();
    }

    [Test]
    public async Task RejectsInvalidCaResponseValueAndMalformedCms()
    {
        var codec = new FdoCsrBase64TextCodec(1024);
        var malformed = new Entry("fdo.csr:cacerts-res", new byte[] { 0x64, 0x41, 0x41, 0x3D, 0x3D });
        var nonText = new Entry("fdo.csr:cacerts-res", new byte[] { 0x41, 0x00 });
        var trailing = new Entry("fdo.csr:cacerts-res", new byte[] { 0x60, 0x00 });
        var wrongKey = new Entry("fdo.csr:simpleenroll-res", new byte[] { 0x60 });

        await Assert.That(Throws<CryptographicException>(() => codec.DecodeCaCertificates(malformed))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.DecodeCaCertificates(nonText))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.DecodeCaCertificates(trailing))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.DecodeCaCertificates(wrongKey))).IsTrue();
    }

    [Test]
    public async Task CaResponseMustFitTheNegotiatedPlaintextAtTheExactBound()
    {
        using var fixture = new Fixture();
        var material = new FdoCaCertificates([fixture.Certificate], [fixture.Crl]);
        var unrestricted = new FdoCsrBase64TextCodec(ushort.MaxValue);
        Entry entry = unrestricted.EncodeCaCertificates(material);
        int exact = new FdoTo2ServiceInfoCodec().EncodeOwner(false, false, [entry]).Length;
        var atLimit = new FdoCsrBase64TextCodec(exact);
        var belowLimit = new FdoCsrBase64TextCodec(exact - 1);

        FdoCaCertificates decoded = atLimit.DecodeCaCertificates(atLimit.EncodeCaCertificates(material));

        await Assert.That(decoded.Certificates[0].Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(decoded.CertificateRevocationLists[0].Span.SequenceEqual(fixture.Crl)).IsTrue();
        await Assert.That(Throws<CborContentException>(() => belowLimit.EncodeCaCertificates(material))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => belowLimit.DecodeCaCertificates(entry))).IsTrue();
    }

    private static byte[] CreateContainer(
        byte[] certificate,
        string outerOid = "1.2.840.113549.1.7.2",
        int version = 1,
        string contentOid = "1.2.840.113549.1.7.1",
        byte[]? content = null,
        bool signer = false,
        bool extraField = false,
        bool digestAlgorithm = false,
        bool otherCertificate = false,
        bool otherRevocation = false)
    {
        var explicitTag = new Asn1Tag(TagClass.ContextSpecific, 0, true);
        var crlsTag = new Asn1Tag(TagClass.ContextSpecific, 1, true);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.WriteObjectIdentifier(outerOid);
        writer.PushSequence(explicitTag);
        writer.PushSequence();
        writer.WriteInteger(version);
        writer.PushSetOf();
        if (digestAlgorithm)
        {
            writer.PushSequence();
            writer.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1");
            writer.WriteNull();
            writer.PopSequence();
        }

        writer.PopSetOf();
        writer.PushSequence();
        writer.WriteObjectIdentifier(contentOid);
        if (content is not null)
        {
            writer.PushSequence(explicitTag);
            writer.WriteOctetString(content);
            writer.PopSequence(explicitTag);
        }

        writer.PopSequence();
        writer.PushSetOf(explicitTag);
        if (otherCertificate)
        {
            writer.PushSequence(crlsTag);
            writer.PopSequence(crlsTag);
        }
        else
        {
            writer.WriteEncodedValue(certificate);
        }

        writer.PopSetOf(explicitTag);
        if (otherRevocation)
        {
            writer.PushSetOf(crlsTag);
            writer.PushSequence(explicitTag);
            writer.PopSequence(explicitTag);
            writer.PopSetOf(crlsTag);
        }

        writer.PushSetOf();
        if (signer)
        {
            writer.WriteInteger(1);
        }

        writer.PopSetOf();
        if (extraField)
        {
            writer.WriteNull();
        }

        writer.PopSequence();
        writer.PopSequence(explicitTag);
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

    private static void ClearExposedMemory(ReadOnlyMemory<byte> value)
    {
        if (!MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment) || segment.Array is null)
        {
            throw new InvalidOperationException("The test expected array-backed memory.");
        }

        Array.Clear(segment.Array, segment.Offset, segment.Count);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public Fixture()
        {
            var request = new CertificateRequest("CN=FDO CA", _key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            using X509Certificate2 ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
            Certificate = ca.RawData;
            var builder = new CertificateRevocationListBuilder();
            Crl = builder.Build(ca, BigInteger.One, DateTimeOffset.UtcNow.AddHours(1), HashAlgorithmName.SHA256);
        }

        public byte[] Certificate { get; }
        public byte[] Crl { get; }

        public byte[] CreateV1Crl()
        {
            var outer = new AsnReader(Crl, AsnEncodingRules.DER).ReadSequence();
            AsnReader tbs = outer.ReadSequence();
            _ = tbs.ReadInteger();
            var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
            tbsWriter.PushSequence();
            while (tbs.HasData && tbs.PeekTag().TagClass != TagClass.ContextSpecific)
            {
                tbsWriter.WriteEncodedValue(tbs.ReadEncodedValue().Span);
            }

            tbsWriter.PopSequence();
            byte[] encodedTbs = tbsWriter.Encode();
            byte[] signature = _key.SignData(
                encodedTbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteEncodedValue(encodedTbs);
            writer.WriteEncodedValue(outer.ReadEncodedValue().Span);
            writer.WriteBitString(signature);
            writer.PopSequence();
            return writer.Encode();
        }

        public void Dispose()
        {
            _key.Dispose();
        }
    }
}
