using System;
using System.Formats.Cbor;
using System.Linq;
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
public sealed class FdoCsrBase64TextCodecTests
{
    [Test]
    public async Task CsrAttributesUseTheRfcExampleAndExactPlaintextLimit()
    {
        const string text =
            "MEEGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiMBYGCSqGSIb3DQEJDjEJ" +
            "BgcrBgEBAQEWBggqhkjOPQQDAw==";
        byte[] encoded = Convert.FromBase64String(text);
        var attributes = new FdoCsrAttributes(encoded);
        var unrestricted = new FdoCsrBase64TextCodec(4096);
        Entry entry = unrestricted.EncodeCsrAttributes(attributes);
        int length = new FdoTo2ServiceInfoCodec().EncodeOwner(false, false, [entry]).Length;
        var atLimit = new FdoCsrBase64TextCodec(length);
        var belowLimit = new FdoCsrBase64TextCodec(length - 1);

        await Assert.That(entry.Key).IsEqualTo("fdo.csr:csrattrs-res");
        await Assert.That(ReadText(entry.EncodedValue)).IsEqualTo(text);
        await Assert.That(atLimit.DecodeCsrAttributes(atLimit.EncodeCsrAttributes(attributes))
            .EncodedValue.Span.SequenceEqual(encoded)).IsTrue();
        await Assert.That(Throws<CborContentException>(() => belowLimit.EncodeCsrAttributes(attributes))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => belowLimit.DecodeCsrAttributes(entry))).IsTrue();
    }

    [Test]
    [Arguments("MAA")]
    [Arguments("MAA= ")]
    [Arguments("MAB=")]
    [Arguments("MAA=\n")]
    [Arguments("_w==")]
    public async Task CsrAttributesRejectNonCanonicalBase64(string text)
    {
        var codec = new FdoCsrBase64TextCodec(1024);
        Entry entry = TextEntry("fdo.csr:csrattrs-res", text);
        await Assert.That(Throws<FormatException>(() => codec.DecodeCsrAttributes(entry))).IsTrue();
    }

    [Test]
    public async Task CsrAttributesRejectWrongKeyNonTextTrailingCborAndMalformedDer()
    {
        var codec = new FdoCsrBase64TextCodec(1024);
        Entry wrongKey = TextEntry("fdo.csr:cacerts-res", "MAA=");
        Entry nonText = new("fdo.csr:csrattrs-res", new byte[] { 0x41, 0x00 });
        Entry trailing = new("fdo.csr:csrattrs-res", new byte[] { 0x60, 0x00 });
        Entry malformed = TextEntry("fdo.csr:csrattrs-res", Convert.ToBase64String(new byte[] { 0x30, 0x01, 0x00 }));

        await Assert.That(Throws<ArgumentException>(() => codec.DecodeCsrAttributes(wrongKey))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.DecodeCsrAttributes(nonText))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.DecodeCsrAttributes(trailing))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.DecodeCsrAttributes(malformed))).IsTrue();
    }

    [Test]
    public async Task CsrAttributesRequestAcceptsAnyUnsignedValueAndRejectsOtherShapes()
    {
        foreach (ulong value in new[] { 0UL, 42UL, ulong.MaxValue })
        {
            var writer = new CborWriter(CborConformanceMode.Canonical);
            writer.WriteUInt64(value);
            FdoCsrAttributesRequestCodec.Validate(new Entry("fdo.csr:csrattrs-req", writer.Encode()));
        }

        FdoCsrAttributesRequestCodec.Validate(FdoCsrAttributesRequestCodec.Encode());
        await Assert.That(Throws<ArgumentException>(() => FdoCsrAttributesRequestCodec.Validate(
            new Entry("fdo.csr:cacerts-req", new byte[] { 0x00 })))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => FdoCsrAttributesRequestCodec.Validate(
            new Entry("fdo.csr:csrattrs-req", new byte[] { 0x20 })))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => FdoCsrAttributesRequestCodec.Validate(
            new Entry("fdo.csr:csrattrs-req", new byte[] { 0x60 })))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => FdoCsrAttributesRequestCodec.Validate(
            new Entry("fdo.csr:csrattrs-req", new byte[] { 0x00, 0x00 })))).IsTrue();
    }

    [Test]
    public async Task SimpleEnrollmentRoundTripsSignedCsrAndMatchingCertificate()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=FDO test", key, HashAlgorithmName.SHA256);
        byte[] csr = request.CreateSigningRequest();
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] certificateDer = certificate.RawData;
        var codec = new FdoCsrBase64TextCodec(4096);

        Entry encodedRequest = codec.EncodeRequest(csr);
        Entry encodedResponse = codec.EncodeResponse(csr, certificateDer);
        byte[] decodedRequest = codec.DecodeRequest(encodedRequest);
        byte[] decodedResponse = codec.DecodeResponse(encodedResponse, decodedRequest);

        await Assert.That(encodedRequest.Key).IsEqualTo("fdo.csr:simpleenroll-req");
        await Assert.That(encodedResponse.Key).IsEqualTo("fdo.csr:simpleenroll-res");
        await Assert.That(ReadText(encodedRequest.EncodedValue)).IsEqualTo(Convert.ToBase64String(csr));
        await Assert.That(ReadText(encodedResponse.EncodedValue)).IsEqualTo(Convert.ToBase64String(certificateDer));
        await Assert.That(decodedRequest.SequenceEqual(csr)).IsTrue();
        await Assert.That(decodedResponse.SequenceEqual(certificateDer)).IsTrue();
    }

    [Test]
    public async Task ReenrollmentUsesDistinctKeysAndRejectsCrossOperationMessages()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=FDO test", key, HashAlgorithmName.SHA256);
        byte[] csr = request.CreateSigningRequest();
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var codec = new FdoCsrBase64TextCodec(4096);
        Entry reenrollmentRequest = codec.EncodeRequest(csr, isReenrollment: true);
        Entry reenrollmentResponse = codec.EncodeResponse(csr, certificate.RawData, isReenrollment: true);
        Entry enrollmentRequest = codec.EncodeRequest(csr);
        Entry enrollmentResponse = codec.EncodeResponse(csr, certificate.RawData);

        await Assert.That(reenrollmentRequest.Key).IsEqualTo("fdo.csr:simplereenroll-req");
        await Assert.That(reenrollmentResponse.Key).IsEqualTo("fdo.csr:simplereenroll-res");
        await Assert.That(codec.DecodeRequest(reenrollmentRequest, isReenrollment: true).SequenceEqual(csr)).IsTrue();
        await Assert.That(codec.DecodeResponse(reenrollmentResponse, csr, isReenrollment: true)
            .SequenceEqual(certificate.RawData)).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.DecodeRequest(reenrollmentRequest))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => codec.DecodeResponse(reenrollmentResponse, csr))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            codec.DecodeRequest(enrollmentRequest, isReenrollment: true))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            codec.DecodeResponse(enrollmentResponse, csr, isReenrollment: true))).IsTrue();
    }

    [Test]
    public async Task ReenrollmentPayloadsMustFitAtTheExactPlaintextLimit()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=FDO test", key, HashAlgorithmName.SHA256);
        byte[] csr = request.CreateSigningRequest();
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var codec = new FdoCsrBase64TextCodec(4096);
        Entry encodedRequest = codec.EncodeRequest(csr, isReenrollment: true);
        Entry encodedResponse = codec.EncodeResponse(csr, certificate.RawData, isReenrollment: true);
        var messages = new FdoTo2ServiceInfoCodec();
        int requestLength = messages.EncodeDevice(false, [encodedRequest]).Length;
        int responseLength = messages.EncodeOwner(false, true, [encodedResponse]).Length;
        var requestAtLimit = new FdoCsrBase64TextCodec(requestLength);
        var requestBelowLimit = new FdoCsrBase64TextCodec(requestLength - 1);
        var responseAtLimit = new FdoCsrBase64TextCodec(responseLength);
        var responseBelowLimit = new FdoCsrBase64TextCodec(responseLength - 1);

        await Assert.That(requestAtLimit.DecodeRequest(
            requestAtLimit.EncodeRequest(csr, true), true).SequenceEqual(csr)).IsTrue();
        await Assert.That(responseAtLimit.DecodeResponse(
            responseAtLimit.EncodeResponse(csr, certificate.RawData, true), csr, true)
            .SequenceEqual(certificate.RawData)).IsTrue();
        await Assert.That(Throws<CborContentException>(() => requestBelowLimit.EncodeRequest(csr, true))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => requestBelowLimit.DecodeRequest(encodedRequest, true))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            responseBelowLimit.EncodeResponse(csr, certificate.RawData, true))).IsTrue();
        await Assert.That(Throws<CborContentException>(() =>
            responseBelowLimit.DecodeResponse(encodedResponse, csr, true))).IsTrue();
    }

    [Test]
    public async Task RejectsInvalidCsrSignatureAndCertificateForADifferentKey()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=FDO test", key, HashAlgorithmName.SHA256);
        var otherRequest = new CertificateRequest("CN=other", otherKey, HashAlgorithmName.SHA256);
        byte[] csr = request.CreateSigningRequest();
        byte[] tamperedCsr = (byte[])csr.Clone();
        tamperedCsr[^1] ^= 1;
        using X509Certificate2 otherCertificate = otherRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var codec = new FdoCsrBase64TextCodec(4096);
        Entry tamperedEntry = TextEntry("fdo.csr:simpleenroll-req", Convert.ToBase64String(tamperedCsr));
        Entry wrongCertificate = TextEntry("fdo.csr:simpleenroll-res", Convert.ToBase64String(otherCertificate.RawData));

        await Assert.That(Throws<CryptographicException>(() => codec.EncodeRequest(tamperedCsr))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.DecodeRequest(tamperedEntry))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.EncodeResponse(csr, otherCertificate.RawData))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.DecodeResponse(wrongCertificate, csr))).IsTrue();
    }

    [Test]
    [Arguments("Zg")]
    [Arguments("Zg== ")]
    [Arguments("Zh==")]
    [Arguments("Zg==\n")]
    [Arguments("-----BEGIN CERTIFICATE REQUEST-----")]
    [Arguments("_w==")]
    public async Task RejectsNonCanonicalBase64WithoutFallback(string text)
    {
        var codec = new FdoCsrBase64TextCodec(1024);
        Entry entry = TextEntry("fdo.csr:simpleenroll-req", text);

        await Assert.That(Throws<FormatException>(() => codec.DecodeRequest(entry))).IsTrue();
    }

    [Test]
    public async Task RejectsWrongKeysNonTextValuesAndTrailingValues()
    {
        var codec = new FdoCsrBase64TextCodec(1024);
        Entry wrongKey = TextEntry("fdo.csr:serverkeygen-res", "MDA=");
        Entry nonText = new("fdo.csr:simpleenroll-req", new byte[] { 0x41, 0x00 });
        Entry trailing = new("fdo.csr:simpleenroll-req", new byte[] { 0x60, 0x00 });

        await Assert.That(Throws<ArgumentException>(() => codec.DecodeRequest(wrongKey))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.DecodeRequest(nonText))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => codec.DecodeRequest(trailing))).IsTrue();
    }

    [Test]
    public async Task RejectsTrailingDerAndNonCertificateResponses()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=FDO test", key, HashAlgorithmName.SHA256);
        byte[] csr = request.CreateSigningRequest();
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var codec = new FdoCsrBase64TextCodec(4096);
        byte[] trailingCsr = [.. csr, 0x00];
        byte[] trailingCertificate = [.. certificate.RawData, 0x00];

        await Assert.That(Throws<CryptographicException>(() => codec.EncodeRequest(trailingCsr))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.EncodeResponse(csr, trailingCertificate))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => codec.EncodeResponse(csr, csr))).IsTrue();
    }

    [Test]
    public async Task OneItemMustFitTheEntireTo2PlaintextAtTheExactBound()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=FDO test", key, HashAlgorithmName.SHA256);
        byte[] csr = request.CreateSigningRequest();
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var unrestricted = new FdoCsrBase64TextCodec(4096);
        Entry requestEntry = unrestricted.EncodeRequest(csr);
        Entry responseEntry = unrestricted.EncodeResponse(csr, certificate.RawData);
        var to2 = new FdoTo2ServiceInfoCodec();
        int requestLength = to2.EncodeDevice(false, [requestEntry]).Length;
        int responseLength = to2.EncodeOwner(false, false, [responseEntry]).Length;
        var requestAtLimit = new FdoCsrBase64TextCodec(requestLength);
        var requestBelowLimit = new FdoCsrBase64TextCodec(requestLength - 1);
        var responseAtLimit = new FdoCsrBase64TextCodec(responseLength);
        var responseBelowLimit = new FdoCsrBase64TextCodec(responseLength - 1);

        await Assert.That(requestAtLimit.DecodeRequest(requestAtLimit.EncodeRequest(csr)).SequenceEqual(csr)).IsTrue();
        await Assert.That(responseAtLimit.DecodeResponse(
            responseAtLimit.EncodeResponse(csr, certificate.RawData), csr).SequenceEqual(certificate.RawData)).IsTrue();
        await Assert.That(Throws<CborContentException>(() => requestBelowLimit.EncodeRequest(csr))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => requestBelowLimit.DecodeRequest(requestEntry))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => responseBelowLimit.EncodeResponse(csr, certificate.RawData))).IsTrue();
        await Assert.That(Throws<CborContentException>(() => responseBelowLimit.DecodeResponse(responseEntry, csr))).IsTrue();
    }

    private static Entry TextEntry(string key, string value)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString(value);
        return new Entry(key, writer.Encode());
    }

    private static string ReadText(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Canonical);
        return reader.ReadTextString();
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
