// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Asn1;
using System.Formats.Cbor;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Enrollment;
using Fdo.Serialization;
using Fdo.ServiceInfo;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.Tests.ServiceInfo;

[UnsupportedOSPlatform("browser")]
public sealed class FdoCsrServerKeygenTests
{
    [Test]
    public async Task ServerKeyRequestIgnoresUnknownPublicKeyAndSignatureAlgorithms()
    {
        byte[] request = RequestWithIgnoredKeyAndSignature();
        var codec = new FdoCsrBase64TextCodec(4096);

        Entry entry = codec.EncodeRequest(request, isServerKeyGeneration: true);

        await Assert.That(entry.Key).IsEqualTo("fdo.csr:serverkeygen-req");
        await Assert.That(codec.DecodeRequest(entry, isServerKeyGeneration: true).SequenceEqual(request)).IsTrue();
        await Assert.That(Throws<NotSupportedException>(() => codec.EncodeRequest(request))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() =>
            codec.EncodeRequest(request, isReenrollment: true, isServerKeyGeneration: true))).IsTrue();
    }

    [Test]
    public async Task ServerKeyRequestRejectsMalformedDerEvenWhenSignatureIsIgnored()
    {
        byte[] request = RequestWithIgnoredKeyAndSignature();
        byte[] trailing = [.. request, 0x00];
        byte[] truncated = request[..^1];

        await Assert.That(Throws<CryptographicException>(() => FdoCsrServerKeygen.ValidateRequest(trailing))).IsTrue();
        await Assert.That(Throws<CryptographicException>(() => FdoCsrServerKeygen.ValidateRequest(truncated))).IsTrue();
    }

    [Test]
    public async Task ServerKeyRequestChecksSubjectAndAttributeStructure()
    {
        byte[] valid = RequestWithIgnoredKeyAndSignature(includeAttribute: true);
        byte[] invalidSubject = RequestWithIgnoredKeyAndSignature(invalidSubject: true);
        byte[] invalidAttribute = RequestWithIgnoredKeyAndSignature(invalidAttribute: true);

        await Assert.That(Throws<CryptographicException>(() => FdoCsrServerKeygen.ValidateRequest(valid))).IsFalse();
        await Assert.That(Throws<CryptographicException>(() => FdoCsrServerKeygen.ValidateRequest(invalidSubject)))
            .IsTrue();
        await Assert.That(Throws<CryptographicException>(() => FdoCsrServerKeygen.ValidateRequest(invalidAttribute)))
            .IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task MimeResponseRoundTripsMatchingKeyAndCertificateAtExactLimit(bool rsa)
    {
        using AsymmetricAlgorithm key = rsa ? RSA.Create(2048) : ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 certificate = SelfSigned(key);
        byte[] privateKey = key.ExportPkcs8PrivateKey();
        Entry? entry = null;
        byte[]? decodedKey = null;
        try
        {
            var codec = new FdoCsrServerKeygenCodec(8192);
            entry = codec.EncodeResponse(certificate.RawData, privateKey);
            (byte[] decodedCertificate, byte[] resultKey) = codec.DecodeResponse(entry);
            decodedKey = resultKey;
            ReadOnlyMemory<byte> message = new FdoTo2ServiceInfoCodec().EncodeOwner(false, true, [entry]);
            int limit = message.Length;
            FdoSecretBuffer.ClearOwned(message);

            var exact = new FdoCsrServerKeygenCodec(limit);
            var below = new FdoCsrServerKeygenCodec(limit - 1);
            Entry exactEntry = exact.EncodeResponse(certificate.RawData, privateKey);
            try
            {
                (byte[] exactCertificate, byte[] exactKey) = exact.DecodeResponse(exactEntry);
                try
                {
                    await Assert.That(exactCertificate.SequenceEqual(certificate.RawData)).IsTrue();
                    await Assert.That(exactKey.SequenceEqual(privateKey)).IsTrue();
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(exactKey);
                }
            }
            finally
            {
                FdoSecretBuffer.ClearOwned(exactEntry.EncodedValue);
            }

            await Assert.That(entry.Key).IsEqualTo("fdo.csr:serverkeygen-res");
            await Assert.That(HasExpectedMimeParts(entry)).IsTrue();
            await Assert.That(decodedCertificate.SequenceEqual(certificate.RawData)).IsTrue();
            await Assert.That(decodedKey.SequenceEqual(privateKey)).IsTrue();
            await Assert.That(Throws<CborContentException>(() => below.EncodeResponse(certificate.RawData, privateKey)))
                .IsTrue();
            await Assert.That(Throws<CborContentException>(() => below.DecodeResponse(entry))).IsTrue();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            if (decodedKey is not null)
            {
                CryptographicOperations.ZeroMemory(decodedKey);
            }

            if (entry is not null)
            {
                FdoSecretBuffer.ClearOwned(entry.EncodedValue);
            }
        }
    }

    [Test]
    public async Task RejectsMismatchedCredentialsOnBothSides()
    {
        using ECDsa first = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa second = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 firstCertificate = SelfSigned(first);
        using X509Certificate2 secondCertificate = SelfSigned(second);
        byte[] firstKey = first.ExportPkcs8PrivateKey();
        byte[] secondKey = second.ExportPkcs8PrivateKey();
        var codec = new FdoCsrServerKeygenCodec(8192);
        Entry? firstEntry = null;
        Entry? secondEntry = null;
        byte[]? forged = null;
        try
        {
            await Assert.That(Throws<CryptographicException>(() =>
                codec.EncodeResponse(firstCertificate.RawData, secondKey))).IsTrue();

            firstEntry = codec.EncodeResponse(firstCertificate.RawData, firstKey);
            secondEntry = codec.EncodeResponse(secondCertificate.RawData, secondKey);
            forged = firstEntry.EncodedValue.ToArray();
            (int firstStart, int firstLength) = PrivatePart(forged);
            (int secondStart, int secondLength) = PrivatePart(secondEntry.EncodedValue.Span);
            await Assert.That(firstLength).IsEqualTo(secondLength);
            secondEntry.EncodedValue.Span.Slice(secondStart, secondLength)
                .CopyTo(forged.AsSpan(firstStart, firstLength));

            var forgedEntry = new Entry("fdo.csr:serverkeygen-res", forged);
            await Assert.That(Throws<CryptographicException>(() => codec.DecodeResponse(forgedEntry))).IsTrue();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstKey);
            CryptographicOperations.ZeroMemory(secondKey);
            if (forged is not null)
            {
                CryptographicOperations.ZeroMemory(forged);
            }

            if (firstEntry is not null)
            {
                FdoSecretBuffer.ClearOwned(firstEntry.EncodedValue);
            }

            if (secondEntry is not null)
            {
                FdoSecretBuffer.ClearOwned(secondEntry.EncodedValue);
            }
        }
    }

    [Test]
    public async Task RejectsMalformedMimeAndNonCanonicalBase64()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 certificate = SelfSigned(key);
        byte[] privateKey = key.ExportPkcs8PrivateKey();
        var codec = new FdoCsrServerKeygenCodec(8192);
        Entry? entry = null;
        byte[]? badBoundary = null;
        byte[]? badBase64 = null;
        try
        {
            entry = codec.EncodeResponse(certificate.RawData, privateKey);
            badBoundary = entry.EncodedValue.ToArray();
            badBoundary[^3] = (byte)'x';
            badBase64 = entry.EncodedValue.ToArray();
            (int start, _) = PrivatePart(badBase64);
            badBase64[start] = (byte)' ';
            var invalidBoundary = new Entry(entry.Key, badBoundary);
            var invalidBase64 = new Entry(entry.Key, badBase64);
            var wrongKey = new Entry("fdo.csr:simpleenroll-res", entry.EncodedValue);

            await Assert.That(Throws<CborContentException>(() => codec.DecodeResponse(invalidBoundary))).IsTrue();
            await Assert.That(Throws<FormatException>(() => codec.DecodeResponse(invalidBase64))).IsTrue();
            await Assert.That(Throws<ArgumentException>(() => codec.DecodeResponse(wrongKey))).IsTrue();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            if (badBoundary is not null)
            {
                CryptographicOperations.ZeroMemory(badBoundary);
            }

            if (badBase64 is not null)
            {
                CryptographicOperations.ZeroMemory(badBase64);
            }

            if (entry is not null)
            {
                FdoSecretBuffer.ClearOwned(entry.EncodedValue);
            }
        }
    }

    [Test]
    public async Task CredentialDisposalClearsItsPrivateKeyCopy()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 certificate = SelfSigned(key);
        byte[] privateKey = key.ExportPkcs8PrivateKey();
        try
        {
            var credential = new FdoServerKeygenCredential(certificate.RawData, privateKey);
            ReadOnlyMemory<byte> ownedKey = credential.PrivateKey;
            credential.Dispose();

            await Assert.That(ownedKey.Span.IndexOfAnyExcept((byte)0)).IsEqualTo(-1);
            await Assert.That(Throws<ObjectDisposedException>(() => _ = credential.PrivateKey)).IsTrue();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }

    internal static byte[] RequestWithIgnoredKeyAndSignature(
        bool invalidSubject = false, bool invalidAttribute = false, bool includeAttribute = false)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        var attributes = new Asn1Tag(TagClass.ContextSpecific, 0, true);
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteInteger(0);
        if (invalidSubject)
        {
            writer.PushSequence();
            writer.WriteInteger(1);
            writer.PopSequence();
        }
        else
        {
            writer.WriteEncodedValue(new X500DistinguishedName("CN=server key request").RawData);
        }
        writer.PushSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.3.4");
        writer.PopSequence();
        writer.WriteBitString(new byte[] { 1, 2, 3 });
        writer.PopSequence();
        writer.PushSetOf(attributes);
        if (invalidAttribute)
        {
            writer.WriteInteger(1);
        }
        else if (includeAttribute)
        {
            writer.PushSequence();
            writer.WriteObjectIdentifier("1.2.3.6");
            writer.PushSetOf();
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, "value");
            writer.PopSetOf();
            writer.PopSequence();
        }

        writer.PopSetOf(attributes);
        writer.PopSequence();
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.2.3.5");
        writer.PopSequence();
        writer.WriteBitString(new byte[] { 4, 5, 6 });
        writer.PopSequence();
        return writer.Encode();
    }

    private static X509Certificate2 SelfSigned(AsymmetricAlgorithm key)
    {
        CertificateRequest request = key switch
        {
            ECDsa ecdsa => new CertificateRequest("CN=server-generated", ecdsa, HashAlgorithmName.SHA256),
            RSA rsa => new CertificateRequest(
                "CN=server-generated", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            _ => throw new ArgumentException("Unsupported test key.", nameof(key)),
        };
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static bool HasExpectedMimeParts(Entry entry)
    {
        var reader = new CborReader(entry.EncodedValue, CborConformanceMode.Strict);
        ReadOnlySpan<byte> text = reader.ReadDefiniteLengthTextStringBytes().Span;
        return text.StartsWith("--fdo\r\nContent-Type: application/pkcs8\r\n"u8) &&
            text.IndexOf("\r\n--fdo\r\nContent-Type: application/pkcs7-mime; smime-type=certs-only\r\n"u8) > 0 &&
            text.EndsWith("\r\n--fdo--\r\n"u8) && reader.BytesRemaining == 0;
    }

    private static (int Start, int Length) PrivatePart(ReadOnlySpan<byte> encoded)
    {
        ReadOnlySpan<byte> header = "Content-Transfer-Encoding: base64\r\n\r\n"u8;
        int start = encoded.IndexOf(header);
        if (start < 0)
        {
            throw new InvalidOperationException("The private-key MIME header is missing.");
        }

        start += header.Length;
        int length = encoded[start..].IndexOf("\r\n--fdo\r\n"u8);
        if (length <= 0)
        {
            throw new InvalidOperationException("The private-key MIME part is missing.");
        }

        return (start, length);
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
