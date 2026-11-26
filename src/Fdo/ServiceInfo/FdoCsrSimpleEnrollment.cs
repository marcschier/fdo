// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fdo.Cryptography;

namespace Fdo.ServiceInfo;

/// <summary>
/// Checks simple-enrollment payloads independently of their ServiceInfo
/// encoding. A valid CSR proves possession of its key, not authorization.
/// A matching certificate still requires the caller's trust and policy checks.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal static class FdoCsrSimpleEnrollment
{
    public static void ValidateRequest(ReadOnlyMemory<byte> request)
    {
        _ = ReadRequest(request);
    }

    public static void ValidateResponse(ReadOnlyMemory<byte> request, ReadOnlyMemory<byte> certificate)
    {
        CertificateRequest parsedRequest = ReadRequest(request);
        using X509Certificate2 parsedCertificate = FdoDerEncoding.LoadCertificate(certificate);

        byte[] requestedKey = parsedRequest.PublicKey.ExportSubjectPublicKeyInfo();
        byte[] certificateKey = parsedCertificate.PublicKey.ExportSubjectPublicKeyInfo();
        if (!requestedKey.AsSpan().SequenceEqual(certificateKey))
        {
            throw new CryptographicException("The enrolled certificate public key does not match the request.");
        }
    }

    internal static CertificateRequest ReadRequest(ReadOnlyMemory<byte> request, bool includeExtensions = false)
    {
        FdoDerEncoding.RequireSingleSequence(request);
        CertificateRequest parsed = CertificateRequest.LoadSigningRequest(
            request.Span,
            HashAlgorithmName.SHA256,
            out int bytesConsumed,
            includeExtensions ? CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions :
                CertificateRequestLoadOptions.Default,
            RSASignaturePadding.Pkcs1);
        if (bytesConsumed != request.Length)
        {
            throw new CryptographicException("The request must contain exactly one DER PKCS#10 value.");
        }

        return parsed;
    }
}
