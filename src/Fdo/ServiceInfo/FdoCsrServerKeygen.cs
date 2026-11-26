using System;
using System.Formats.Asn1;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fdo.Cryptography;

namespace Fdo.ServiceInfo;

/// <summary>Checks server-key request framing and the generated key/certificate binding.</summary>
[UnsupportedOSPlatform("browser")]
internal static class FdoCsrServerKeygen
{
    private static readonly Asn1Tag AttributesTag = new(TagClass.ContextSpecific, 0, true);

    public static void ValidateRequest(ReadOnlyMemory<byte> request)
    {
        try
        {
            var reader = new AsnReader(request, AsnEncodingRules.DER);
            AsnReader outer = reader.ReadSequence();
            AsnReader info = outer.ReadSequence();
            if (info.ReadInteger() != 0)
            {
                throw new CryptographicException("The server-key request must use PKCS#10 version 0.");
            }

            FdoDerEncoding.ValidateSubject(info.ReadSequence());
            AsnReader publicKey = info.ReadSequence();
            ReadAlgorithm(publicKey);
            _ = publicKey.ReadBitString(out _);
            publicKey.ThrowIfNotEmpty();
            ReadAttributes(info.ReadSetOf(AttributesTag));
            info.ThrowIfNotEmpty();

            ReadAlgorithm(outer);
            _ = outer.ReadBitString(out _);
            outer.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
        }
        catch (AsnContentException exception)
        {
            throw new CryptographicException("The server-key request is not a DER PKCS#10 value.", exception);
        }
    }

    public static void ValidateCredential(ReadOnlyMemory<byte> certificate, ReadOnlyMemory<byte> privateKeyPkcs8)
    {
        try
        {
            ValidatePrivateKeyInfo(privateKeyPkcs8);
            using X509Certificate2 parsedCertificate = FdoDerEncoding.LoadCertificate(certificate);
            byte[] generatedPublicKey;
            int bytesRead;
            switch (parsedCertificate.PublicKey.Oid.Value)
            {
                case "1.2.840.113549.1.1.1":
                    using (RSA rsa = RSA.Create())
                    {
                        rsa.ImportPkcs8PrivateKey(privateKeyPkcs8.Span, out bytesRead);
                        generatedPublicKey = rsa.ExportSubjectPublicKeyInfo();
                    }

                    break;
                case "1.2.840.10045.2.1":
                    using (ECDsa ecdsa = ECDsa.Create())
                    {
                        ecdsa.ImportPkcs8PrivateKey(privateKeyPkcs8.Span, out bytesRead);
                        generatedPublicKey = ecdsa.ExportSubjectPublicKeyInfo();
                    }

                    break;
                default:
                    throw new NotSupportedException("The paired server-key profile supports RSA and EC certificates.");
            }

            if (bytesRead != privateKeyPkcs8.Length ||
                !generatedPublicKey.AsSpan().SequenceEqual(parsedCertificate.PublicKey.ExportSubjectPublicKeyInfo()))
            {
                throw new CryptographicException("The generated private key does not match the issued certificate.");
            }
        }
        catch (AsnContentException exception)
        {
            throw new CryptographicException("The generated private key is not a DER PKCS#8 value.", exception);
        }
    }

    private static void ReadAlgorithm(AsnReader container)
    {
        AsnReader algorithm = container.ReadSequence();
        _ = algorithm.ReadObjectIdentifier();
        if (algorithm.HasData)
        {
            FdoDerEncoding.ValidateEncodedValue(algorithm.ReadEncodedValue(), validateUniversalValues: true);
        }

        algorithm.ThrowIfNotEmpty();
    }

    private static void ReadAttributes(AsnReader attributes)
    {
        while (attributes.HasData)
        {
            AsnReader attribute = attributes.ReadSequence();
            _ = attribute.ReadObjectIdentifier();
            AsnReader values = attribute.ReadSetOf();
            FdoDerEncoding.ValidateEncodedValues(values, validateUniversalValues: true);
            attribute.ThrowIfNotEmpty();
        }
    }

    private static void ValidatePrivateKeyInfo(ReadOnlyMemory<byte> encoded)
    {
        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        AsnReader info = reader.ReadSequence();
        if (info.ReadInteger() != 0)
        {
            throw new CryptographicException("The generated key must use PKCS#8 PrivateKeyInfo version 0.");
        }

        ReadAlgorithm(info);
        if (!info.TryReadPrimitiveOctetString(out _))
        {
            throw new CryptographicException("The generated private key must use a primitive DER octet string.");
        }

        if (info.HasData)
        {
            ReadAttributes(info.ReadSetOf(AttributesTag));
        }

        info.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();
    }
}
