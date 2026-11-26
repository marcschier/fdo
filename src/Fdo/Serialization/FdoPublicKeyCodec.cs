// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fdo.Cryptography;

namespace Fdo.Serialization;

/// <summary>
/// Encodes FDO public keys using SubjectPublicKeyInfo or an ECDSA X5CHAIN.
/// </summary>
[UnsupportedOSPlatform("browser")]
public sealed class FdoPublicKeyCodec
{
    private const int X509Encoding = 1;
    private const int X5ChainEncoding = 2;
    internal const int Rsa2048Restricted = 1;
    internal const int RsaPkcs = 5;
    private const int Secp256R1 = 10;
    private const int Secp384R1 = 11;
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";
    private const string RsaEncryptionOid = "1.2.840.113549.1.1.1";
    private const string P256Oid = "1.2.840.10045.3.1.7";
    private const string P384Oid = "1.3.132.0.34";
    private readonly FdoCborCodec _cbor;

    /// <summary>Creates a codec for the supported EC and RSA key formats.</summary>
    public FdoPublicKeyCodec()
        : this(ushort.MaxValue, 32, ushort.MaxValue)
    {
    }

    internal FdoPublicKeyCodec(int maxEncodedBytes, int maxDepth, int maxItems)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
    }

    /// <summary>
    /// Returns an owned public key and the exact encoded FDO PublicKey bytes.
    /// The caller must dispose the returned key and establish its provenance.
    /// </summary>
    internal DecodedKey Decode(ReadOnlyMemory<byte> encoded)
    {
        ReadOnlyMemory<byte> copy = _cbor.ValidateAndCopy(encoded);
        var reader = new CborReader(copy, CborConformanceMode.Canonical);
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != 3)
        {
            throw new CborContentException("An FDO PublicKey must contain three fields.");
        }

        ulong keyType = ReadUnsigned(reader);
        if (keyType is not (Rsa2048Restricted or RsaPkcs or Secp256R1 or Secp384R1))
        {
            throw new NotSupportedException("The FDO public key type is not supported.");
        }
        ulong encoding = ReadUnsigned(reader);
        ReadOnlyMemory<byte> subjectPublicKeyInfo;
        if (encoding == X509Encoding)
        {
            if (reader.PeekState() != CborReaderState.ByteString)
            {
                throw new CborContentException("An X.509 FDO public key body must be a byte string.");
            }

            subjectPublicKeyInfo = reader.ReadDefiniteLengthByteString();
        }
        else if (encoding == X5ChainEncoding && keyType is (Secp256R1 or Secp384R1))
        {
            var chain = new FdoX5ChainCodec().Decode(reader.ReadEncodedValue());
            using X509Certificate2 leaf = FdoDerEncoding.LoadCertificate(chain[0]);
            RequireEndEntity(leaf);
            subjectPublicKeyInfo = leaf.PublicKey.ExportSubjectPublicKeyInfo();
            for (int i = 1; i < chain.Count; i++)
            {
                using X509Certificate2 attached = FdoDerEncoding.LoadCertificate(chain[i]);
            }
        }
        else
        {
            throw new NotSupportedException("The FDO public key encoding is not supported for this key type.");
        }

        reader.ReadEndArray();
        if (keyType is Rsa2048Restricted or RsaPkcs)
        {
            return DecodeRsa((int)keyType, copy, subjectPublicKeyInfo);
        }

        string curveOid = keyType == Secp256R1 ? P256Oid : P384Oid;
        FdoCoseSignatureAlgorithm algorithm = keyType == Secp256R1
            ? FdoCoseSignatureAlgorithm.ES256 : FdoCoseSignatureAlgorithm.ES384;
        RequireDerEcSubjectPublicKeyInfo(subjectPublicKeyInfo, curveOid);
        ECDsa key = ECDsa.Create();
        bool completed = false;
        try
        {
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo.Span, out int bytesRead);
            if (bytesRead != subjectPublicKeyInfo.Length)
            {
                throw new CryptographicException("The FDO public key has trailing SubjectPublicKeyInfo data.");
            }

            ECCurve curve = key.ExportParameters(false).Curve;
            if (!curve.IsNamed || !string.Equals(curve.Oid.Value, curveOid, StringComparison.Ordinal))
            {
                throw new CryptographicException("The FDO public key type does not match its named curve.");
            }

            var result = new DecodedKey((int)keyType, algorithm, copy, key);
            completed = true;
            return result;
        }
        finally
        {
            if (!completed)
            {
                key.Dispose();
            }
        }
    }

    /// <summary>Encodes the public portion of a P-256 or P-384 key as an FDO PublicKey.</summary>
    /// <remarks>
    /// This conversion does not establish trust. The host must authenticate
    /// the configured key independently of any received voucher.
    /// </remarks>
    /// <param name="key">The independently configured public or private ECDSA key.</param>
    /// <returns>The CBOR-encoded FDO PublicKey containing X.509 SubjectPublicKeyInfo.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    /// <exception cref="NotSupportedException">The key does not use a supported named curve.</exception>
    public ReadOnlyMemory<byte> Encode(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return EncodeKey(GetEcKeyType(key), key.ExportSubjectPublicKeyInfo());
    }

    /// <summary>Encodes a leaf-first DER certificate chain as an ECDSA FDO PublicKey.</summary>
    /// <remarks>
    /// The first certificate must contain a P-256 or P-384 end-entity key.
    /// The caller authorizes this key and any use of attached certificates.
    /// This conversion does not establish certificate trust or support a CA Owner.
    /// </remarks>
    public ReadOnlyMemory<byte> EncodeCertificateChain(IReadOnlyList<ReadOnlyMemory<byte>> certificates)
    {
        var chains = new FdoX5ChainCodec();
        ReadOnlyMemory<byte> body = chains.Encode(certificates);
        using X509Certificate2 leaf = FdoDerEncoding.LoadCertificate(chains.Decode(body)[0]);
        using ECDsa key = leaf.GetECDsaPublicKey()
            ?? throw new CryptographicException("An FDO X5CHAIN leaf must contain an ECDSA public key.");
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteInt32(GetEcKeyType(key));
        writer.WriteInt32(X5ChainEncoding);
        writer.WriteEncodedValue(body.Span);
        writer.WriteEndArray();
        ReadOnlyMemory<byte> encoded = _cbor.ValidateAndCopy(writer.Encode());
        using DecodedKey verified = Decode(encoded);
        return encoded;
    }

    private static void RequireEndEntity(X509Certificate2 leaf)
    {
        foreach (X509Extension extension in leaf.Extensions)
        {
            if (extension.Oid?.Value != "2.5.29.19")
            {
                continue;
            }

            var constraints = new X509BasicConstraintsExtension();
            constraints.CopyFrom(extension);
            if (constraints.CertificateAuthority)
            {
                throw new NotSupportedException("An FDO X5CHAIN CA Owner key is not supported.");
            }
        }
    }

    private static int GetEcKeyType(ECDsa key)
    {
        ECCurve curve = key.ExportParameters(false).Curve;
        return curve.IsNamed ? curve.Oid.Value switch
        {
            P256Oid => Secp256R1,
            P384Oid => Secp384R1,
            _ => throw new NotSupportedException("Only FDO ECDSA P-256 and P-384 public keys are supported."),
        } : throw new NotSupportedException("The FDO public key must use a supported named curve.");

    }

    /// <summary>Encodes an RSA public key as an FDO X.509 SubjectPublicKeyInfo.</summary>
    /// <param name="key">The independently configured public or private RSA key.</param>
    /// <param name="restricted">
    /// Selects RSA2048RESTR instead of RSAPKCS. The restricted form requires a
    /// 2048-bit modulus and public exponent 65537.
    /// </param>
    /// <returns>The CBOR-encoded FDO PublicKey.</returns>
    /// <remarks>This conversion does not establish trust in the key.</remarks>
    public ReadOnlyMemory<byte> EncodeRsa(RSA key, bool restricted = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        _ = RequireRsaParameters(key, restricted);
        return EncodeKey(restricted ? Rsa2048Restricted : RsaPkcs, key.ExportSubjectPublicKeyInfo());
    }

    internal ReadOnlyMemory<byte> EncodeOwnerKey(AsymmetricAlgorithm key, int? expectedKeyType = null) => key switch
    {
        ECDsa ecdsa => Encode(ecdsa),
        RSA rsa => EncodeRsa(rsa, expectedKeyType == Rsa2048Restricted),
        _ => throw new NotSupportedException("The Owner key must be a supported ECDSA or RSA key."),
    };

    private ReadOnlyMemory<byte> EncodeKey(int keyType, ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteInt32(keyType);
        writer.WriteInt32(X509Encoding);
        writer.WriteByteString(subjectPublicKeyInfo);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    private static DecodedKey DecodeRsa(
        int keyType, ReadOnlyMemory<byte> encoded, ReadOnlyMemory<byte> subjectPublicKeyInfo)
    {
        RequireDerRsaSubjectPublicKeyInfo(subjectPublicKeyInfo);
        RSA key = RSA.Create();
        bool completed = false;
        try
        {
            key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo.Span, out int bytesRead);
            if (bytesRead != subjectPublicKeyInfo.Length)
            {
                throw new CryptographicException("The FDO public key has trailing SubjectPublicKeyInfo data.");
            }

            FdoCoseSignatureAlgorithm algorithm = RequireRsaParameters(key, keyType == Rsa2048Restricted);
            var result = new DecodedKey(keyType, algorithm, encoded, key);
            completed = true;
            return result;
        }
        finally
        {
            if (!completed)
            {
                key.Dispose();
            }
        }
    }

    private static FdoCoseSignatureAlgorithm RequireRsaParameters(RSA key, bool restricted)
    {
        RSAParameters parameters = key.ExportParameters(false);
        byte[] modulus = parameters.Modulus
            ?? throw new CryptographicException("The FDO RSA key has no modulus.");
        byte[] exponent = parameters.Exponent
            ?? throw new CryptographicException("The FDO RSA key has no public exponent.");
        if (key.KeySize is not (2048 or 3072) ||
            modulus.Length != key.KeySize / 8 || (modulus[0] & 0x80) == 0 ||
            exponent.Length == 0 || (exponent[^1] & 1) == 0 ||
            (exponent.Length == 1 && exponent[0] < 3))
        {
            throw new CryptographicException("The FDO RSA key must have a 2048- or 3072-bit modulus and a valid public exponent.");
        }

        if (restricted && (key.KeySize != 2048 || !exponent.AsSpan().SequenceEqual(new byte[] { 1, 0, 1 })))
        {
            throw new CryptographicException("RSA2048RESTR requires a 2048-bit modulus and public exponent 65537.");
        }

        return key.KeySize == 2048 ? FdoCoseSignatureAlgorithm.RS256 : FdoCoseSignatureAlgorithm.RS384;
    }

    private static ulong ReadUnsigned(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("An FDO public key type and encoding must be unsigned integers.");
        }

        return reader.ReadUInt64();
    }

    private static void RequireDerEcSubjectPublicKeyInfo(ReadOnlyMemory<byte> encoded, string curveOid)
    {
        try
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            AsnReader algorithm = sequence.ReadSequence();
            string algorithmOid = algorithm.ReadObjectIdentifier();
            string namedCurveOid = algorithm.ReadObjectIdentifier();
            algorithm.ThrowIfNotEmpty();
            sequence.ReadBitString(out int unusedBits);
            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            if (algorithmOid != EcPublicKeyOid || namedCurveOid != curveOid || unusedBits != 0)
            {
                throw new CryptographicException("The FDO public key does not identify the required named EC curve.");
            }
        }
        catch (AsnContentException exception)
        {
            throw new CryptographicException("The FDO public key is not a DER SubjectPublicKeyInfo.", exception);
        }
    }

    private static void RequireDerRsaSubjectPublicKeyInfo(ReadOnlyMemory<byte> encoded)
    {
        try
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            AsnReader algorithm = sequence.ReadSequence();
            string algorithmOid = algorithm.ReadObjectIdentifier();
            algorithm.ReadNull();
            algorithm.ThrowIfNotEmpty();
            byte[] keyBits = sequence.ReadBitString(out int unusedBits);
            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            if (algorithmOid != RsaEncryptionOid || unusedBits != 0)
            {
                throw new CryptographicException("The FDO RSA key must identify rsaEncryption.");
            }

            var keyReader = new AsnReader(keyBits, AsnEncodingRules.DER);
            AsnReader rsaPublicKey = keyReader.ReadSequence();
            ReadOnlyMemory<byte> modulus = rsaPublicKey.ReadIntegerBytes();
            ReadOnlyMemory<byte> exponent = rsaPublicKey.ReadIntegerBytes();
            rsaPublicKey.ThrowIfNotEmpty();
            keyReader.ThrowIfNotEmpty();
            if ((modulus.Span[0] & 0x80) != 0 || (exponent.Span[0] & 0x80) != 0)
            {
                throw new CryptographicException("The FDO RSA modulus and exponent must be positive.");
            }
        }
        catch (AsnContentException exception)
        {
            throw new CryptographicException("The FDO public key is not a DER RSA SubjectPublicKeyInfo.", exception);
        }
    }

    internal sealed class DecodedKey : IDisposable
    {
        private readonly AsymmetricAlgorithm _key;

        internal DecodedKey(
            int keyType,
            FdoCoseSignatureAlgorithm algorithm,
            ReadOnlyMemory<byte> encoded,
            AsymmetricAlgorithm key)
        {
            KeyType = keyType;
            Algorithm = algorithm;
            Encoded = encoded;
            _key = key;
        }

        public int KeyType { get; }

        public FdoCoseSignatureAlgorithm Algorithm { get; }

        public ReadOnlyMemory<byte> Encoded { get; }

        internal RSA RsaPublicKey => _key as RSA
            ?? throw new CryptographicException("The FDO public key is not RSA.");

        public ReadOnlyMemory<byte> VerifySignature(
            FdoCoseSign1Codec codec,
            FdoSignatureOperation operation,
            ReadOnlyMemory<byte> encodedSignature)
        {
            ArgumentNullException.ThrowIfNull(codec);
            return codec.Verify(operation, Algorithm, _key, encodedSignature);
        }

        /// <summary>
        /// Verifies an X.509 signature made directly by this key. The signature
        /// algorithm must use the hash that FDO binds to the key type.
        /// </summary>
        internal bool VerifyCertificateSignature(
            ReadOnlySpan<byte> signedData, ReadOnlySpan<byte> signature, string signatureAlgorithmOid)
        {
            string expected = Algorithm switch
            {
                FdoCoseSignatureAlgorithm.ES256 => "1.2.840.10045.4.3.2",
                FdoCoseSignatureAlgorithm.ES384 => "1.2.840.10045.4.3.3",
                FdoCoseSignatureAlgorithm.RS256 => "1.2.840.113549.1.1.11",
                FdoCoseSignatureAlgorithm.RS384 => "1.2.840.113549.1.1.12",
                _ => string.Empty,
            };
            if (expected.Length == 0 || !string.Equals(expected, signatureAlgorithmOid, StringComparison.Ordinal))
            {
                return false;
            }

            HashAlgorithmName hash = Algorithm is FdoCoseSignatureAlgorithm.ES256 or FdoCoseSignatureAlgorithm.RS256
                ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384;
            return _key switch
            {
                ECDsa ecdsa => ecdsa.VerifyData(signedData, signature, hash, DSASignatureFormat.Rfc3279DerSequence),
                RSA rsa => rsa.VerifyData(signedData, signature, hash, RSASignaturePadding.Pkcs1),
                _ => false,
            };
        }

        /// <summary>Compares public key material, not encoded certificate or key bytes.</summary>
        public bool HasSamePublicKey(DecodedKey other)
        {
            ArgumentNullException.ThrowIfNull(other);
            if (KeyType != other.KeyType || Algorithm != other.Algorithm)
            {
                return false;
            }

            if (_key is RSA firstRsa && other._key is RSA secondRsa)
            {
                RSAParameters firstParameters = firstRsa.ExportParameters(false);
                RSAParameters secondParameters = secondRsa.ExportParameters(false);
                if (firstParameters.Modulus is null || firstParameters.Exponent is null ||
                    secondParameters.Modulus is null || secondParameters.Exponent is null)
                {
                    throw new CryptographicException("The FDO RSA public key is incomplete.");
                }

                return CryptographicOperations.FixedTimeEquals(firstParameters.Modulus, secondParameters.Modulus)
                    && CryptographicOperations.FixedTimeEquals(firstParameters.Exponent, secondParameters.Exponent);
            }

            if (_key is not ECDsa firstEc || other._key is not ECDsa secondEc)
            {
                return false;
            }

            ECPoint first = firstEc.ExportParameters(false).Q;
            ECPoint second = secondEc.ExportParameters(false).Q;
            if (first.X is null || first.Y is null || second.X is null || second.Y is null)
            {
                throw new CryptographicException("The FDO public key does not contain a complete EC point.");
            }

            return CryptographicOperations.FixedTimeEquals(first.X, second.X)
                && CryptographicOperations.FixedTimeEquals(first.Y, second.Y);
        }

        internal ReadOnlyMemory<byte> EncodeSubjectPublicKeyInfo() =>
            new FdoPublicKeyCodec().EncodeOwnerKey(_key, KeyType);

        public void Dispose() => _key.Dispose();
    }
}
