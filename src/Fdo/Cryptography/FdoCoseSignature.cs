// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Security.Cryptography;
using Fdo.Serialization;

namespace Fdo.Cryptography;

internal enum FdoCoseSignatureAlgorithm
{
    RS384 = -258,
    RS256 = -257,
    ES384 = -35,
    ES256 = -7,
}

/// <summary>
/// Signs or verifies the exact protected-header and payload contents. The
/// caller supplies the operation, algorithm, and key. This does not parse a
/// COSE_Sign1 envelope or authenticate a protocol peer.
/// </summary>
internal sealed class FdoCoseSignature
{
    private const string P256Oid = "1.2.840.10045.3.1.7";
    private const string P384Oid = "1.3.132.0.34";
    private readonly FdoCborCodec _cbor;
    private readonly int _maxSignedBytes;

    public FdoCoseSignature(int maxSignedBytes = ushort.MaxValue)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxSignedBytes);
        _maxSignedBytes = maxSignedBytes;
        _cbor = new FdoCborCodec(maxEncodedBytes: maxSignedBytes);
    }

    /// <summary>
    /// Signs with a caller-owned private key. The caller must enforce key-use
    /// policy and construct the COSE envelope. EAT MAROEPrefix is not supported.
    /// </summary>
    public byte[] Sign(
        FdoSignatureOperation operation,
        FdoCoseSignatureAlgorithm algorithm,
        AsymmetricAlgorithm privateKey,
        ReadOnlyMemory<byte> protectedHeader,
        ReadOnlyMemory<byte> payload)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        int signatureLength = GetSignatureLength(algorithm);
        byte[] toBeSigned = PrepareSignedInput(
            operation, algorithm, protectedHeader, payload, signatureLength, out _);
        byte[] signature = algorithm switch
        {
            FdoCoseSignatureAlgorithm.ES256 => RequireEcdsaKey(privateKey, P256Oid)
                .SignData(toBeSigned, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            FdoCoseSignatureAlgorithm.ES384 => RequireEcdsaKey(privateKey, P384Oid)
                .SignData(toBeSigned, HashAlgorithmName.SHA384, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            FdoCoseSignatureAlgorithm.RS256 => RequireRsaKey(privateKey, 2048)
                .SignData(toBeSigned, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            FdoCoseSignatureAlgorithm.RS384 => RequireRsaKey(privateKey, 3072)
                .SignData(toBeSigned, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "The COSE signature algorithm is not supported."),
        };
        if (signature.Length != signatureLength)
        {
            throw new CryptographicException("The signing provider returned a signature of the wrong length.");
        }

        return signature;
    }

    /// <summary>
    /// On success, returns an owned copy of the exact payload that was verified.
    /// Only a protected header containing the alg parameter alone is supported.
    /// The caller must validate the envelope, unprotected headers, payload,
    /// key provenance, EAT prefix policy, and operation-specific protocol state.
    /// EAT MAROEPrefix is not supported; the caller must require it to be empty.
    /// </summary>
    public bool TryVerify(
        FdoSignatureOperation operation,
        FdoCoseSignatureAlgorithm expectedAlgorithm,
        AsymmetricAlgorithm publicKey,
        ReadOnlyMemory<byte> protectedHeader,
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signature,
        out ReadOnlyMemory<byte> verifiedPayload)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        verifiedPayload = default;
        byte[] toBeSigned = PrepareSignedInput(
            operation, expectedAlgorithm, protectedHeader, payload, signature.Length, out byte[] payloadCopy);

        bool valid = expectedAlgorithm switch
        {
            FdoCoseSignatureAlgorithm.ES256 => VerifyEcdsa(
                publicKey, P256Oid, 64, HashAlgorithmName.SHA256, toBeSigned, signature.Span),
            FdoCoseSignatureAlgorithm.ES384 => VerifyEcdsa(
                publicKey, P384Oid, 96, HashAlgorithmName.SHA384, toBeSigned, signature.Span),
            FdoCoseSignatureAlgorithm.RS256 => VerifyRsa(
                publicKey, 2048, HashAlgorithmName.SHA256, toBeSigned, signature.Span),
            FdoCoseSignatureAlgorithm.RS384 => VerifyRsa(
                publicKey, 3072, HashAlgorithmName.SHA384, toBeSigned, signature.Span),
            _ => throw new ArgumentOutOfRangeException(
                nameof(expectedAlgorithm), expectedAlgorithm, "The COSE signature algorithm is not supported."),
        };
        if (valid)
        {
            verifiedPayload = payloadCopy;
        }

        return valid;
    }

    private byte[] PrepareSignedInput(
        FdoSignatureOperation operation,
        FdoCoseSignatureAlgorithm algorithm,
        ReadOnlyMemory<byte> protectedHeader,
        ReadOnlyMemory<byte> payload,
        int signatureLength,
        out byte[] payloadCopy)
    {
        if ((long)protectedHeader.Length + payload.Length + signatureLength > _maxSignedBytes)
        {
            throw new CborContentException("The COSE signature components exceed the signed-byte limit.");
        }

        ReadOnlyMemory<byte> headerCopy = _cbor.ValidateAndCopy(protectedHeader);
        RequireProtectedAlgorithm(headerCopy, algorithm);
        payloadCopy = payload.ToArray();
        return FdoCoseSigningInput.CreateToBeSigned(operation, headerCopy.Span, payloadCopy);
    }

    private static int GetSignatureLength(FdoCoseSignatureAlgorithm algorithm) => algorithm switch
    {
        FdoCoseSignatureAlgorithm.ES256 => 64,
        FdoCoseSignatureAlgorithm.ES384 => 96,
        FdoCoseSignatureAlgorithm.RS256 => 256,
        FdoCoseSignatureAlgorithm.RS384 => 384,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "The COSE signature algorithm is not supported."),
    };

    private static void RequireProtectedAlgorithm(
        ReadOnlyMemory<byte> encoded, FdoCoseSignatureAlgorithm expectedAlgorithm)
    {
        if (expectedAlgorithm is not (FdoCoseSignatureAlgorithm.ES256 or FdoCoseSignatureAlgorithm.ES384
            or FdoCoseSignatureAlgorithm.RS256 or FdoCoseSignatureAlgorithm.RS384))
        {
            throw new ArgumentOutOfRangeException(
                nameof(expectedAlgorithm), expectedAlgorithm, "The COSE signature algorithm is not supported.");
        }

        var reader = new CborReader(encoded, CborConformanceMode.Canonical);
        if (reader.PeekState() != CborReaderState.StartMap || reader.ReadStartMap() != 1)
        {
            throw new CborContentException("Only a protected COSE header containing the alg parameter is supported.");
        }

        if (reader.PeekState() != CborReaderState.UnsignedInteger || reader.ReadUInt64() != 1
            || reader.PeekState() != CborReaderState.NegativeInteger
            || reader.ReadCborNegativeIntegerRepresentation() != (ulong)(-1 - (int)expectedAlgorithm))
        {
            throw new CborContentException("The protected COSE algorithm does not match the expected algorithm.");
        }

        reader.ReadEndMap();
    }

    private static bool VerifyEcdsa(
        AsymmetricAlgorithm publicKey,
        string curveOid,
        int signatureLength,
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> toBeSigned,
        ReadOnlySpan<byte> signature)
    {
        ECDsa ecdsa = RequireEcdsaKey(publicKey, curveOid);
        return signature.Length == signatureLength
            && ecdsa.VerifyData(toBeSigned, signature, hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private static ECDsa RequireEcdsaKey(AsymmetricAlgorithm key, string curveOid)
    {
        if (key is not ECDsa ecdsa)
        {
            throw new ArgumentException("The selected COSE algorithm requires an ECDSA key.", nameof(key));
        }

        ECCurve curve = ecdsa.ExportParameters(false).Curve;
        if (!curve.IsNamed || !string.Equals(curve.Oid?.Value, curveOid, StringComparison.Ordinal))
        {
            throw new ArgumentException("The ECDSA key does not use the required named curve.", nameof(key));
        }

        return ecdsa;
    }

    private static bool VerifyRsa(
        AsymmetricAlgorithm publicKey,
        int keySize,
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> toBeSigned,
        ReadOnlySpan<byte> signature)
    {
        RSA rsa = RequireRsaKey(publicKey, keySize);
        return signature.Length == keySize / 8
            && rsa.VerifyData(toBeSigned, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);
    }

    private static RSA RequireRsaKey(AsymmetricAlgorithm key, int keySize)
    {
        if (key is not RSA rsa || rsa.KeySize != keySize)
        {
            throw new ArgumentException("The RSA key does not have the size required by the COSE algorithm.", nameof(key));
        }

        return rsa;
    }
}
