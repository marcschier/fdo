using System;
using System.Formats.Cbor;
using System.Security.Cryptography;
using Fdo.Cryptography;

namespace Fdo.Serialization;

/// <summary>
/// Signs and verifies the subset of tagged COSE_Sign1 with an alg-only
/// protected header, an empty unprotected header, and an embedded CBOR payload.
/// A verified signature is not, by itself, peer or voucher authentication.
/// </summary>
internal sealed class FdoCoseSign1Codec
{
    private const CborTag Sign1Tag = (CborTag)18;
    private readonly FdoCborCodec _cbor;
    private readonly FdoCoseSignature _signature;

    public FdoCoseSign1Codec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _signature = new FdoCoseSignature(maxEncodedBytes);
    }

    /// <summary>
    /// Produces a tagged COSE_Sign1. The caller must enforce key-use policy
    /// and provide the payload and operation for the intended protocol state.
    /// </summary>
    public ReadOnlyMemory<byte> Sign(
        FdoSignatureOperation operation,
        FdoCoseSignatureAlgorithm algorithm,
        AsymmetricAlgorithm privateKey,
        ReadOnlyMemory<byte> encodedPayload)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ReadOnlyMemory<byte> payload = _cbor.ValidateEmbeddedValueAndCopy(encodedPayload);
        byte[] protectedHeader = EncodeProtectedAlgorithm(algorithm);
        byte[] signature = _signature.Sign(operation, algorithm, privateKey, protectedHeader, payload);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag(Sign1Tag);
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeader);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString(payload.Span);
        writer.WriteByteString(signature);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    /// <summary>
    /// Returns an owned copy of the exact signed payload after signature and
    /// embedded-CBOR checks. The caller must validate the key's trust and FDO
    /// type, the payload semantics, and the expected protocol state and nonce.
    /// EAT signatures requiring a non-empty MAROEPrefix are not supported.
    /// </summary>
    public ReadOnlyMemory<byte> Verify(
        FdoSignatureOperation expectedOperation,
        FdoCoseSignatureAlgorithm expectedAlgorithm,
        AsymmetricAlgorithm trustedPublicKey,
        ReadOnlyMemory<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(trustedPublicKey);
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        if (reader.PeekState() != CborReaderState.Tag || reader.ReadTag() != Sign1Tag)
        {
            throw new CborContentException("An FDO COSE_Sign1 requires tag 18.");
        }

        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != 4)
        {
            throw new CborContentException("An FDO COSE_Sign1 must contain four fields.");
        }

        ReadOnlyMemory<byte> protectedHeader = ReadByteString(reader, "protected header");
        if (reader.PeekState() != CborReaderState.StartMap)
        {
            throw new CborContentException("The COSE unprotected header must be a map.");
        }

        if (reader.ReadStartMap() != 0)
        {
            throw new NotSupportedException("Non-empty COSE unprotected headers are not supported.");
        }

        reader.ReadEndMap();
        ReadOnlyMemory<byte> payload = ReadByteString(reader, "payload");
        ReadOnlyMemory<byte> signature = ReadByteString(reader, "signature");
        reader.ReadEndArray();

        if (!_signature.TryVerify(
            expectedOperation, expectedAlgorithm, trustedPublicKey,
            protectedHeader, payload, signature, out ReadOnlyMemory<byte> verifiedPayload))
        {
            throw new CryptographicException("The COSE signature did not verify.");
        }

        return _cbor.ValidateEmbeddedValueAndCopy(verifiedPayload);
    }

    private static byte[] EncodeProtectedAlgorithm(FdoCoseSignatureAlgorithm algorithm)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteInt32((int)algorithm);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static ReadOnlyMemory<byte> ReadByteString(CborReader reader, string field)
    {
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException($"The COSE {field} must be a byte string.");
        }

        return reader.ReadDefiniteLengthByteString();
    }
}
