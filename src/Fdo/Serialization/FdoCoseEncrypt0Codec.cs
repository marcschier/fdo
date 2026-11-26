// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Fdo.Cryptography;

namespace Fdo.Serialization;

/// <summary>
/// Frames the provisional tagged COSE_Encrypt0 subset for AES-GCM and AES-CCM. This codec
/// does not establish a session or authenticate a peer. Callers must reserve
/// unique nonces across both directions, including after an encryption error,
/// and enforce replay checks, message state, and the negotiated size limit.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoCoseEncrypt0Codec
{
    private const CborTag Encrypt0Tag = (CborTag)16;
    private readonly FdoCborCodec _cbor;
    private readonly int _maxEncodedBytes;

    public FdoCoseEncrypt0Codec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _maxEncodedBytes = maxEncodedBytes;
    }

    /// <summary>
    /// Encrypts one encoded FDO CBOR value using the caller's reserved nonce.
    /// The complete Encrypt0 envelope is subject to the configured byte limit.
    /// </summary>
    public ReadOnlyMemory<byte> Encrypt(
        FdoCoseAeadAlgorithm algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlyMemory<byte> encodedPlaintext)
    {
        (_, int nonceLength, _) = FdoCoseAead.GetParameters(algorithm);
        if (nonce.Length != nonceLength)
        {
            throw new ArgumentException("The nonce length does not match the selected AEAD algorithm.", nameof(nonce));
        }

        byte[] protectedHeader = EncodeProtectedAlgorithm(algorithm);
        long ciphertextLength = (long)encodedPlaintext.Length + FdoCoseAead.TagSize;
        if (GetEncodedLength(algorithm, encodedPlaintext.Length) > _maxEncodedBytes)
        {
            throw new CborContentException("The COSE_Encrypt0 envelope exceeds the encoded byte limit.");
        }

        byte[] plaintext = encodedPlaintext.ToArray();
        try
        {
            _cbor.ValidateOwned(plaintext);
            byte[] iv = nonce.ToArray();
            byte[] associatedData = EncodeAssociatedData(protectedHeader);
            byte[] encrypted = new byte[(int)ciphertextLength];
            FdoCoseAead.Encrypt(
                algorithm, key, iv, plaintext,
                encrypted.AsSpan(0, plaintext.Length), encrypted.AsSpan(plaintext.Length), associatedData);

            var writer = new CborWriter(CborConformanceMode.Canonical);
            writer.WriteTag(Encrypt0Tag);
            writer.WriteStartArray(3);
            writer.WriteByteString(protectedHeader);
            writer.WriteStartMap(1);
            writer.WriteInt32(5);
            writer.WriteByteString(iv);
            writer.WriteEndMap();
            writer.WriteByteString(encrypted);
            writer.WriteEndArray();
            return _cbor.ValidateAndCopy(writer.Encode());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Returns the exact canonical envelope length that <see cref="Encrypt"/>
    /// produces for a plaintext of the given length.
    /// </summary>
    public static long GetEncodedLength(FdoCoseAeadAlgorithm algorithm, int plaintextLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(plaintextLength);
        (_, int nonceLength, _) = FdoCoseAead.GetParameters(algorithm);
        long ciphertextLength = (long)plaintextLength + FdoCoseAead.TagSize;
        int fixedEnvelopeLength = 6 + EncodeProtectedAlgorithm(algorithm).Length + nonceLength;
        return fixedEnvelopeLength + ByteStringHeaderLength(ciphertextLength) + ciphertextLength;
    }

    /// <summary>
    /// Verifies and decrypts one envelope, returning owned nonce and plaintext
    /// copies. The caller must enforce replay and protocol-state checks before
    /// acting on the plaintext and clear the plaintext buffer after use.
    /// </summary>
    public DecryptedMessage Decrypt(
        FdoCoseAeadAlgorithm expectedAlgorithm,
        ReadOnlySpan<byte> key,
        ReadOnlyMemory<byte> encoded)
    {
        (_, int nonceLength, _) = FdoCoseAead.GetParameters(expectedAlgorithm);
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        if (reader.PeekState() != CborReaderState.Tag || reader.ReadTag() != Encrypt0Tag)
        {
            throw new CborContentException("An FDO COSE_Encrypt0 requires tag 16.");
        }

        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != 3)
        {
            throw new CborContentException("An FDO COSE_Encrypt0 must contain three fields.");
        }

        ReadOnlyMemory<byte> protectedHeader = ReadByteString(reader, "protected header");
        if (!protectedHeader.Span.SequenceEqual(EncodeProtectedAlgorithm(expectedAlgorithm)))
        {
            throw new CborContentException("The COSE protected header must contain only the selected algorithm.");
        }

        if (reader.PeekState() != CborReaderState.StartMap || reader.ReadStartMap() != 1 ||
            reader.PeekState() != CborReaderState.UnsignedInteger || reader.ReadUInt64() != 5)
        {
            throw new CborContentException("The COSE unprotected header must contain only the IV.");
        }

        ReadOnlyMemory<byte> nonce = ReadByteString(reader, "IV");
        if (nonce.Length != nonceLength)
        {
            throw new CborContentException("The IV length does not match the selected AEAD algorithm.");
        }

        reader.ReadEndMap();
        ReadOnlyMemory<byte> encrypted = ReadByteString(reader, "ciphertext");
        if (encrypted.Length < FdoCoseAead.TagSize)
        {
            throw new CborContentException("The COSE ciphertext must include a 16-byte authentication tag.");
        }

        reader.ReadEndArray();
        int plaintextLength = encrypted.Length - FdoCoseAead.TagSize;
        byte[] plaintext = new byte[plaintextLength];
        bool completed = false;
        try
        {
            FdoCoseAead.Decrypt(
                expectedAlgorithm, key, nonce.Span, encrypted.Span[..plaintextLength],
                encrypted.Span[plaintextLength..], plaintext, EncodeAssociatedData(protectedHeader.Span));
            _cbor.ValidateOwned(plaintext);
            var result = new DecryptedMessage(nonce.ToArray(), plaintext);
            completed = true;
            return result;
        }
        finally
        {
            if (!completed)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private static byte[] EncodeProtectedAlgorithm(FdoCoseAeadAlgorithm algorithm)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteInt32((int)algorithm);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] EncodeAssociatedData(ReadOnlySpan<byte> protectedHeader)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteTextString("Encrypt0");
        writer.WriteByteString(protectedHeader);
        writer.WriteByteString(ReadOnlySpan<byte>.Empty);
        writer.WriteEndArray();
        return writer.Encode();
    }

    private static int ByteStringHeaderLength(long length) => length switch
    {
        <= 23 => 1,
        <= byte.MaxValue => 2,
        <= ushort.MaxValue => 3,
        _ => 5,
    };

    private static ReadOnlyMemory<byte> ReadByteString(CborReader reader, string field)
    {
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException($"The COSE {field} must be a byte string.");
        }

        return reader.ReadDefiniteLengthByteString();
    }

    public sealed record DecryptedMessage(byte[] Nonce, byte[] Plaintext);
}
