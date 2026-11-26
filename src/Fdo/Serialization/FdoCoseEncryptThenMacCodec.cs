// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Fdo.Cryptography;

namespace Fdo.Serialization;

/// <summary>
/// Frames the paired encrypt-then-MAC TO2 profile. The outer value is a tagged
/// COSE_Mac0 (tag 17) whose protected header holds only the FDO MacType and
/// whose payload is the exact bytes of a tagged COSE_Encrypt0 (tag 16). The
/// inner protected header holds only the FDO cipher suite identifier, and the
/// inner unprotected header holds only the 16-byte AES IV. The receiver verifies
/// the MAC over the received payload bytes before it parses or decrypts the
/// inner value. This codec does not reserve IVs or counters, enforce message
/// order, or authenticate a peer.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoCoseEncryptThenMacCodec
{
    public const int CounterBlockSize = 16;
    private const CborTag Mac0Tag = (CborTag)17;
    private const CborTag Encrypt0Tag = (CborTag)16;
    private readonly FdoCborCodec _cbor;
    private readonly int _maxEncodedBytes;

    public FdoCoseEncryptThenMacCodec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _maxEncodedBytes = maxEncodedBytes;
    }

    /// <summary>
    /// Encrypts one encoded FDO CBOR value with the caller's reserved IV or
    /// counter block, then authenticates the encoded inner envelope.
    /// </summary>
    public ReadOnlyMemory<byte> Encrypt(
        FdoCoseAeadAlgorithm suite,
        ReadOnlySpan<byte> verificationKey,
        ReadOnlySpan<byte> encryptionKey,
        ReadOnlySpan<byte> counterBlock,
        ReadOnlyMemory<byte> encodedPlaintext)
    {
        FdoTo2CipherSuites.EncryptThenMacParameters parameters = RequireKeys(suite, verificationKey, encryptionKey);
        if (counterBlock.Length != CounterBlockSize)
        {
            throw new ArgumentException("The AES IV must contain 16 bytes.", nameof(counterBlock));
        }

        byte[] innerProtected = EncodeProtectedAlgorithm((int)suite);
        byte[] outerProtected = EncodeProtectedAlgorithm(parameters.CoseMacAlgorithm);
        int ciphertextLength = FdoTo2CipherSuites.IsAesCbc(suite)
            ? FdoAesCbc.GetCiphertextLength(encodedPlaintext.Length) : encodedPlaintext.Length;
        if (GetEncodedLength(suite, encodedPlaintext.Length) > _maxEncodedBytes)
        {
            throw new CborContentException("The encrypt-then-MAC envelope exceeds the encoded byte limit.");
        }

        byte[] plaintext = encodedPlaintext.ToArray();
        try
        {
            _cbor.ValidateOwned(plaintext);
            byte[] ciphertext;
            if (FdoTo2CipherSuites.IsAesCbc(suite))
            {
                ciphertext = FdoAesCbc.Encrypt(encryptionKey, counterBlock, plaintext);
            }
            else
            {
                ciphertext = new byte[ciphertextLength];
                FdoAesCtr.Transform(encryptionKey, counterBlock, plaintext, ciphertext);
            }

            var inner = new CborWriter(CborConformanceMode.Canonical);
            inner.WriteTag(Encrypt0Tag);
            inner.WriteStartArray(3);
            inner.WriteByteString(innerProtected);
            inner.WriteStartMap(1);
            inner.WriteInt32(5);
            inner.WriteByteString(counterBlock);
            inner.WriteEndMap();
            inner.WriteByteString(ciphertext);
            inner.WriteEndArray();
            byte[] payload = inner.Encode();

            byte[] tag = ComputeTag(parameters, verificationKey, outerProtected, payload);
            var outer = new CborWriter(CborConformanceMode.Canonical);
            outer.WriteTag(Mac0Tag);
            outer.WriteStartArray(4);
            outer.WriteByteString(outerProtected);
            outer.WriteStartMap(0);
            outer.WriteEndMap();
            outer.WriteByteString(payload);
            outer.WriteByteString(tag);
            outer.WriteEndArray();
            return _cbor.ValidateAndCopy(outer.Encode());
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
    public static long GetEncodedLength(FdoCoseAeadAlgorithm suite, int plaintextLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(plaintextLength);
        FdoTo2CipherSuites.EncryptThenMacParameters parameters = GetParameters(suite);
        int innerProtectedLength = EncodeProtectedAlgorithm((int)suite).Length;
        int outerProtectedLength = EncodeProtectedAlgorithm(parameters.CoseMacAlgorithm).Length;
        long ciphertextLength = FdoTo2CipherSuites.IsAesCbc(suite)
            ? FdoAesCbc.GetCiphertextLength(plaintextLength) : plaintextLength;
        long innerLength = 5 + innerProtectedLength + 1 + CounterBlockSize +
            ByteStringHeaderLength(ciphertextLength) + ciphertextLength;
        return 3 + outerProtectedLength + 1 + ByteStringHeaderLength(innerLength) + innerLength +
            ByteStringHeaderLength(parameters.TagSize) + parameters.TagSize;
    }

    /// <summary>
    /// Verifies the outer MAC in constant time and only then parses the inner
    /// envelope. The returned ciphertext is not decrypted; the caller must
    /// enforce the selected channel's IV and counter rules before calling
    /// <see cref="Decrypt"/>.
    /// </summary>
    public AuthenticatedMessage VerifyAndParse(
        FdoCoseAeadAlgorithm suite,
        ReadOnlySpan<byte> verificationKey,
        ReadOnlyMemory<byte> encoded)
    {
        FdoTo2CipherSuites.EncryptThenMacParameters parameters = GetParameters(suite);
        if (verificationKey.Length != parameters.VerificationKeySize)
        {
            throw new ArgumentException("The verification key length does not match the suite.", nameof(verificationKey));
        }

        var outer = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        if (outer.PeekState() != CborReaderState.Tag || outer.ReadTag() != Mac0Tag)
        {
            throw new CborContentException("An FDO encrypt-then-MAC message requires COSE_Mac0 tag 17.");
        }

        if (outer.PeekState() != CborReaderState.StartArray || outer.ReadStartArray() != 4)
        {
            throw new CborContentException("An FDO COSE_Mac0 must contain four fields.");
        }

        ReadOnlyMemory<byte> outerProtected = ReadByteString(outer, "COSE_Mac0 protected header");
        if (!outerProtected.Span.SequenceEqual(EncodeProtectedAlgorithm(parameters.CoseMacAlgorithm)))
        {
            throw new CborContentException("The COSE_Mac0 protected header must contain only the selected MAC algorithm.");
        }

        if (outer.PeekState() != CborReaderState.StartMap || outer.ReadStartMap() != 0)
        {
            throw new CborContentException("The COSE_Mac0 unprotected header must be empty.");
        }

        outer.ReadEndMap();
        ReadOnlyMemory<byte> payload = ReadByteString(outer, "COSE_Mac0 payload");
        ReadOnlyMemory<byte> tag = ReadByteString(outer, "COSE_Mac0 tag");
        outer.ReadEndArray();
        if (outer.BytesRemaining != 0)
        {
            throw new CborContentException("The COSE_Mac0 message contains trailing data.");
        }

        byte[] expectedTag = ComputeTag(parameters, verificationKey, outerProtected.Span, payload.Span);
        try
        {
            if (tag.Length != expectedTag.Length || !CryptographicOperations.FixedTimeEquals(tag.Span, expectedTag))
            {
                throw new CryptographicException("The encrypt-then-MAC authentication tag is not valid.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedTag);
        }

        var inner = new CborReader(payload, CborConformanceMode.Canonical);
        if (inner.PeekState() != CborReaderState.Tag || inner.ReadTag() != Encrypt0Tag)
        {
            throw new CborContentException("The encrypt-then-MAC payload requires COSE_Encrypt0 tag 16.");
        }

        if (inner.PeekState() != CborReaderState.StartArray || inner.ReadStartArray() != 3)
        {
            throw new CborContentException("The inner COSE_Encrypt0 must contain three fields.");
        }

        ReadOnlyMemory<byte> innerProtected = ReadByteString(inner, "COSE_Encrypt0 protected header");
        if (!innerProtected.Span.SequenceEqual(EncodeProtectedAlgorithm((int)suite)))
        {
            throw new CborContentException("The inner protected header must contain only the selected cipher suite.");
        }

        if (inner.PeekState() != CborReaderState.StartMap || inner.ReadStartMap() != 1 ||
            inner.PeekState() != CborReaderState.UnsignedInteger || inner.ReadUInt64() != 5)
        {
            throw new CborContentException("The inner unprotected header must contain only the IV.");
        }

        ReadOnlyMemory<byte> counterBlock = ReadByteString(inner, "IV");
        if (counterBlock.Length != CounterBlockSize)
        {
            throw new CborContentException("The AES IV must contain 16 bytes.");
        }

        inner.ReadEndMap();
        ReadOnlyMemory<byte> ciphertext = ReadByteString(inner, "ciphertext");
        inner.ReadEndArray();
        if (inner.BytesRemaining != 0)
        {
            throw new CborContentException("The encrypt-then-MAC payload contains trailing data.");
        }

        return new AuthenticatedMessage(counterBlock.ToArray(), ciphertext.ToArray());
    }

    /// <summary>
    /// Decrypts an authenticated message and validates the plaintext as one
    /// FDO CBOR value. The caller must clear the returned buffer after use.
    /// </summary>
    public byte[] Decrypt(
        FdoCoseAeadAlgorithm suite,
        ReadOnlySpan<byte> encryptionKey,
        AuthenticatedMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (encryptionKey.Length != GetParameters(suite).EncryptionKeySize)
        {
            throw new ArgumentException("The encryption key length does not match the suite.", nameof(encryptionKey));
        }

        bool cbc = FdoTo2CipherSuites.IsAesCbc(suite);
        byte[] plaintext = cbc
            ? FdoAesCbc.Decrypt(encryptionKey, message.CounterBlock, message.Ciphertext)
            : new byte[message.Ciphertext.Length];
        bool completed = false;
        try
        {
            if (!cbc)
            {
                FdoAesCtr.Transform(encryptionKey, message.CounterBlock, message.Ciphertext, plaintext);
            }

            _cbor.ValidateOwned(plaintext);
            completed = true;
            return plaintext;
        }
        finally
        {
            if (!completed)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private static FdoTo2CipherSuites.EncryptThenMacParameters GetParameters(FdoCoseAeadAlgorithm suite) =>
        FdoTo2CipherSuites.GetEncryptThenMacParameters(suite);

    private static FdoTo2CipherSuites.EncryptThenMacParameters RequireKeys(
        FdoCoseAeadAlgorithm suite, ReadOnlySpan<byte> verificationKey, ReadOnlySpan<byte> encryptionKey)
    {
        FdoTo2CipherSuites.EncryptThenMacParameters parameters = GetParameters(suite);
        if (verificationKey.Length != parameters.VerificationKeySize)
        {
            throw new ArgumentException("The verification key length does not match the suite.", nameof(verificationKey));
        }

        if (encryptionKey.Length != parameters.EncryptionKeySize)
        {
            throw new ArgumentException("The encryption key length does not match the suite.", nameof(encryptionKey));
        }

        return parameters;
    }

    private static byte[] ComputeTag(
        FdoTo2CipherSuites.EncryptThenMacParameters parameters,
        ReadOnlySpan<byte> verificationKey,
        ReadOnlySpan<byte> protectedHeader,
        ReadOnlySpan<byte> payload)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(4);
        writer.WriteTextString("MAC0");
        writer.WriteByteString(protectedHeader);
        writer.WriteByteString(ReadOnlySpan<byte>.Empty);
        writer.WriteByteString(payload);
        writer.WriteEndArray();
        byte[] macInput = writer.Encode();
        return parameters.Hash == HashAlgorithmName.SHA384
            ? HMACSHA384.HashData(verificationKey, macInput)
            : HMACSHA256.HashData(verificationKey, macInput);
    }

    private static byte[] EncodeProtectedAlgorithm(int algorithm)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteInt32(algorithm);
        writer.WriteEndMap();
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
            throw new CborContentException($"The {field} must be a byte string.");
        }

        return reader.ReadDefiniteLengthByteString();
    }

    /// <summary>An authenticated but still encrypted message.</summary>
    public sealed record AuthenticatedMessage(byte[] CounterBlock, byte[] Ciphertext);
}
