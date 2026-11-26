// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

internal enum FdoCoseAeadAlgorithm
{
    /// <summary>
    /// FDO <c>CS_AES256_CTR_HMAC-SHA384</c> encrypt-then-MAC suite. It is not a
    /// COSE AEAD algorithm; <see cref="FdoCoseAead"/> rejects it.
    /// </summary>
    AesCtr256HmacSha384 = -17760706,

    /// <summary>
    /// FDO <c>CS_AES256_CBC_HMAC-SHA384</c> encrypt-then-MAC suite.
    /// </summary>
    AesCbc256HmacSha384 = -17760705,

    /// <summary>
    /// FDO <c>CS_AES128_CTR_HMAC-SHA256</c> encrypt-then-MAC suite. It is not a
    /// COSE AEAD algorithm; <see cref="FdoCoseAead"/> rejects it.
    /// </summary>
    AesCtr128HmacSha256 = -17760704,

    /// <summary>
    /// FDO <c>CS_AES128_CBC_HMAC-SHA256</c> encrypt-then-MAC suite.
    /// </summary>
    AesCbc128HmacSha256 = -17760703,
    A128Gcm = 1,
    A256Gcm = 3,
    AesCcm16_128_128 = 30,
    AesCcm16_128_256 = 31,
    AesCcm64_128_128 = 32,
    AesCcm64_128_256 = 33,
}

/// <summary>
/// Applies the AES-GCM and AES-CCM primitives used by selected COSE algorithms.
/// This type does not construct COSE messages or negotiate FDO session suites.
/// The caller must enforce key and nonce ownership, uniqueness, and usage limits,
/// and supply the authenticated data required by the enclosing protocol.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal static class FdoCoseAead
{
    public const int TagSize = 16;

    public static bool IsSupported(FdoCoseAeadAlgorithm algorithm)
    {
        (_, _, bool ccm) = GetParameters(algorithm);
        return ccm ? AesCcm.IsSupported : AesGcm.IsSupported;
    }

    /// <summary>
    /// Encrypts into separate caller-owned ciphertext and tag buffers. Output
    /// buffers must not overlap each other or any input.
    /// </summary>
    /// <param name="algorithm">The algorithm to use for this operation.</param>
    /// <param name="key">The symmetric key of the selected AEAD algorithm.</param>
    /// <param name="nonce">The nonce for this exchange.</param>
    /// <param name="plaintext">The buffer containing or receiving the unprotected payload.</param>
    /// <param name="ciphertext">The buffer containing or receiving the encrypted payload.</param>
    /// <param name="tag">The authentication tag to write or verify.</param>
    /// <param name="associatedData">The additional bytes authenticated but not encrypted.</param>
    /// <exception cref="ArgumentException">
    /// The ciphertext and tag must not overlap each other or the inputs.
    /// </exception>
    public static void Encrypt(
        FdoCoseAeadAlgorithm algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        bool ccm = Validate(algorithm, key, nonce, plaintext.Length, ciphertext.Length, tag);
        if (key.Overlaps(ciphertext) || key.Overlaps(tag) ||
            nonce.Overlaps(ciphertext) || nonce.Overlaps(tag) ||
            plaintext.Overlaps(ciphertext) || plaintext.Overlaps(tag) ||
            associatedData.Overlaps(ciphertext) || associatedData.Overlaps(tag) ||
            ((ReadOnlySpan<byte>)ciphertext).Overlaps(tag))
        {
            throw new ArgumentException("The ciphertext and tag must not overlap each other or the inputs.");
        }

        RequireSupport(ccm);
        bool completed = false;
        try
        {
            if (ccm)
            {
                using var aes = new AesCcm(key);
                aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }
            else
            {
                using var aes = new AesGcm(key, TagSize);
                aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            }

            completed = true;
        }
        finally
        {
            if (!completed)
            {
                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(tag);
            }
        }
    }

    /// <summary>
    /// Decrypts into a caller-owned buffer that must not overlap any input.
    /// The caller must not read the buffer before this method returns. A
    /// cryptographic failure clears the plaintext buffer and is propagated.
    /// </summary>
    /// <param name="algorithm">The algorithm to use for this operation.</param>
    /// <param name="key">The symmetric key of the selected AEAD algorithm.</param>
    /// <param name="nonce">The nonce for this exchange.</param>
    /// <param name="ciphertext">The buffer containing or receiving the encrypted payload.</param>
    /// <param name="tag">The authentication tag to write or verify.</param>
    /// <param name="plaintext">The buffer containing or receiving the unprotected payload.</param>
    /// <param name="associatedData">The additional bytes authenticated but not encrypted.</param>
    /// <exception cref="ArgumentException">The plaintext buffer must not overlap the inputs.</exception>
    public static void Decrypt(
        FdoCoseAeadAlgorithm algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        bool ccm = Validate(algorithm, key, nonce, ciphertext.Length, plaintext.Length, tag);
        if (key.Overlaps(plaintext) || nonce.Overlaps(plaintext) ||
            ciphertext.Overlaps(plaintext) || tag.Overlaps(plaintext) ||
            associatedData.Overlaps(plaintext))
        {
            throw new ArgumentException("The plaintext buffer must not overlap the inputs.");
        }

        RequireSupport(ccm);
        bool completed = false;
        try
        {
            if (ccm)
            {
                using var aes = new AesCcm(key);
                aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            }
            else
            {
                using var aes = new AesGcm(key, TagSize);
                aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            }

            completed = true;
        }
        finally
        {
            if (!completed)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private static bool Validate(
        FdoCoseAeadAlgorithm algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        int inputLength,
        int outputLength,
        ReadOnlySpan<byte> tag)
    {
        (int keySize, int nonceSize, bool ccm) = GetParameters(algorithm);
        if (key.Length != keySize)
        {
            throw new ArgumentException("The key length does not match the selected COSE algorithm.", nameof(key));
        }

        if (nonce.Length != nonceSize)
        {
            throw new ArgumentException("The nonce length does not match the selected COSE algorithm.", nameof(nonce));
        }

        if (tag.Length != TagSize)
        {
            throw new ArgumentException("The authentication tag must contain 16 bytes.", nameof(tag));
        }

        if (inputLength != outputLength)
        {
            throw new ArgumentException("The input and output buffers must have the same length.");
        }

        if (ccm && nonceSize == 13 && inputLength > ushort.MaxValue)
        {
            throw new ArgumentException("The selected AES-CCM algorithm permits at most 65535 plaintext bytes.");
        }

        return ccm;
    }

    internal static (int KeySize, int NonceSize, bool Ccm) GetParameters(FdoCoseAeadAlgorithm algorithm) => algorithm switch
    {
        FdoCoseAeadAlgorithm.A128Gcm => (16, 12, false),
        FdoCoseAeadAlgorithm.A256Gcm => (32, 12, false),
        FdoCoseAeadAlgorithm.AesCcm16_128_128 => (16, 13, true),
        FdoCoseAeadAlgorithm.AesCcm16_128_256 => (32, 13, true),
        FdoCoseAeadAlgorithm.AesCcm64_128_128 => (16, 7, true),
        FdoCoseAeadAlgorithm.AesCcm64_128_256 => (32, 7, true),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "The COSE AEAD algorithm is not supported."),
    };

    private static void RequireSupport(bool ccm)
    {
        if (!(ccm ? AesCcm.IsSupported : AesGcm.IsSupported))
        {
            throw new PlatformNotSupportedException("The selected AES AEAD algorithm is not available on this platform.");
        }
    }
}
