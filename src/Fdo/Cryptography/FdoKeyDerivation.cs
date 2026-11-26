// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

/// <summary>Derives FDO 2.0 session key material as specified in section 3.7.4.</summary>
[UnsupportedOSPlatform("browser")]
internal static class FdoKeyDerivation
{
    private const int MaxOutputBytes = ushort.MaxValue / 8;
    private const int MaxCounter = byte.MaxValue;

    /// <summary>
    /// Derives key material from the shared secret and exchange context.
    /// The caller owns and must clear the resulting key material.
    /// </summary>
    /// <param name="sharedSecret">The secret produced by the key exchange.</param>
    /// <param name="contextRand">The random bytes included in the key derivation context.</param>
    /// <param name="hashAlgorithm">The hash algorithm required by the suite.</param>
    /// <param name="destination">The buffer that receives the result.</param>
    /// <exception cref="ArgumentOutOfRangeException">The output length must fit in a 16-bit bit count.</exception>
    public static void Derive(
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> contextRand,
        HashAlgorithmName hashAlgorithm,
        Span<byte> destination)
    {
        if (destination.Length > MaxOutputBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(destination), "The output length must fit in a 16-bit bit count.");
        }

        Span<byte> bitLength = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(bitLength, (ushort)(destination.Length * 8));
        DeriveCounterMode(
            sharedSecret,
            "FIDO-KDF\0AutomaticOnboardTunnel"u8,
            contextRand,
            bitLength,
            hashAlgorithm,
            destination);
    }

    /// <summary>
    /// Derives the verification and encryption keys for an encrypt-then-MAC
    /// suite. The caller selects their lengths and must clear both outputs.
    /// </summary>
    /// <param name="sharedSecret">The secret produced by the key exchange.</param>
    /// <param name="contextRand">The random bytes included in the key derivation context.</param>
    /// <param name="hashAlgorithm">The hash algorithm required by the suite.</param>
    /// <param name="verificationKey">The key used to verify the signature or MAC.</param>
    /// <param name="encryptionKey">The key used to encrypt or decrypt the message.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The combined key length must fit in a 16-bit bit count. The encryption key must not be empty. The verification
    /// key must not be empty.
    /// </exception>
    /// <exception cref="ArgumentException">The output keys must not overlap each other or the inputs.</exception>
    public static void DeriveEncryptThenMac(
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> contextRand,
        HashAlgorithmName hashAlgorithm,
        Span<byte> verificationKey,
        Span<byte> encryptionKey)
    {
        if (verificationKey.IsEmpty)
        {
            throw new ArgumentOutOfRangeException(nameof(verificationKey), "The verification key must not be empty.");
        }

        if (encryptionKey.IsEmpty)
        {
            throw new ArgumentOutOfRangeException(nameof(encryptionKey), "The encryption key must not be empty.");
        }

        if ((long)verificationKey.Length + encryptionKey.Length > MaxOutputBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(encryptionKey), "The combined key length must fit in a 16-bit bit count.");
        }

        if (((ReadOnlySpan<byte>)verificationKey).Overlaps(encryptionKey) ||
            sharedSecret.Overlaps(verificationKey) || sharedSecret.Overlaps(encryptionKey) ||
            contextRand.Overlaps(verificationKey) || contextRand.Overlaps(encryptionKey))
        {
            throw new ArgumentException("The output keys must not overlap each other or the inputs.");
        }

        byte[] keyMaterial = new byte[verificationKey.Length + encryptionKey.Length];
        try
        {
            Derive(sharedSecret, contextRand, hashAlgorithm, keyMaterial);
            keyMaterial.AsSpan(0, verificationKey.Length).CopyTo(verificationKey);
            keyMaterial.AsSpan(verificationKey.Length).CopyTo(encryptionKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyMaterial);
        }
    }

    /// <summary>
    /// Applies an eight-bit counter before the supplied fixed input fragments.
    /// </summary>
    /// <param name="sharedSecret">The secret produced by the key exchange.</param>
    /// <param name="fixedInputPrefix">The fixed input bytes before the key derivation context.</param>
    /// <param name="fixedInputContext">The context portion of the fixed key derivation input.</param>
    /// <param name="fixedInputSuffix">The fixed input bytes after the key derivation context.</param>
    /// <param name="hashAlgorithm">The hash algorithm required by the suite.</param>
    /// <param name="destination">The buffer that receives the result.</param>
    /// <exception cref="ArgumentException">
    /// Only HMAC-SHA-256 and HMAC-SHA-384 are supported. The destination must not overlap the secret or fixed input.
    /// The shared secret must not be empty.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The output length exceeds the FDO counter or bit-length limit.
    /// </exception>
    /// <exception cref="CryptographicException">The HMAC returned an unexpected output length.</exception>
    internal static void DeriveCounterMode(
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> fixedInputPrefix,
        ReadOnlySpan<byte> fixedInputContext,
        ReadOnlySpan<byte> fixedInputSuffix,
        HashAlgorithmName hashAlgorithm,
        Span<byte> destination)
    {
        if (sharedSecret.IsEmpty)
        {
            throw new ArgumentException("The shared secret must not be empty.", nameof(sharedSecret));
        }

        if (hashAlgorithm != HashAlgorithmName.SHA256 && hashAlgorithm != HashAlgorithmName.SHA384)
        {
            throw new ArgumentException("Only HMAC-SHA-256 and HMAC-SHA-384 are supported.", nameof(hashAlgorithm));
        }

        int hashLength = hashAlgorithm == HashAlgorithmName.SHA256 ? 32 : 48;
        if (destination.IsEmpty || destination.Length > MaxOutputBytes ||
            (destination.Length + hashLength - 1) / hashLength > MaxCounter)
        {
            throw new ArgumentOutOfRangeException(nameof(destination), "The output length exceeds the FDO counter or bit-length limit.");
        }

        if (sharedSecret.Overlaps(destination) || fixedInputPrefix.Overlaps(destination) ||
            fixedInputContext.Overlaps(destination) || fixedInputSuffix.Overlaps(destination))
        {
            throw new ArgumentException("The destination must not overlap the secret or fixed input.", nameof(destination));
        }

        Span<byte> block = stackalloc byte[48];
        Span<byte> counter = stackalloc byte[1];
        bool completed = false;
        try
        {
            using (IncrementalHash hmac = IncrementalHash.CreateHMAC(hashAlgorithm, sharedSecret))
            {
                int written = 0;
                for (int iteration = 1; written < destination.Length; iteration++)
                {
                    counter[0] = (byte)iteration;
                    hmac.AppendData(counter);
                    hmac.AppendData(fixedInputPrefix);
                    hmac.AppendData(fixedInputContext);
                    hmac.AppendData(fixedInputSuffix);
                    int blockLength = hmac.GetHashAndReset(block);
                    if (blockLength != hashLength)
                    {
                        throw new CryptographicException("The HMAC returned an unexpected output length.");
                    }

                    int copyLength = Math.Min(blockLength, destination.Length - written);
                    block[..copyLength].CopyTo(destination.Slice(written, copyLength));
                    written += copyLength;
                }
            }

            completed = true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
            if (!completed)
            {
                CryptographicOperations.ZeroMemory(destination);
            }
        }
    }
}
