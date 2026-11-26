// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

/// <summary>
/// Applies AES-CBC with PKCS#7 padding. The caller must authenticate the
/// ciphertext and IV before decryption and use a fresh random IV per message.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal static class FdoAesCbc
{
    public const int BlockSize = 16;

    public static bool IsSupported =>
        OperatingSystem.IsLinux() || OperatingSystem.IsMacOS() || OperatingSystem.IsWindows();

    public static int GetCiphertextLength(int plaintextLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(plaintextLength);
        long length = (((long)plaintextLength / BlockSize) + 1) * BlockSize;
        if (length > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintextLength));
        }

        return (int)length;
    }

    public static byte[] Encrypt(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> plaintext)
    {
        Validate(key, iv);
        byte[] ciphertext = new byte[GetCiphertextLength(plaintext.Length)];
        using Aes aes = Aes.Create();
        aes.SetKey(key);
        int written = aes.EncryptCbc(plaintext, iv, ciphertext, PaddingMode.PKCS7);
        if (written != ciphertext.Length)
        {
            throw new CryptographicException("AES-CBC returned an unexpected ciphertext length.");
        }

        return ciphertext;
    }

    public static byte[] Decrypt(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext)
    {
        Validate(key, iv);
        if (ciphertext.IsEmpty || ciphertext.Length % BlockSize != 0)
        {
            throw new CryptographicException("AES-CBC ciphertext must contain complete blocks.");
        }

        byte[] scratch = new byte[ciphertext.Length];
        try
        {
            using Aes aes = Aes.Create();
            aes.SetKey(key);
            if (!aes.TryDecryptCbc(ciphertext, iv, scratch, out int written, PaddingMode.PKCS7))
            {
                throw new CryptographicException("AES-CBC returned an unexpected plaintext length.");
            }

            return scratch.AsSpan(0, written).ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scratch);
        }
    }

    private static void Validate(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length is not (16 or 32))
        {
            throw new ArgumentException("The AES-CBC key must contain 16 or 32 bytes.", nameof(key));
        }

        if (iv.Length != BlockSize)
        {
            throw new ArgumentException("The AES-CBC IV must contain 16 bytes.", nameof(iv));
        }

        if (!IsSupported)
        {
            throw new PlatformNotSupportedException("AES-CBC is available only on Linux, macOS, and Windows.");
        }
    }
}
