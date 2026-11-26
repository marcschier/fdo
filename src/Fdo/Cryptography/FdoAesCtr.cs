// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

/// <summary>
/// Applies AES-CTR without authentication. The caller must authenticate
/// ciphertext and reserve a distinct counter block for every block encrypted
/// with the same key, using <see cref="TryReserve"/>. The final four bytes of the
/// initial counter block are a big-endian counter that must not wrap. Linux
/// uses OpenSSL, macOS uses CommonCrypto, and Windows uses CNG AES-ECB with the
/// NIST SP 800-38A counter construction applied here.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal static partial class FdoAesCtr
{
    /// <summary>Number of counter values available under one 12-byte prefix.</summary>
    public const ulong CounterSpace = 1UL << 32;

    private const int BlockSize = 16;
    private const int MaxInputLength = ushort.MaxValue;
    private const int CngChunkBlocks = 64;
    private const uint CcEncrypt = 0;
    private const uint CcModeCtr = 4;
    private const uint CcAlgorithmAes = 0;
    private const uint CcNoPadding = 0;
    private const uint CcCtrBigEndian = 2;

    public static void Transform(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> counterBlock,
        ReadOnlySpan<byte> input,
        Span<byte> output)
    {
        if (key.Length is not (16 or 32))
        {
            throw new ArgumentException("The AES-CTR key must contain 16 or 32 bytes.", nameof(key));
        }

        if (counterBlock.Length != BlockSize)
        {
            throw new ArgumentException("The AES-CTR counter block must contain 16 bytes.", nameof(counterBlock));
        }

        if (input.Length > MaxInputLength || output.Length != input.Length)
        {
            throw new ArgumentException("The input and output lengths must match and not exceed 65535 bytes.");
        }

        if (key.Overlaps(output) || counterBlock.Overlaps(output) || input.Overlaps(output))
        {
            throw new ArgumentException("The output must not overlap any input.", nameof(output));
        }

        uint counter = BinaryPrimitives.ReadUInt32BigEndian(counterBlock[^4..]);
        if ((ulong)counter + (ulong)BlockCount(input.Length) > CounterSpace)
        {
            throw new ArgumentException("The AES-CTR counter would wrap.", nameof(counterBlock));
        }

        if (!IsSupported)
        {
            throw new PlatformNotSupportedException("The AES-CTR primitive is available only on Linux, macOS, and Windows.");
        }

        if (input.IsEmpty)
        {
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            TransformCng(key, counterBlock, input, output);
            return;
        }

        byte[] buffer = new byte[input.Length + BlockSize];
        bool completed = false;
        try
        {
            int written = OperatingSystem.IsLinux()
                ? TransformOpenSsl(key, counterBlock, input, buffer)
                : TransformCommonCrypto(key, counterBlock, input, buffer);
            if (written != input.Length)
            {
                throw new CryptographicException("The native AES-CTR provider returned an unexpected output length.");
            }

            buffer.AsSpan(0, written).CopyTo(output);
            completed = true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            if (!completed)
            {
                CryptographicOperations.ZeroMemory(output);
            }
        }
    }

    /// <summary>Gets whether this platform has a qualified AES-CTR implementation.</summary>
    public static bool IsSupported =>
        OperatingSystem.IsLinux() || OperatingSystem.IsMacOS() || OperatingSystem.IsWindows();

    /// <summary>
    /// Reserves the counter blocks for one message of <paramref name="length"/>
    /// bytes, starting at <paramref name="nextCounter"/>. Every message reserves
    /// at least one block so that no two messages share an initial counter block.
    /// Returns <see langword="false"/> when the 32-bit counter space under the
    /// current prefix cannot hold the message; the caller must then stop using
    /// the key. The caller commits <paramref name="followingCounter"/> only after
    /// the message has been processed successfully.
    /// </summary>
    /// <param name="nextCounter">The counter value to use for the next operation.</param>
    /// <param name="length">The length of the value in bytes.</param>
    /// <param name="initialCounter">The initial counter value for encryption or decryption.</param>
    /// <param name="followingCounter">The counter immediately after the reserved blocks.</param>
    public static bool TryReserve(ulong nextCounter, int length, out uint initialCounter, out ulong followingCounter)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        ulong blocks = Math.Max(1UL, (ulong)BlockCount(length));
        if (nextCounter >= CounterSpace || blocks > CounterSpace - nextCounter)
        {
            initialCounter = 0;
            followingCounter = nextCounter;
            return false;
        }

        initialCounter = (uint)nextCounter;
        followingCounter = nextCounter + blocks;
        return true;
    }

    private static long BlockCount(int length) => ((long)length + BlockSize - 1) / BlockSize;

    private static unsafe void TransformCng(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> counterBlock, ReadOnlySpan<byte> input, Span<byte> output)
    {
        nint algorithm = 0;
        nint keyHandle = 0;
        byte[] counters = new byte[CngChunkBlocks * BlockSize];
        byte[] keystream = new byte[CngChunkBlocks * BlockSize];
        bool completed = false;
        try
        {
            CheckCng(BCryptOpenAlgorithmProvider(out algorithm, "AES", null, 0));
            fixed (char* mode = "ChainingModeECB")
            {
                CheckCng(BCryptSetProperty(
                    algorithm, "ChainingMode", (byte*)mode, (uint)(("ChainingModeECB".Length + 1) * sizeof(char)), 0));
            }

            fixed (byte* keyPtr = key)
            {
                CheckCng(BCryptGenerateSymmetricKey(algorithm, out keyHandle, 0, 0, keyPtr, (uint)key.Length, 0));
            }

            ReadOnlySpan<byte> prefix = counterBlock[..12];
            uint counter = BinaryPrimitives.ReadUInt32BigEndian(counterBlock[12..]);
            int offset = 0;
            while (offset < input.Length)
            {
                int chunk = Math.Min(input.Length - offset, counters.Length);
                int blocks = (int)BlockCount(chunk);
                int bytes = blocks * BlockSize;
                for (int i = 0; i < blocks; i++)
                {
                    Span<byte> block = counters.AsSpan(i * BlockSize, BlockSize);
                    prefix.CopyTo(block);
                    BinaryPrimitives.WriteUInt32BigEndian(block[12..], unchecked(counter + (uint)i));
                }

                uint written;
                fixed (byte* countersPtr = counters, keystreamPtr = keystream)
                {
                    CheckCng(BCryptEncrypt(
                        keyHandle, countersPtr, (uint)bytes, 0, null, 0, keystreamPtr, (uint)bytes, out written, 0));
                }

                if (written != (uint)bytes)
                {
                    throw new CryptographicException("CNG returned an unexpected AES-ECB output length.");
                }

                for (int i = 0; i < chunk; i++)
                {
                    output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);
                }

                counter = unchecked(counter + (uint)blocks);
                offset += chunk;
            }

            completed = true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(counters);
            CryptographicOperations.ZeroMemory(keystream);
            if (keyHandle != 0)
            {
                _ = BCryptDestroyKey(keyHandle);
            }

            if (algorithm != 0)
            {
                _ = BCryptCloseAlgorithmProvider(algorithm, 0);
            }

            if (!completed)
            {
                CryptographicOperations.ZeroMemory(output);
            }
        }
    }

    private static void CheckCng(int status)
    {
        if (status != 0)
        {
            throw new CryptographicException($"The CNG AES-ECB operation failed with status 0x{status:X8}.");
        }
    }

    private static unsafe int TransformOpenSsl(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> counterBlock, ReadOnlySpan<byte> input, Span<byte> output)
    {
        ReadOnlySpan<byte> name = key.Length == 16 ? "AES-128-CTR\0"u8 : "AES-256-CTR\0"u8;
        nint cipher = 0;
        nint context = 0;
        try
        {
            fixed (byte* namePtr = name, keyPtr = key, counterPtr = counterBlock, inputPtr = input, outputPtr = output)
            {
                cipher = OpenSslCipherFetch(0, namePtr, 0);
                if (cipher == 0)
                {
                    throw new CryptographicException("OpenSSL could not fetch the selected AES-CTR cipher.");
                }

                context = OpenSslContextNew();
                if (context == 0)
                {
                    throw new CryptographicException("OpenSSL could not allocate an AES-CTR context.");
                }

                if (OpenSslEncryptInit(context, cipher, 0, keyPtr, counterPtr) != 1 ||
                    OpenSslEncryptUpdate(context, outputPtr, out int written, inputPtr, input.Length) != 1 ||
                    written < 0 || written > input.Length ||
                    OpenSslEncryptFinal(context, outputPtr + written, out int final) != 1 ||
                    final < 0 || final > BlockSize)
                {
                    throw new CryptographicException("The OpenSSL AES-CTR operation failed.");
                }

                return written + final;
            }
        }
        finally
        {
            if (context != 0)
            {
                OpenSslContextFree(context);
            }

            if (cipher != 0)
            {
                OpenSslCipherFree(cipher);
            }
        }
    }

    private static unsafe int TransformCommonCrypto(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> counterBlock, ReadOnlySpan<byte> input, Span<byte> output)
    {
        nint context = 0;
        try
        {
            fixed (byte* keyPtr = key, counterPtr = counterBlock, inputPtr = input, outputPtr = output)
            {
                int status = CommonCryptoCreate(
                    CcEncrypt, CcModeCtr, CcAlgorithmAes, CcNoPadding, counterPtr, keyPtr,
                    (nuint)key.Length, 0, 0, 0, CcCtrBigEndian, out context);
                CheckCommonCrypto(status);
                status = CommonCryptoUpdate(
                    context, inputPtr, (nuint)input.Length, outputPtr, (nuint)output.Length, out nuint written);
                CheckCommonCrypto(status);
                if (written > (nuint)input.Length)
                {
                    throw new CryptographicException("CommonCrypto returned an unexpected AES-CTR output length.");
                }

                status = CommonCryptoFinal(
                    context, outputPtr + (int)written, (nuint)(output.Length - (int)written), out nuint final);
                CheckCommonCrypto(status);
                if (final > BlockSize)
                {
                    throw new CryptographicException("CommonCrypto returned an unexpected AES-CTR final length.");
                }

                return (int)(written + final);
            }
        }
        finally
        {
            if (context != 0)
            {
                CheckCommonCrypto(CommonCryptoRelease(context));
            }
        }
    }

    private static void CheckCommonCrypto(int status)
    {
        if (status != 0)
        {
            throw new CryptographicException($"The CommonCrypto AES-CTR operation failed with status {status}.");
        }
    }

    [LibraryImport("bcrypt.dll", EntryPoint = "BCryptOpenAlgorithmProvider", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int BCryptOpenAlgorithmProvider(
        out nint algorithm, string algorithmId, string? implementation, uint flags);

    [LibraryImport("bcrypt.dll", EntryPoint = "BCryptSetProperty", StringMarshalling = StringMarshalling.Utf16)]
    private static unsafe partial int BCryptSetProperty(
        nint handle, string property, byte* input, uint inputLength, uint flags);

    [LibraryImport("bcrypt.dll", EntryPoint = "BCryptGenerateSymmetricKey")]
    private static unsafe partial int BCryptGenerateSymmetricKey(
        nint algorithm, out nint key, nint keyObject, uint keyObjectLength, byte* secret, uint secretLength, uint flags);

    [LibraryImport("bcrypt.dll", EntryPoint = "BCryptEncrypt")]
    private static unsafe partial int BCryptEncrypt(
        nint key, byte* input, uint inputLength, nint paddingInfo, byte* iv, uint ivLength,
        byte* output, uint outputLength, out uint written, uint flags);

    [LibraryImport("bcrypt.dll", EntryPoint = "BCryptDestroyKey")]
    private static partial int BCryptDestroyKey(nint key);

    [LibraryImport("bcrypt.dll", EntryPoint = "BCryptCloseAlgorithmProvider")]
    private static partial int BCryptCloseAlgorithmProvider(nint algorithm, uint flags);

    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_CIPHER_fetch")]
    private static unsafe partial nint OpenSslCipherFetch(nint context, byte* algorithm, nint properties);

    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_CIPHER_free")]
    private static partial void OpenSslCipherFree(nint cipher);

    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_CIPHER_CTX_new")]
    private static partial nint OpenSslContextNew();

    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_CIPHER_CTX_free")]
    private static partial void OpenSslContextFree(nint context);

    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_EncryptInit_ex")]
    private static unsafe partial int OpenSslEncryptInit(nint context, nint cipher, nint engine, byte* key, byte* iv);

    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_EncryptUpdate")]
    private static unsafe partial int OpenSslEncryptUpdate(
        nint context, byte* output, out int written, byte* input, int length);

    [LibraryImport("libcrypto.so.3", EntryPoint = "EVP_EncryptFinal_ex")]
    private static unsafe partial int OpenSslEncryptFinal(nint context, byte* output, out int written);

    [LibraryImport("/usr/lib/libSystem.B.dylib", EntryPoint = "CCCryptorCreateWithMode")]
    private static unsafe partial int CommonCryptoCreate(
        uint operation, uint mode, uint algorithm, uint padding, byte* iv, byte* key,
        nuint keyLength, nint tweak, nuint tweakLength, int rounds, uint options, out nint context);

    [LibraryImport("/usr/lib/libSystem.B.dylib", EntryPoint = "CCCryptorUpdate")]
    private static unsafe partial int CommonCryptoUpdate(
        nint context, byte* input, nuint inputLength, byte* output, nuint available, out nuint written);

    [LibraryImport("/usr/lib/libSystem.B.dylib", EntryPoint = "CCCryptorFinal")]
    private static unsafe partial int CommonCryptoFinal(
        nint context, byte* output, nuint available, out nuint written);

    [LibraryImport("/usr/lib/libSystem.B.dylib", EntryPoint = "CCCryptorRelease")]
    private static partial int CommonCryptoRelease(nint context);
}
