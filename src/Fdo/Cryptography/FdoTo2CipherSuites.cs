// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

/// <summary>
/// Classifies the TO2 cipher suites accepted by the paired profile and reports
/// their session key layout. AEAD suites use one SEVK; encrypt-then-MAC suites
/// use the FDO 2.0 section 3.7.4 output order SVK followed by SEK.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal static class FdoTo2CipherSuites
{
    public static bool IsAesCtr(FdoCoseAeadAlgorithm suite) =>
        suite is FdoCoseAeadAlgorithm.AesCtr128HmacSha256 or FdoCoseAeadAlgorithm.AesCtr256HmacSha384;

    public static bool IsAesCbc(FdoCoseAeadAlgorithm suite) =>
        suite is FdoCoseAeadAlgorithm.AesCbc128HmacSha256 or FdoCoseAeadAlgorithm.AesCbc256HmacSha384;

    public static bool IsEncryptThenMac(FdoCoseAeadAlgorithm suite) => IsAesCtr(suite) || IsAesCbc(suite);

    /// <summary>Throws when the suite is not one of the paired TO2 suites.</summary>
    public static void Validate(FdoCoseAeadAlgorithm suite)
    {
        if (IsEncryptThenMac(suite))
        {
            return;
        }

        _ = FdoCoseAead.GetParameters(suite);
    }

    public static bool IsSupported(FdoCoseAeadAlgorithm suite) =>
        IsAesCtr(suite) ? FdoAesCtr.IsSupported :
        IsAesCbc(suite) ? FdoAesCbc.IsSupported :
        FdoCoseAead.IsSupported(suite);

    /// <summary>
    /// Returns the encrypt-then-MAC parameters. The SVK lengths follow FDO 2.0
    /// (256 and 512 bits), which differ from the RFC 9053 HMAC 384/384 key size.
    /// </summary>
    public static EncryptThenMacParameters GetEncryptThenMacParameters(FdoCoseAeadAlgorithm suite) => suite switch
    {
        FdoCoseAeadAlgorithm.AesCtr128HmacSha256 or FdoCoseAeadAlgorithm.AesCbc128HmacSha256 =>
            new(32, 16, HashAlgorithmName.SHA256, 5, 32),
        FdoCoseAeadAlgorithm.AesCtr256HmacSha384 or FdoCoseAeadAlgorithm.AesCbc256HmacSha384 =>
            new(64, 32, HashAlgorithmName.SHA384, 6, 48),
        _ => throw new ArgumentOutOfRangeException(nameof(suite), suite, "The suite is not an encrypt-then-MAC suite."),
    };

    /// <summary>Returns the total session key length that the KDF must produce.</summary>
    public static int GetSessionKeyLength(FdoCoseAeadAlgorithm suite)
    {
        if (IsEncryptThenMac(suite))
        {
            EncryptThenMacParameters parameters = GetEncryptThenMacParameters(suite);
            return parameters.VerificationKeySize + parameters.EncryptionKeySize;
        }

        return FdoCoseAead.GetParameters(suite).KeySize;
    }

    /// <summary>Returns the KDF PRF for the suite.</summary>
    public static HashAlgorithmName GetKdfHash(FdoCoseAeadAlgorithm suite) =>
        IsEncryptThenMac(suite) ? GetEncryptThenMacParameters(suite).Hash : HashAlgorithmName.SHA256;

    internal readonly record struct EncryptThenMacParameters(
        int VerificationKeySize,
        int EncryptionKeySize,
        HashAlgorithmName Hash,
        int CoseMacAlgorithm,
        int TagSize);
}
