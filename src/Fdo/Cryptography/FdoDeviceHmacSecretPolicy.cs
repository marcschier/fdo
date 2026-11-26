// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

/// <summary>
/// Applies the FDO 2.0 Device voucher-HMAC secret sizes from section 2.7.
/// An opaque root-of-trust provider can enforce the same lengths without
/// exporting its key material.
/// </summary>
internal static class FdoDeviceHmacSecretPolicy
{
    public static int GetRequiredLength(FdoHashAlgorithm algorithm) => algorithm switch
    {
        FdoHashAlgorithm.HmacSha256 => 32,
        FdoHashAlgorithm.HmacSha384 => 64,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "An FDO HMAC algorithm is required."),
    };

    /// <summary>
    /// Generates a software-held secret. The caller must persist it in
    /// protected storage and clear the returned buffer when it is no longer needed.
    /// </summary>
    /// <param name="algorithm">The algorithm to use for this operation.</param>
    public static byte[] Generate(FdoHashAlgorithm algorithm) =>
        RandomNumberGenerator.GetBytes(GetRequiredLength(algorithm));

    public static void ValidateLength(FdoHashAlgorithm algorithm, int actualLength)
    {
        int requiredLength = GetRequiredLength(algorithm);
        if (actualLength != requiredLength)
        {
            throw new ArgumentException(
                $"The Device HMAC secret must contain exactly {requiredLength} bytes.", nameof(actualLength));
        }
    }
}
