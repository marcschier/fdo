// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using Fdo.Serialization;

namespace Fdo.Cryptography;

/// <summary>Computes or checks the Ownership Voucher header HMAC.</summary>
internal static class FdoOwnershipVoucherHeaderHmac
{
    private static readonly FdoCborCodec Cbor = new();

    /// <summary>
    /// Computes the HMAC over the encoded OVHeader contents, excluding the
    /// outer CBOR byte-string wrapper in OVHeaderTag.
    /// </summary>
    /// <param name="algorithm">The algorithm to use for this operation.</param>
    /// <param name="deviceHmacSecret">The Device's voucher HMAC key.</param>
    /// <param name="encodedHeaderTag">The exact voucher header, including its CBOR byte-string wrapper.</param>
    public static FdoHashValue Compute(
        FdoHashAlgorithm algorithm,
        ReadOnlySpan<byte> deviceHmacSecret,
        ReadOnlyMemory<byte> encodedHeaderTag) =>
        Compute(algorithm, deviceHmacSecret, encodedHeaderTag, Cbor);

    internal static FdoHashValue Compute(
        FdoHashAlgorithm algorithm,
        ReadOnlySpan<byte> deviceHmacSecret,
        ReadOnlyMemory<byte> encodedHeaderTag,
        FdoCborCodec cbor)
    {
        ReadOnlyMemory<byte> header = cbor.ReadByteStringPayload(encodedHeaderTag);
        return FdoHashValue.ComputeHmac(algorithm, deviceHmacSecret, header.Span);
    }

    /// <summary>
    /// Checks the header HMAC using the algorithm selected by the caller.
    /// </summary>
    /// <param name="expectedAlgorithm">The required algorithm for the verified value.</param>
    /// <param name="deviceHmacSecret">The Device's voucher HMAC key.</param>
    /// <param name="encodedHeaderTag">The exact voucher header, including its CBOR byte-string wrapper.</param>
    /// <param name="expectedHmac">The HMAC from the voucher to compare with the computed value.</param>
    public static bool Verify(
        FdoHashAlgorithm expectedAlgorithm,
        ReadOnlySpan<byte> deviceHmacSecret,
        ReadOnlyMemory<byte> encodedHeaderTag,
        FdoHashValue expectedHmac)
    {
        ArgumentNullException.ThrowIfNull(expectedHmac);
        ReadOnlyMemory<byte> header = Cbor.ReadByteStringPayload(encodedHeaderTag);
        return expectedHmac.MatchesHmac(expectedAlgorithm, deviceHmacSecret, header.Span);
    }
}
