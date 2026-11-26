// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Fdo.Serialization;

namespace Fdo.Cryptography;

/// <summary>
/// Computes the Ownership Voucher Device certificate-chain hash over the
/// concatenated x5chain byte-string contents. It does not validate certificates.
/// </summary>
internal sealed class FdoCertificateChainHash
{
    private readonly FdoX5ChainCodec _codec;

    public FdoCertificateChainHash(int maxEncodedBytes = ushort.MaxValue, int maxItems = ushort.MaxValue)
    {
        _codec = new FdoX5ChainCodec(maxEncodedBytes, maxItems);
    }

    public FdoHashValue Compute(FdoHashAlgorithm algorithm, ReadOnlyMemory<byte> encodedChain)
    {
        HashAlgorithmName name = algorithm switch
        {
            FdoHashAlgorithm.Sha256 => HashAlgorithmName.SHA256,
            FdoHashAlgorithm.Sha384 => HashAlgorithmName.SHA384,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "A SHA-256 or SHA-384 digest is required."),
        };
        IReadOnlyList<ReadOnlyMemory<byte>> certificates = _codec.Decode(encodedChain);
        using IncrementalHash hash = IncrementalHash.CreateHash(name);
        foreach (ReadOnlyMemory<byte> certificate in certificates)
        {
            hash.AppendData(certificate.Span);
        }

        return new FdoHashValue(algorithm, hash.GetHashAndReset());
    }

    /// <summary>
    /// Compares the chain to an expected digest obtained from an authenticated
    /// source. A match does not establish certificate or supply-chain trust.
    /// </summary>
    /// <param name="expectedAlgorithm">The required algorithm for the verified value.</param>
    /// <param name="encodedChain">The encoded certificate chain.</param>
    /// <param name="expectedDigest">The authenticated digest to compare with the computed value.</param>
    public bool Verify(
        FdoHashAlgorithm expectedAlgorithm,
        ReadOnlyMemory<byte> encodedChain,
        FdoHashValue expectedDigest)
    {
        ArgumentNullException.ThrowIfNull(expectedDigest);
        FdoHashValue actual = Compute(expectedAlgorithm, encodedChain);
        return expectedDigest.Algorithm == expectedAlgorithm
            && CryptographicOperations.FixedTimeEquals(actual.Value, expectedDigest.Value);
    }
}
