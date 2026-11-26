// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Security.Cryptography;
using Fdo.Serialization;

namespace Fdo.Cryptography;

internal enum FdoHashAlgorithm
{
    Sha384 = -43,
    Sha256 = -16,
    HmacSha256 = 5,
    HmacSha384 = 6,
}

/// <summary>
/// Represents the FDO 2.0 Hash or HMac value. The caller selects the expected
/// algorithm and supplies the exact bytes for each protocol operation.
/// </summary>
internal sealed class FdoHashValue
{
    private const int MaxEncodedBytes = 53;
    private static readonly FdoCborCodec Cbor = new(MaxEncodedBytes, maxDepth: 2, maxItems: 3);
    private readonly byte[] _value;

    public FdoHashValue(FdoHashAlgorithm algorithm, ReadOnlySpan<byte> value)
    {
        int length = GetValueLength(algorithm);
        if (value.Length != length)
        {
            throw new ArgumentException("The hash value has the wrong length for its algorithm.", nameof(value));
        }

        Algorithm = algorithm;
        _value = value.ToArray();
    }

    public FdoHashAlgorithm Algorithm { get; }

    public bool IsHmac => Algorithm is FdoHashAlgorithm.HmacSha256 or FdoHashAlgorithm.HmacSha384;

    public byte[] Value => _value.AsSpan().ToArray();

    public ReadOnlyMemory<byte> Encode()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical, initialCapacity: MaxEncodedBytes);
        writer.WriteStartArray(2);
        writer.WriteInt32((int)Algorithm);
        writer.WriteByteString(_value);
        writer.WriteEndArray();
        return Cbor.ValidateAndCopy(writer.Encode());
    }

    public static FdoHashValue Decode(ReadOnlyMemory<byte> encoded)
    {
        ReadOnlyMemory<byte> copy = Cbor.ValidateAndCopy(encoded);
        var reader = new CborReader(copy, CborConformanceMode.Canonical);
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != 2)
        {
            throw new CborContentException("An FDO Hash must be an array of two fields.");
        }

        FdoHashAlgorithm algorithm = ReadAlgorithm(reader);
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("An FDO Hash value must be a byte string.");
        }

        ReadOnlyMemory<byte> value = reader.ReadDefiniteLengthByteString();
        if (value.Length != GetValueLength(algorithm))
        {
            throw new CborContentException("The FDO Hash value has the wrong length for its algorithm.");
        }

        reader.ReadEndArray();
        return new FdoHashValue(algorithm, value.Span);
    }

    public static FdoHashValue ComputeDigest(FdoHashAlgorithm algorithm, ReadOnlySpan<byte> data)
    {
        Span<byte> value = stackalloc byte[SHA384.HashSizeInBytes];
        int length = ComputeDigestBytes(algorithm, data, value);
        return new FdoHashValue(algorithm, value[..length]);
    }

    public static FdoHashValue ComputeHmac(
        FdoHashAlgorithm algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> data)
    {
        Span<byte> value = stackalloc byte[HMACSHA384.HashSizeInBytes];
        int length = ComputeHmacBytes(algorithm, key, data, value);
        return new FdoHashValue(algorithm, value[..length]);
    }

    public bool MatchesDigest(FdoHashAlgorithm expectedAlgorithm, ReadOnlySpan<byte> data)
    {
        RequireDigestAlgorithm(expectedAlgorithm);
        if (Algorithm != expectedAlgorithm)
        {
            return false;
        }

        Span<byte> actual = stackalloc byte[SHA384.HashSizeInBytes];
        int length = ComputeDigestBytes(expectedAlgorithm, data, actual);
        return CryptographicOperations.FixedTimeEquals(_value, actual[..length]);
    }

    public bool MatchesHmac(
        FdoHashAlgorithm expectedAlgorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> data)
    {
        RequireHmacAlgorithm(expectedAlgorithm);
        RequireKey(key);
        if (Algorithm != expectedAlgorithm)
        {
            return false;
        }

        Span<byte> actual = stackalloc byte[HMACSHA384.HashSizeInBytes];
        int length = ComputeHmacBytes(expectedAlgorithm, key, data, actual);
        return CryptographicOperations.FixedTimeEquals(_value, actual[..length]);
    }

    public bool MatchesComputedHmac(FdoHashAlgorithm expectedAlgorithm, ReadOnlySpan<byte> computedHmac)
    {
        RequireHmacAlgorithm(expectedAlgorithm);
        return Algorithm == expectedAlgorithm && CryptographicOperations.FixedTimeEquals(_value, computedHmac);
    }

    private static FdoHashAlgorithm ReadAlgorithm(CborReader reader) => reader.PeekState() switch
    {
        CborReaderState.NegativeInteger => reader.ReadCborNegativeIntegerRepresentation() switch
        {
            15 => FdoHashAlgorithm.Sha256,
            42 => FdoHashAlgorithm.Sha384,
            _ => throw new CborContentException("The FDO Hash algorithm is not supported."),
        },
        CborReaderState.UnsignedInteger => reader.ReadUInt64() switch
        {
            5 => FdoHashAlgorithm.HmacSha256,
            6 => FdoHashAlgorithm.HmacSha384,
            _ => throw new CborContentException("The FDO Hash algorithm is not supported."),
        },
        _ => throw new CborContentException("The FDO Hash algorithm must be an integer."),
    };

    private static int GetValueLength(FdoHashAlgorithm algorithm) => algorithm switch
    {
        FdoHashAlgorithm.Sha256 or FdoHashAlgorithm.HmacSha256 => SHA256.HashSizeInBytes,
        FdoHashAlgorithm.Sha384 or FdoHashAlgorithm.HmacSha384 => SHA384.HashSizeInBytes,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "The FDO Hash algorithm is not supported."),
    };

    private static int ComputeDigestBytes(
        FdoHashAlgorithm algorithm,
        ReadOnlySpan<byte> data,
        Span<byte> destination)
    {
        RequireDigestAlgorithm(algorithm);
        return algorithm == FdoHashAlgorithm.Sha256
            ? SHA256.HashData(data, destination)
            : SHA384.HashData(data, destination);
    }

    private static int ComputeHmacBytes(
        FdoHashAlgorithm algorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> data,
        Span<byte> destination)
    {
        RequireHmacAlgorithm(algorithm);
        RequireKey(key);
        return algorithm == FdoHashAlgorithm.HmacSha256
            ? HMACSHA256.HashData(key, data, destination)
            : HMACSHA384.HashData(key, data, destination);
    }

    private static void RequireDigestAlgorithm(FdoHashAlgorithm algorithm)
    {
        if (algorithm is not (FdoHashAlgorithm.Sha256 or FdoHashAlgorithm.Sha384))
        {
            throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "A SHA-256 or SHA-384 algorithm is required.");
        }
    }

    private static void RequireHmacAlgorithm(FdoHashAlgorithm algorithm)
    {
        if (algorithm is not (FdoHashAlgorithm.HmacSha256 or FdoHashAlgorithm.HmacSha384))
        {
            throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "An HMAC-SHA-256 or HMAC-SHA-384 algorithm is required.");
        }
    }

    private static void RequireKey(ReadOnlySpan<byte> key)
    {
        if (key.IsEmpty)
        {
            throw new ArgumentException("The HMAC key must not be empty.", nameof(key));
        }
    }
}
