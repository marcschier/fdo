using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Text;
using Fdo.Transport;

namespace Fdo.Serialization;

/// <summary>
/// Checks FDO length-first CBOR encoding and frames StreamMsg values without
/// normalizing received message bodies or signed byte strings. Scalar map keys
/// are checked for semantic duplicates. Maps with two compound keys of the
/// same kind are not supported.
/// </summary>
internal sealed class FdoCborCodec
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly int _maxEncodedBytes;
    private readonly int _maxDepth;
    private readonly int _maxItems;

    /// <summary>
    /// Sets independent byte, nesting and item limits. Nesting includes tags
    /// and is capped at 128 to bound the validator's call stack.
    /// </summary>
    public FdoCborCodec(int maxEncodedBytes = ushort.MaxValue, int maxDepth = 32, int maxItems = ushort.MaxValue)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxEncodedBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxItems);
        if (maxDepth is < 1 or > 128)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDepth));
        }

        _maxEncodedBytes = maxEncodedBytes;
        _maxDepth = maxDepth;
        _maxItems = maxItems;
    }

    /// <summary>
    /// Returns an owned copy of exactly one CBOR value after encoding and limit
    /// checks. Byte-string payloads remain opaque; embedded signed CBOR is not
    /// rewritten.
    /// </summary>
    public ReadOnlyMemory<byte> ValidateAndCopy(ReadOnlyMemory<byte> encoded) =>
        ValidateAndCopy(encoded, CborConformanceMode.Canonical);

    /// <summary>
    /// Checks one definite-length embedded value without normalizing its
    /// encoded bytes. The enclosing FDO message is checked separately.
    /// </summary>
    public ReadOnlyMemory<byte> ValidateEmbeddedValueAndCopy(ReadOnlyMemory<byte> encoded) =>
        ValidateAndCopy(encoded, CborConformanceMode.Strict);

    /// <summary>
    /// Checks a value without copying it. The caller must exclusively own the
    /// buffer and prevent mutation for the duration of validation.
    /// </summary>
    public void ValidateOwned(ReadOnlyMemory<byte> encoded) =>
        Validate(encoded, CborConformanceMode.Canonical);

    private ReadOnlyMemory<byte> ValidateAndCopy(ReadOnlyMemory<byte> encoded, CborConformanceMode mode)
    {
        CheckLength(encoded.Length);
        byte[] copy = encoded.ToArray();
        Validate(copy, mode);
        return copy;
    }

    private void Validate(ReadOnlyMemory<byte> encoded, CborConformanceMode mode)
    {
        CheckLength(encoded.Length);
        var reader = new CborReader(encoded, mode);
        int remainingItems = _maxItems;
        ValidateValue(reader, encoded, 1, ref remainingItems, mode == CborConformanceMode.Canonical);
        if (reader.BytesRemaining != 0)
        {
            throw new CborContentException("An FDO CBOR value has trailing data.");
        }
    }

    /// <summary>
    /// Returns the exact contents of a definite byte string, excluding its CBOR
    /// wrapper. The payload is not decoded or re-encoded before hashing or signing.
    /// </summary>
    public ReadOnlyMemory<byte> ReadByteStringPayload(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireState(reader, CborReaderState.ByteString);
        return reader.ReadDefiniteLengthByteString();
    }

    /// <summary>
    /// Reconstructs the StreamMsg structure from HTTP metadata and a received
    /// body, without encoding an extra wire envelope.
    /// </summary>
    public StreamMessage CreateStreamMessage(
        ushort messageType,
        FdoProtocolVersion version,
        string? authorization,
        ReadOnlyMemory<byte> encodedBody)
    {
        RequireVersion(version);
        ReadOnlyMemory<byte> body = ValidateAndCopy(encodedBody);
        ReadOnlyMemory<byte>? token = EncodeTextToken(authorization, int.MaxValue);
        return new StreamMessage(
            GetFrameLength(messageType, version, token?.Length, body.Length), messageType, version, authorization, body, token);
    }

    /// <summary>Reads one complete StreamMsg and preserves its encoded body.</summary>
    public StreamMessage DecodeStreamMessage(ReadOnlyMemory<byte> encoded)
    {
        ReadOnlyMemory<byte> copy = ValidateAndCopy(encoded);
        var reader = new CborReader(copy, CborConformanceMode.Canonical);
        RequireState(reader, CborReaderState.StartArray);
        if (reader.ReadStartArray() != 5)
        {
            throw new CborContentException("StreamMsg must contain exactly five elements.");
        }

        RequireState(reader, CborReaderState.UnsignedInteger);
        if (reader.ReadUInt64() != (ulong)copy.Length)
        {
            throw new CborContentException("StreamMsg length does not match the complete encoded frame.");
        }

        ushort messageType = ReadUInt16(reader);
        ushort versionValue = ReadUInt16(reader);
        if (versionValue < 100)
        {
            throw new CborContentException("StreamMsg has an invalid protocol version.");
        }

        var version = new FdoProtocolVersion(versionValue / 100, versionValue % 100);
        RequireState(reader, CborReaderState.StartMap);
        int? count = reader.ReadStartMap();
        if (count is not (0 or 1))
        {
            throw new CborContentException("MsgProtocolInfo permits only an optional token entry.");
        }

        ReadOnlyMemory<byte>? encodedToken = null;
        if (count == 1)
        {
            RequireState(reader, CborReaderState.TextString);
            if (reader.ReadTextString() != "token")
            {
                throw new CborContentException("MsgProtocolInfo contains an unknown key.");
            }

            encodedToken = reader.ReadEncodedValue();
        }

        reader.ReadEndMap();
        ReadOnlyMemory<byte> body = reader.ReadEncodedValue();
        reader.ReadEndArray();
        return new StreamMessage(copy.Length, messageType, version, ReadTextToken(encodedToken), body, encodedToken);
    }

    /// <summary>
    /// Encodes a StreamMsg with a shortest-form length field that includes its
    /// own encoded width. The body must already be deterministic CBOR. This
    /// overload represents an HTTP authorization value as text; it does not
    /// restrict the specification's undefined authtoken wire type.
    /// </summary>
    public ReadOnlyMemory<byte> EncodeStreamMessage(
        ushort messageType,
        FdoProtocolVersion version,
        string? authorization,
        ReadOnlyMemory<byte> encodedBody)
    {
        return EncodeStreamMessageWithEncodedToken(messageType, version, EncodeTextToken(authorization, _maxEncodedBytes), encodedBody);
    }

    /// <summary>
    /// Encodes an opaque CBOR token without imposing a wire type on authtoken.
    /// A missing token differs from a token encoded as CBOR null.
    /// </summary>
    public ReadOnlyMemory<byte> EncodeStreamMessageWithEncodedToken(
        ushort messageType,
        FdoProtocolVersion version,
        ReadOnlyMemory<byte>? encodedToken,
        ReadOnlyMemory<byte> encodedBody)
    {
        StreamMessage message = CreateStreamMessageWithEncodedToken(messageType, version, encodedToken, encodedBody);
        int length = message.Length;
        if (length > _maxEncodedBytes)
        {
            throw new CborContentException("StreamMsg exceeds the encoded byte limit.");
        }

        var writer = new CborWriter(CborConformanceMode.Canonical, initialCapacity: length);
        writer.WriteStartArray(5);
        writer.WriteUInt64((ulong)length);
        writer.WriteUInt64(messageType);
        writer.WriteUInt64(version.Value);
        writer.WriteStartMap(message.EncodedToken is null ? 0 : 1);
        if (message.EncodedToken is ReadOnlyMemory<byte> token)
        {
            writer.WriteTextString("token");
            writer.WriteEncodedValue(token.Span);
        }

        writer.WriteEndMap();
        writer.WriteEncodedValue(message.Body.Span);
        writer.WriteEndArray();
        return ValidateAndCopy(writer.Encode());
    }

    private StreamMessage CreateStreamMessageWithEncodedToken(
        ushort messageType,
        FdoProtocolVersion version,
        ReadOnlyMemory<byte>? encodedToken,
        ReadOnlyMemory<byte> encodedBody)
    {
        RequireVersion(version);
        ReadOnlyMemory<byte> body = ValidateAndCopy(encodedBody);
        ReadOnlyMemory<byte>? token = null;
        if (encodedToken is ReadOnlyMemory<byte> raw)
        {
            token = ValidateAndCopy(raw);
        }
        int length = GetFrameLength(messageType, version, token?.Length, body.Length);
        return new StreamMessage(length, messageType, version, ReadTextToken(token), body, token);
    }

    private static ReadOnlyMemory<byte>? EncodeTextToken(string? authorization, int maxEncodedBytes)
    {
        if (authorization is null)
        {
            return null;
        }

        int bytes = StrictUtf8.GetByteCount(authorization);
        if ((long)GetHeaderSize((ulong)bytes) + bytes > maxEncodedBytes)
        {
            throw new CborContentException("The encoded token exceeds the byte limit.");
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString(authorization);
        return writer.Encode();
    }

    private static string? ReadTextToken(ReadOnlyMemory<byte>? encodedToken)
    {
        if (encodedToken is not ReadOnlyMemory<byte> token)
        {
            return null;
        }

        var reader = new CborReader(token, CborConformanceMode.Canonical);
        return reader.PeekState() == CborReaderState.TextString ? reader.ReadTextString() : null;
    }

    private static void RequireVersion(FdoProtocolVersion version)
    {
        if (version.Value == 0)
        {
            throw new ArgumentException("The protocol version must be initialized.", nameof(version));
        }
    }

    private void ValidateValue(
        CborReader reader,
        ReadOnlyMemory<byte> encoded,
        int depth,
        ref int remainingItems,
        bool requireDeterministicEncoding)
    {
        if (depth > _maxDepth || remainingItems-- <= 0)
        {
            throw new CborContentException("CBOR exceeds the nesting or item limit.");
        }

        switch (reader.PeekState())
        {
            case CborReaderState.UnsignedInteger:
                reader.ReadUInt64();
                break;
            case CborReaderState.NegativeInteger:
                reader.ReadCborNegativeIntegerRepresentation();
                break;
            case CborReaderState.ByteString:
                reader.ReadDefiniteLengthByteString();
                break;
            case CborReaderState.TextString:
                reader.ReadDefiniteLengthTextStringBytes();
                break;
            case CborReaderState.StartArray:
                int arrayLength = reader.ReadStartArray()
                    ?? throw new CborContentException("Indefinite CBOR arrays are not permitted.");
                if (arrayLength > remainingItems)
                {
                    throw new CborContentException("CBOR array exceeds the item limit or has indefinite length.");
                }

                for (int i = 0; i < arrayLength; i++)
                {
                    ValidateValue(reader, encoded, depth + 1, ref remainingItems, requireDeterministicEncoding);
                }

                reader.ReadEndArray();
                break;
            case CborReaderState.StartMap:
                int mapLength = reader.ReadStartMap()
                    ?? throw new CborContentException("Indefinite CBOR maps are not permitted.");
                if (mapLength > remainingItems / 2)
                {
                    throw new CborContentException("CBOR map exceeds the item limit or has indefinite length.");
                }

                var scalarKeys = mapLength > 1 ? new HashSet<ScalarMapKey>(ScalarMapKeyComparer.Instance) : null;
                var compoundKinds = mapLength > 1 ? new HashSet<CborReaderState>() : null;
                for (int i = 0; i < mapLength; i++)
                {
                    int keyStart = encoded.Length - reader.BytesRemaining;
                    CborReaderState keyState = reader.PeekState();
                    ValidateValue(reader, encoded, depth + 1, ref remainingItems, requireDeterministicEncoding);
                    if (scalarKeys is not null)
                    {
                        if (keyState is CborReaderState.StartArray or CborReaderState.StartMap or CborReaderState.Tag)
                        {
                            if (!compoundKinds!.Add(keyState))
                            {
                                throw new NotSupportedException(
                                    "Maps with multiple array, map, or tagged keys of the same kind are not supported.");
                            }
                        }
                        else
                        {
                            int keyLength = encoded.Length - reader.BytesRemaining - keyStart;
                            if (!scalarKeys.Add(ReadScalarMapKey(encoded.Slice(keyStart, keyLength))))
                            {
                                throw new CborContentException("CBOR map contains equivalent scalar keys.");
                            }
                        }
                    }

                    ValidateValue(reader, encoded, depth + 1, ref remainingItems, requireDeterministicEncoding);
                }

                reader.ReadEndMap();
                break;
            case CborReaderState.Tag:
                reader.ReadTag();
                ValidateValue(reader, encoded, depth + 1, ref remainingItems, requireDeterministicEncoding);
                break;
            case CborReaderState.Boolean:
                reader.ReadBoolean();
                break;
            case CborReaderState.Null:
                reader.ReadNull();
                break;
            case CborReaderState.SimpleValue:
                if (encoded.Span[encoded.Length - reader.BytesRemaining] >= 0xfc)
                {
                    throw new CborContentException("CBOR contains a reserved simple-value encoding.");
                }

                reader.ReadSimpleValue();
                break;
            case CborReaderState.HalfPrecisionFloat:
            case CborReaderState.SinglePrecisionFloat:
            case CborReaderState.DoublePrecisionFloat:
                int offset = encoded.Length - reader.BytesRemaining;
                double value = reader.ReadDouble();
                if (requireDeterministicEncoding)
                {
                    var canonicalFloat = new CborWriter(CborConformanceMode.Canonical);
                    canonicalFloat.WriteDouble(value);
                    ReadOnlySpan<byte> original = encoded.Span.Slice(offset, encoded.Length - reader.BytesRemaining - offset);
                    if (!original.SequenceEqual(canonicalFloat.Encode()))
                    {
                        throw new CborContentException("CBOR floating point is not in its preferred deterministic encoding.");
                    }
                }

                break;
            default:
                throw new CborContentException("Expected a complete definite-length CBOR value.");
        }
    }

    private static ScalarMapKey ReadScalarMapKey(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Strict);
        return reader.PeekState() switch
        {
            CborReaderState.UnsignedInteger => new(ScalarMapKeyKind.Unsigned, reader.ReadUInt64(), default),
            CborReaderState.NegativeInteger => new(
                ScalarMapKeyKind.Negative, reader.ReadCborNegativeIntegerRepresentation(), default),
            CborReaderState.ByteString => new(
                ScalarMapKeyKind.ByteString, 0, reader.ReadDefiniteLengthByteString()),
            CborReaderState.TextString => new(
                ScalarMapKeyKind.TextString, 0, reader.ReadDefiniteLengthTextStringBytes()),
            CborReaderState.Boolean => new(ScalarMapKeyKind.Simple, reader.ReadBoolean() ? 21UL : 20UL, default),
            CborReaderState.Null => new(ScalarMapKeyKind.Simple, 22, default),
            CborReaderState.SimpleValue => new(ScalarMapKeyKind.Simple, (ulong)reader.ReadSimpleValue(), default),
            CborReaderState.HalfPrecisionFloat or CborReaderState.SinglePrecisionFloat or
                CborReaderState.DoublePrecisionFloat => ReadFloatMapKey(reader, encoded.Span),
            _ => throw new CborContentException("The CBOR map key is not a supported scalar value."),
        };
    }

    private static ScalarMapKey ReadFloatMapKey(CborReader reader, ReadOnlySpan<byte> encoded)
    {
        double value = reader.ReadDouble();
        if (double.IsNaN(value))
        {
            ulong significand = encoded[0] switch
            {
                0xf9 => (ulong)(BinaryPrimitives.ReadUInt16BigEndian(encoded[1..]) & 0x03ff) << 54,
                0xfa => (ulong)(BinaryPrimitives.ReadUInt32BigEndian(encoded[1..]) & 0x007fffff) << 41,
                0xfb => (BinaryPrimitives.ReadUInt64BigEndian(encoded[1..]) & 0x000fffffffffffffUL) << 12,
                _ => throw new CborContentException("The CBOR floating-point key is invalid."),
            };
            return new ScalarMapKey(ScalarMapKeyKind.NaN, significand, default);
        }

        ulong bits = value == 0 ? 0 : unchecked((ulong)BitConverter.DoubleToInt64Bits(value));
        return new ScalarMapKey(ScalarMapKeyKind.Float, bits, default);
    }

    private enum ScalarMapKeyKind
    {
        Unsigned,
        Negative,
        ByteString,
        TextString,
        Simple,
        Float,
        NaN,
    }

    private readonly record struct ScalarMapKey(ScalarMapKeyKind Kind, ulong Value, ReadOnlyMemory<byte> Bytes);

    private sealed class ScalarMapKeyComparer : IEqualityComparer<ScalarMapKey>
    {
        public static ScalarMapKeyComparer Instance { get; } = new();

        public bool Equals(ScalarMapKey x, ScalarMapKey y) =>
            x.Kind == y.Kind && x.Value == y.Value && x.Bytes.Span.SequenceEqual(y.Bytes.Span);

        public int GetHashCode(ScalarMapKey key)
        {
            var hash = new HashCode();
            hash.Add(key.Kind);
            hash.Add(key.Value);
            hash.AddBytes(key.Bytes.Span);
            return hash.ToHashCode();
        }
    }

    private void CheckLength(int length)
    {
        if (length == 0 || length > _maxEncodedBytes)
        {
            throw new CborContentException("CBOR input is empty or exceeds the encoded byte limit.");
        }
    }

    private static ushort ReadUInt16(CborReader reader)
    {
        RequireState(reader, CborReaderState.UnsignedInteger);
        ulong value = reader.ReadUInt64();
        if (value > ushort.MaxValue)
        {
            throw new CborContentException("StreamMsg message type and protocol version must fit in 16 bits.");
        }

        return (ushort)value;
    }

    private static void RequireState(CborReader reader, CborReaderState expected)
    {
        if (reader.PeekState() != expected)
        {
            throw new CborContentException($"Expected CBOR {expected} in StreamMsg or byte-string payload.");
        }
    }

    /// <summary>Returns the shortest CBOR initial-byte and argument length.</summary>
    internal static int GetHeaderSize(ulong value) => value switch
    {
        <= 23 => 1,
        <= byte.MaxValue => 2,
        <= ushort.MaxValue => 3,
        <= uint.MaxValue => 5,
        _ => 9,
    };

    private static int GetFrameLength(
        ushort messageType, FdoProtocolVersion version, int? tokenLength, int bodyLength)
    {
        long protocolInfoBytes = tokenLength is int bytes ? 1L + 6 + bytes : 1;
        long withoutLength = 1L + GetHeaderSize(messageType) + GetHeaderSize(version.Value) + protocolInfoBytes + bodyLength;
        long length = withoutLength + 1;
        while (true)
        {
            long next = withoutLength + GetHeaderSize((ulong)length);
            if (next == length)
            {
                if (length > int.MaxValue)
                {
                    throw new CborContentException("StreamMsg is too large for a contiguous encoded buffer.");
                }

                return (int)length;
            }

            length = next;
        }
    }

    /// <summary>A StreamMsg whose body retains its received encoding.</summary>
    public sealed record StreamMessage(
        int Length,
        ushort MessageType,
        FdoProtocolVersion Version,
        string? Authorization,
        ReadOnlyMemory<byte> Body,
        ReadOnlyMemory<byte>? EncodedToken);
}
