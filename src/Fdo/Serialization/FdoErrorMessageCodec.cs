using System;
using System.Formats.Cbor;
using System.Globalization;
using Fdo.Transport;

namespace Fdo.Serialization;

/// <summary>
/// Frames the selected common subset of the FDO 2.0 Error body. This codec
/// does not send an Error or apply the protection required by protocol state.
/// </summary>
internal sealed class FdoErrorMessageCodec
{
    private readonly FdoCborCodec _cbor;

    public FdoErrorMessageCodec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
    }

    /// <summary>
    /// Uses an existing request correlation ID and a non-sensitive description
    /// containing only the previous message ID. An Error must never answer an Error.
    /// </summary>
    public ReadOnlyMemory<byte> Encode(ushort errorCode, byte previousMessageId, ulong correlationId)
    {
        if (previousMessageId == FdoMessageTypes.Error)
        {
            throw new ArgumentOutOfRangeException(nameof(previousMessageId), "An Error cannot answer another Error.");
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(5);
        writer.WriteUInt64(errorCode);
        writer.WriteUInt64(previousMessageId);
        writer.WriteTextString(string.Concat(
            "FDO message ", previousMessageId.ToString(CultureInfo.InvariantCulture), " failed."));
        writer.WriteNull();
        writer.WriteUInt64(correlationId);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    /// <summary>
    /// Reads the selected subset only. The received description is untrusted;
    /// callers must not automatically log it or echo it to another peer.
    /// Non-null timestamps and null correlation IDs are not implemented.
    /// </summary>
    public ErrorMessage Decode(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != 5)
        {
            throw new CborContentException("An FDO Error body must contain five fields.");
        }

        ushort errorCode = (ushort)ReadUnsigned(reader, ushort.MaxValue, "error code");
        byte previousMessageId = (byte)ReadUnsigned(reader, byte.MaxValue, "previous message ID");
        if (previousMessageId == FdoMessageTypes.Error)
        {
            throw new CborContentException("An FDO Error cannot answer another Error.");
        }

        if (reader.PeekState() != CborReaderState.TextString)
        {
            throw new CborContentException("An FDO Error description must be a text string.");
        }

        string untrustedDescription = reader.ReadTextString();
        if (reader.PeekState() != CborReaderState.Null)
        {
            throw new NotSupportedException("Non-null FDO Error timestamps are not supported.");
        }

        reader.ReadNull();
        if (reader.PeekState() == CborReaderState.Null)
        {
            throw new NotSupportedException("A null FDO Error correlation ID is not supported.");
        }

        ulong correlationId = ReadUnsigned(reader, ulong.MaxValue, "correlation ID");
        reader.ReadEndArray();
        return new ErrorMessage(errorCode, previousMessageId, untrustedDescription, correlationId);
    }

    private static ulong ReadUnsigned(CborReader reader, ulong maximum, string name)
    {
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException($"The FDO Error {name} must be an unsigned integer.");
        }

        ulong value = reader.ReadUInt64();
        if (value > maximum)
        {
            throw new CborContentException($"The FDO Error {name} exceeds its allowed range.");
        }

        return value;
    }

    public sealed record ErrorMessage(
        ushort ErrorCode,
        byte PreviousMessageId,
        string UntrustedDescription,
        ulong CorrelationId);
}
