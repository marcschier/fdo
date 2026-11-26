using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Fdo.Transport;

namespace Fdo.Serialization;

[Flags]
internal enum FdoKnownCapabilities : byte
{
    None = 0,
    Fdo10 = 0x01,
    Fdo11 = 0x02,
    Fdo20 = 0x04,
    Delegation = 0x80,
}

/// <summary>
/// Reads and writes the initial TO0 and TO1 message bodies. The advertised
/// capabilities, GUID and nonce are unverified. This codec does not negotiate
/// a version, authorize vendor capabilities, or authenticate a peer.
/// </summary>
internal sealed class FdoInitialMessageCodec
{
    private const byte KnownFirstByteMask = 0x87;
    private const int IdentifierLength = 16;

    private readonly FdoCborCodec _cbor;
    private readonly int _maxEncodedBytes;
    private readonly int _maxItems;

    public FdoInitialMessageCodec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _maxEncodedBytes = maxEncodedBytes;
        _maxItems = maxItems;
    }

    public InitialMessage Decode(ushort messageType, ReadOnlyMemory<byte> encoded)
    {
        bool hasIdentifier = HasIdentifier(messageType);
        ReadOnlyMemory<byte> copy = _cbor.ValidateAndCopy(encoded);
        var reader = new CborReader(copy, CborConformanceMode.Canonical);

        RequireState(reader, CborReaderState.StartArray);
        if (reader.ReadStartArray() != (hasIdentifier ? 3 : 2))
        {
            throw new CborContentException("The initial message has the wrong number of fields.");
        }

        FdoCapabilityFields.Parsed fields = FdoCapabilityFields.Read(reader);

        ReadOnlyMemory<byte>? identifier = null;
        if (hasIdentifier)
        {
            RequireState(reader, CborReaderState.ByteString);
            identifier = reader.ReadDefiniteLengthByteString();
            if (identifier.Value.Length != IdentifierLength)
            {
                throw new CborContentException("The GUID or nonce must contain exactly 16 bytes.");
            }
        }

        reader.ReadEndArray();
        return new InitialMessage(messageType, fields.Flags, fields.Vendors, identifier);
    }

    public ReadOnlyMemory<byte> Encode(InitialMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        bool hasIdentifier = HasIdentifier(message.MessageType);

        if (hasIdentifier != message.GuidOrNonce.HasValue ||
            (hasIdentifier && message.GuidOrNonce!.Value.Length != IdentifierLength))
        {
            throw new ArgumentException("The message requires a 16-byte GUID or nonce, or no such field.", nameof(message));
        }

        FdoCapabilityFields.Prepared fields = FdoCapabilityFields.Prepare(
            message.CapabilityFlags, message.VendorCapabilities, _maxEncodedBytes, _maxItems,
            hasIdentifier ? 1 : 0, hasIdentifier ? 1 + IdentifierLength : 0);

        byte[]? identifier = message.GuidOrNonce?.ToArray();
        var writer = new CborWriter(CborConformanceMode.Canonical, initialCapacity: fields.EncodedSize);
        writer.WriteStartArray(hasIdentifier ? 3 : 2);
        FdoCapabilityFields.Write(writer, fields);
        if (identifier is not null)
        {
            writer.WriteByteString(identifier);
        }

        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    private static bool HasIdentifier(ushort messageType) => messageType switch
    {
        FdoMessageTypes.TO0Hello => false,
        FdoMessageTypes.TO0HelloAck or FdoMessageTypes.TO1HelloRV or FdoMessageTypes.TO1HelloRVAck => true,
        _ => throw new ArgumentOutOfRangeException(nameof(messageType), messageType, "This message is not an initial TO0 or TO1 message."),
    };

    private static void RequireState(CborReader reader, CborReaderState expected)
    {
        if (reader.PeekState() != expected)
        {
            throw new CborContentException($"Expected CBOR {expected} in the initial message.");
        }
    }

    /// <summary>
    /// The optional 16-byte field is a GUID for TO1.HelloRV and a nonce for
    /// TO0.HelloAck and TO1.HelloRVAck. Vendor names retain their wire order;
    /// their reverse-domain notation and authorization are not checked here.
    /// </summary>
    public sealed record InitialMessage(
        ushort MessageType,
        ReadOnlyMemory<byte> CapabilityFlags,
        IReadOnlyList<string> VendorCapabilities,
        ReadOnlyMemory<byte>? GuidOrNonce)
    {
        public FdoKnownCapabilities AdvertisedCapabilities => CapabilityFlags.IsEmpty
            ? FdoKnownCapabilities.None
            : (FdoKnownCapabilities)(CapabilityFlags.Span[0] & KnownFirstByteMask);
    }
}
