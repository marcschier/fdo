using System;
using System.Formats.Cbor;
using Fdo.Cryptography;

namespace Fdo.Serialization;

/// <summary>
/// Encodes and decodes the plaintext TO2 completion bodies. The caller must
/// authenticate and decrypt received messages and check their protocol state.
/// </summary>
internal sealed class FdoTo2CompletionCodec
{
    private const int NonceLength = 16;
    private const int MaxEncodedBytes = 70;
    private static readonly FdoCborCodec Cbor = new(MaxEncodedBytes, maxDepth: 3, maxItems: 5);

    /// <summary>
    /// Reads the user-selected Done20 form: nonce followed by HMac or null.
    /// A parsed value does not authenticate the message or establish a
    /// credential disposition.
    /// </summary>
    public Done20 DecodeDone(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(Cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 2);
        ReadOnlyMemory<byte> nonce = ReadNonce(reader);

        FdoHashValue? replacementHmac;
        if (reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
            replacementHmac = null;
        }
        else
        {
            replacementHmac = FdoHashValue.Decode(reader.ReadEncodedValue());
            if (!replacementHmac.IsHmac)
            {
                throw new CborContentException("ReplacementHMac must use an HMAC algorithm.");
            }
        }

        reader.ReadEndArray();
        return new Done20(nonce, replacementHmac);
    }

    /// <summary>
    /// Writes the user-selected Done20 form. The role must ensure null is
    /// used for credential reuse and the replacement HMAC for replacement.
    /// </summary>
    public ReadOnlyMemory<byte> EncodeDone(ReadOnlyMemory<byte> nonce, FdoHashValue? replacementHmac)
    {
        RequireNonce(nonce);
        if (replacementHmac is not null && !replacementHmac.IsHmac)
        {
            throw new ArgumentException("ReplacementHMac must use an HMAC algorithm.", nameof(replacementHmac));
        }

        var writer = new CborWriter(CborConformanceMode.Canonical, initialCapacity: MaxEncodedBytes);
        writer.WriteStartArray(2);
        writer.WriteByteString(nonce.Span);
        if (replacementHmac is null)
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteEncodedValue(replacementHmac.Encode().Span);
        }

        writer.WriteEndArray();
        return Cbor.ValidateAndCopy(writer.Encode());
    }

    /// <summary>Reads the nonce from the plaintext DoneAck20 body.</summary>
    public ReadOnlyMemory<byte> DecodeDoneAck(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(Cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 1);
        ReadOnlyMemory<byte> nonce = ReadNonce(reader);
        reader.ReadEndArray();
        return nonce;
    }

    /// <summary>Writes the nonce in the plaintext DoneAck20 body.</summary>
    public ReadOnlyMemory<byte> EncodeDoneAck(ReadOnlyMemory<byte> nonce)
    {
        RequireNonce(nonce);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(1);
        writer.WriteByteString(nonce.Span);
        writer.WriteEndArray();
        return Cbor.ValidateAndCopy(writer.Encode());
    }

    private static void RequireArray(CborReader reader, int count)
    {
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != count)
        {
            throw new CborContentException("The TO2 completion body has the wrong array shape.");
        }
    }

    private static ReadOnlyMemory<byte> ReadNonce(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("The TO2 completion nonce must be a byte string.");
        }

        ReadOnlyMemory<byte> nonce = reader.ReadDefiniteLengthByteString();
        if (nonce.Length != NonceLength)
        {
            throw new CborContentException("The TO2 completion nonce must contain exactly 16 bytes.");
        }

        return nonce;
    }

    private static void RequireNonce(ReadOnlyMemory<byte> nonce)
    {
        if (nonce.Length != NonceLength)
        {
            throw new ArgumentException("The TO2 completion nonce must contain exactly 16 bytes.", nameof(nonce));
        }
    }

    /// <summary>The unverified Done20 fields, with nonce bytes owned by this value.</summary>
    public sealed record Done20(ReadOnlyMemory<byte> Nonce, FdoHashValue? ReplacementHmac);
}
