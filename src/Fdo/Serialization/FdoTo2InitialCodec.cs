// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using Fdo.Cryptography;

namespace Fdo.Serialization;

/// <summary>
/// Frames the FDO 2.0 TO2 probe and acknowledgement and checks their
/// provisional paired-profile transcript. These unsigned messages and their
/// offers are not authenticated until the Device proof is verified.
/// </summary>
internal sealed class FdoTo2InitialCodec
{
    private const int IdentifierLength = 16;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly FdoCborCodec _cbor;
    private readonly int _maxEncodedBytes;
    private readonly int _maxItems;

    public FdoTo2InitialCodec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _maxEncodedBytes = maxEncodedBytes;
        _maxItems = maxItems;
    }

    public Probe DecodeProbe(ReadOnlyMemory<byte> encoded) =>
        ReadProbe(_cbor.ValidateAndCopy(encoded));

    public Acknowledgement DecodeAcknowledgement(ReadOnlyMemory<byte> encoded) =>
        ReadAcknowledgement(_cbor.ValidateAndCopy(encoded));

    public ReadOnlyMemory<byte> EncodeProbe(Probe message)
    {
        ArgumentNullException.ThrowIfNull(message);
        byte[] guid = CopyIdentifier(message.Guid, nameof(message));
        byte[] sugar = CopyIdentifier(message.Sugar, nameof(message));
        long[] hashes = CopyNumbers(message.HashTypes, "hash types", out long hashBytes);
        long size = (2L * (1 + IdentifierLength)) + IntegerSize(message.MaxDeviceMessageSize) +
            FdoCborCodec.GetHeaderSize((ulong)hashes.Length) + hashBytes;
        int additionalItems = CheckAdditionalItems(4L + hashes.Length);
        FdoCapabilityFields.Prepared fields = FdoCapabilityFields.Prepare(
            message.CapabilityFlags, message.VendorCapabilities, _maxEncodedBytes, _maxItems,
            additionalItems, size);

        var writer = new CborWriter(CborConformanceMode.Canonical, initialCapacity: fields.EncodedSize);
        writer.WriteStartArray(6);
        FdoCapabilityFields.Write(writer, fields);
        writer.WriteByteString(guid);
        writer.WriteUInt64(message.MaxDeviceMessageSize);
        WriteNumbers(writer, hashes);
        writer.WriteByteString(sugar);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    public ReadOnlyMemory<byte> EncodeAcknowledgement(Acknowledgement message)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(message.HashPrev);
        byte[] guid = CopyIdentifier(message.Guid, nameof(message));
        byte[] nonce = CopyIdentifier(message.NonceTo2ProveDv, nameof(message));
        string[] exchanges = CopyNames(message.KeyExchangeSuites, out long exchangeBytes);
        long[] ciphers = CopyNumbers(message.CipherSuites, "cipher suites", out long cipherBytes);
        ReadOnlyMemory<byte> hashPrev = message.HashPrev.Encode();
        long size = (2L * (1 + IdentifierLength)) + IntegerSize(message.MaxOwnerMessageSize) +
            FdoCborCodec.GetHeaderSize((ulong)exchanges.Length) + exchangeBytes +
            FdoCborCodec.GetHeaderSize((ulong)ciphers.Length) + cipherBytes + hashPrev.Length;
        int additionalItems = CheckAdditionalItems(8L + exchanges.Length + ciphers.Length);
        FdoCapabilityFields.Prepared fields = FdoCapabilityFields.Prepare(
            message.CapabilityFlags, message.VendorCapabilities, _maxEncodedBytes, _maxItems,
            additionalItems, size);

        var writer = new CborWriter(CborConformanceMode.Canonical, initialCapacity: fields.EncodedSize);
        writer.WriteStartArray(8);
        FdoCapabilityFields.Write(writer, fields);
        writer.WriteByteString(guid);
        writer.WriteUInt64(message.MaxOwnerMessageSize);
        writer.WriteStartArray(exchanges.Length);
        foreach (string exchange in exchanges)
        {
            writer.WriteTextString(exchange);
        }

        writer.WriteEndArray();
        WriteNumbers(writer, ciphers);
        writer.WriteByteString(nonce);
        writer.WriteEncodedValue(hashPrev.Span);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    /// <summary>
    /// Hashes the exact probe bytes with a SHA-2 algorithm offered by the
    /// Device. This paired profile does not append the manufacturer-key hash.
    /// </summary>
    /// <param name="algorithm">The algorithm to use for this operation.</param>
    /// <param name="encodedProbe">The exact encoded initial probe from the exchange.</param>
    public FdoHashValue ComputeProbeHash(FdoHashAlgorithm algorithm, ReadOnlyMemory<byte> encodedProbe)
    {
        ReadOnlyMemory<byte> copy = _cbor.ValidateAndCopy(encodedProbe);
        Probe probe = ReadProbe(copy);
        RequireFdo20(probe.CapabilityFlags);
        RequireOfferedDigest(probe.HashTypes, algorithm);
        return FdoHashValue.ComputeDigest(algorithm, copy.Span);
    }

    /// <summary>
    /// Checks the unsigned acknowledgement against the exact sent probe and
    /// returns the hash that must be included in the signed Device proof.
    /// This does not establish peer trust or verify a voucher.
    /// </summary>
    /// <param name="sentProbe">The exact probe bytes sent to the peer.</param>
    /// <param name="receivedAcknowledgement">The exact acknowledgement bytes received from the peer.</param>
    /// <exception cref="CryptographicException">
    /// The acknowledgement GUID does not match the probe. The acknowledgement hash does not match the probe.
    /// </exception>
    public CheckedAcknowledgement CheckAcknowledgement(
        ReadOnlyMemory<byte> sentProbe,
        ReadOnlyMemory<byte> receivedAcknowledgement)
    {
        ReadOnlyMemory<byte> probeBytes = _cbor.ValidateAndCopy(sentProbe);
        ReadOnlyMemory<byte> acknowledgementBytes = _cbor.ValidateAndCopy(receivedAcknowledgement);
        Probe probe = ReadProbe(probeBytes);
        Acknowledgement acknowledgement = ReadAcknowledgement(acknowledgementBytes);
        RequireFdo20(probe.CapabilityFlags);
        RequireFdo20(acknowledgement.CapabilityFlags);
        if (!probe.Guid.Span.SequenceEqual(acknowledgement.Guid.Span))
        {
            throw new CryptographicException("The acknowledgement GUID does not match the probe.");
        }

        FdoHashAlgorithm algorithm = acknowledgement.HashPrev.Algorithm;
        RequireOfferedDigest(probe.HashTypes, algorithm);
        if (!acknowledgement.HashPrev.MatchesDigest(algorithm, probeBytes.Span))
        {
            throw new CryptographicException("The acknowledgement hash does not match the probe.");
        }

        return new CheckedAcknowledgement(
            acknowledgement, FdoHashValue.ComputeDigest(algorithm, acknowledgementBytes.Span));
    }

    /// <summary>
    /// Checks a Device proof's hash against the exact acknowledgement sent by
    /// the Owner. The caller must separately verify the Device signature,
    /// nonce, GUID, selected suites, voucher, and trust.
    /// </summary>
    /// <param name="sentAcknowledgement">The exact acknowledgement bytes sent to the peer.</param>
    /// <param name="hashPrev2">The authenticated digest of the preceding voucher data.</param>
    /// <exception cref="CryptographicException">The Device proof hash does not match the acknowledgement.</exception>
    public void VerifyAcknowledgementHash(ReadOnlyMemory<byte> sentAcknowledgement, FdoHashValue hashPrev2)
    {
        ArgumentNullException.ThrowIfNull(hashPrev2);
        ReadOnlyMemory<byte> copy = _cbor.ValidateAndCopy(sentAcknowledgement);
        Acknowledgement acknowledgement = ReadAcknowledgement(copy);
        RequireFdo20(acknowledgement.CapabilityFlags);
        FdoHashAlgorithm algorithm = acknowledgement.HashPrev.Algorithm;
        if (algorithm is not (FdoHashAlgorithm.Sha256 or FdoHashAlgorithm.Sha384) ||
            !hashPrev2.MatchesDigest(algorithm, copy.Span))
        {
            throw new CryptographicException("The Device proof hash does not match the acknowledgement.");
        }
    }

    /// <summary>
    /// Checks that the paired key-exchange and cipher selections appeared in the exact Owner
    /// acknowledgement. Key compatibility and signature checks remain separate.
    /// </summary>
    /// <param name="encodedAcknowledgement">The exact encoded acknowledgement from the exchange.</param>
    /// <param name="exchange">The selected key exchange suite.</param>
    /// <param name="cipher">The cipher suite selected for protected messages.</param>
    /// <exception cref="CryptographicException">The selected key exchange or cipher was not offered.</exception>
    public void RequireOfferedSuites(
        ReadOnlyMemory<byte> encodedAcknowledgement,
        FdoKeyExchangeSuite exchange,
        FdoCoseAeadAlgorithm cipher)
    {
        string exchangeName = FdoKeyExchangeSuites.GetName(exchange);
        FdoTo2CipherSuites.Validate(cipher);

        Acknowledgement acknowledgement = DecodeAcknowledgement(encodedAcknowledgement);
        RequireFdo20(acknowledgement.CapabilityFlags);
        bool exchangeOffered = false;
        foreach (string offered in acknowledgement.KeyExchangeSuites)
        {
            exchangeOffered |= string.Equals(offered, exchangeName, StringComparison.Ordinal);
        }

        bool cipherOffered = false;
        foreach (long offered in acknowledgement.CipherSuites)
        {
            cipherOffered |= offered == (long)cipher;
        }

        if (!exchangeOffered || !cipherOffered)
        {
            throw new CryptographicException("The selected key exchange or cipher was not offered.");
        }
    }

    private static Probe ReadProbe(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Canonical);
        RequireArray(reader, 6);
        FdoCapabilityFields.Parsed fields = FdoCapabilityFields.Read(reader);
        ReadOnlyMemory<byte> guid = ReadIdentifier(reader);
        ushort size = ReadUInt16(reader);
        IReadOnlyList<long> hashes = ReadNumbers(reader);
        ReadOnlyMemory<byte> sugar = ReadIdentifier(reader);
        reader.ReadEndArray();
        return new Probe(fields.Flags, fields.Vendors, guid, size, hashes, sugar);
    }

    private static Acknowledgement ReadAcknowledgement(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Canonical);
        RequireArray(reader, 8);
        FdoCapabilityFields.Parsed fields = FdoCapabilityFields.Read(reader);
        ReadOnlyMemory<byte> guid = ReadIdentifier(reader);
        ushort size = ReadUInt16(reader);
        IReadOnlyList<string> exchanges = ReadNames(reader);
        IReadOnlyList<long> ciphers = ReadNumbers(reader);
        ReadOnlyMemory<byte> nonce = ReadIdentifier(reader);
        FdoHashValue hashPrev = FdoHashValue.Decode(reader.ReadEncodedValue());
        reader.ReadEndArray();
        return new Acknowledgement(fields.Flags, fields.Vendors, guid, size, exchanges, ciphers, nonce, hashPrev);
    }

    private long[] CopyNumbers(IReadOnlyList<long> values, string field, out long encodedBytes)
    {
        ArgumentNullException.ThrowIfNull(values);
        int count = CheckListCount(values.Count, field);
        var copy = new long[count];
        encodedBytes = 0;
        for (int i = 0; i < count; i++)
        {
            copy[i] = values[i];
            encodedBytes += IntegerSize(copy[i]);
            CheckEncodedSize(encodedBytes);
        }

        return copy;
    }

    private string[] CopyNames(IReadOnlyList<string> values, out long encodedBytes)
    {
        ArgumentNullException.ThrowIfNull(values);
        int count = CheckListCount(values.Count, "key exchange suites");
        var copy = new string[count];
        encodedBytes = 0;
        for (int i = 0; i < count; i++)
        {
            string value = values[i]
                ?? throw new ArgumentException("A key exchange suite cannot be null.", nameof(values));
            int length = StrictUtf8.GetByteCount(value);
            encodedBytes += FdoCborCodec.GetHeaderSize((ulong)length) + (long)length;
            CheckEncodedSize(encodedBytes);
            copy[i] = value;
        }

        return copy;
    }

    private int CheckListCount(int count, string field)
    {
        if (count < 1)
        {
            throw new ArgumentException($"The {field} array must not be empty.");
        }

        if (count > _maxItems || count > _maxEncodedBytes)
        {
            throw new CborContentException("The TO2 initial message exceeds the item or byte limit.");
        }

        return count;
    }

    private int CheckAdditionalItems(long count)
    {
        if (count > _maxItems)
        {
            throw new CborContentException("The TO2 initial message exceeds the item limit.");
        }

        return (int)count;
    }

    private void CheckEncodedSize(long size)
    {
        if (size > _maxEncodedBytes)
        {
            throw new CborContentException("The TO2 initial message exceeds the byte limit.");
        }
    }

    private static byte[] CopyIdentifier(ReadOnlyMemory<byte> value, string parameter)
    {
        if (value.Length != IdentifierLength)
        {
            throw new ArgumentException("A GUID, nonce, or sugar value must contain exactly 16 bytes.", parameter);
        }

        return value.ToArray();
    }

    private static ReadOnlyMemory<byte> ReadIdentifier(CborReader reader)
    {
        RequireState(reader, CborReaderState.ByteString);
        ReadOnlyMemory<byte> value = reader.ReadDefiniteLengthByteString();
        if (value.Length != IdentifierLength)
        {
            throw new CborContentException("A GUID, nonce, or sugar value must contain exactly 16 bytes.");
        }

        return value;
    }

    private static ReadOnlyCollection<long> ReadNumbers(CborReader reader)
    {
        int count = ReadNonEmptyArrayLength(reader);
        var result = new long[count];
        for (int i = 0; i < count; i++)
        {
            result[i] = ReadInteger(reader);
        }

        reader.ReadEndArray();
        return Array.AsReadOnly(result);
    }

    private static ReadOnlyCollection<string> ReadNames(CborReader reader)
    {
        int count = ReadNonEmptyArrayLength(reader);
        var result = new string[count];
        for (int i = 0; i < count; i++)
        {
            RequireState(reader, CborReaderState.TextString);
            result[i] = reader.ReadTextString();
        }

        reader.ReadEndArray();
        return Array.AsReadOnly(result);
    }

    private static int ReadNonEmptyArrayLength(CborReader reader)
    {
        RequireState(reader, CborReaderState.StartArray);
        int? count = reader.ReadStartArray();
        if (count is null or 0)
        {
            throw new CborContentException("A TO2 algorithm array must be definite and non-empty.");
        }

        return count.Value;
    }

    private static long ReadInteger(CborReader reader)
    {
        bool negative = reader.PeekState() == CborReaderState.NegativeInteger;
        if (!negative && reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("A TO2 algorithm identifier must be an integer.");
        }

        ulong value = negative ? reader.ReadCborNegativeIntegerRepresentation() : reader.ReadUInt64();
        if (value > long.MaxValue)
        {
            throw new CborContentException("A TO2 algorithm identifier exceeds the supported integer range.");
        }

        return negative ? -1 - (long)value : (long)value;
    }

    private static ushort ReadUInt16(CborReader reader)
    {
        RequireState(reader, CborReaderState.UnsignedInteger);
        ulong value = reader.ReadUInt64();
        if (value > ushort.MaxValue)
        {
            throw new CborContentException("A TO2 message size must fit in uint16.");
        }

        return (ushort)value;
    }

    private static void WriteNumbers(CborWriter writer, ReadOnlySpan<long> values)
    {
        writer.WriteStartArray(values.Length);
        foreach (long value in values)
        {
            writer.WriteInt64(value);
        }

        writer.WriteEndArray();
    }

    private static int IntegerSize(long value) =>
        FdoCborCodec.GetHeaderSize(value >= 0 ? (ulong)value : (ulong)(-(value + 1)));

    private static void RequireFdo20(ReadOnlyMemory<byte> flags)
    {
        if (flags.IsEmpty || (flags.Span[0] & (byte)FdoKnownCapabilities.Fdo20) == 0)
        {
            throw new CryptographicException("The paired TO2 profile requires FDO 2.0 capabilities.");
        }
    }

    private static void RequireOfferedDigest(IReadOnlyList<long> hashes, FdoHashAlgorithm algorithm)
    {
        if (algorithm is FdoHashAlgorithm.Sha256 or FdoHashAlgorithm.Sha384)
        {
            foreach (long offered in hashes)
            {
                if (offered == (long)algorithm)
                {
                    return;
                }
            }
        }

        throw new CryptographicException("The selected SHA-2 hash was not offered by the Device.");
    }

    private static void RequireArray(CborReader reader, int count)
    {
        RequireState(reader, CborReaderState.StartArray);
        if (reader.ReadStartArray() != count)
        {
            throw new CborContentException("The TO2 initial message has the wrong number of fields.");
        }
    }

    private static void RequireState(CborReader reader, CborReaderState state)
    {
        if (reader.PeekState() != state)
        {
            throw new CborContentException($"Expected CBOR {state} in the TO2 initial message.");
        }
    }

    public sealed record Probe(
        ReadOnlyMemory<byte> CapabilityFlags,
        IReadOnlyList<string> VendorCapabilities,
        ReadOnlyMemory<byte> Guid,
        ushort MaxDeviceMessageSize,
        IReadOnlyList<long> HashTypes,
        ReadOnlyMemory<byte> Sugar);

    public sealed record Acknowledgement(
        ReadOnlyMemory<byte> CapabilityFlags,
        IReadOnlyList<string> VendorCapabilities,
        ReadOnlyMemory<byte> Guid,
        ushort MaxOwnerMessageSize,
        IReadOnlyList<string> KeyExchangeSuites,
        IReadOnlyList<long> CipherSuites,
        ReadOnlyMemory<byte> NonceTo2ProveDv,
        FdoHashValue HashPrev);

    public sealed record CheckedAcknowledgement(Acknowledgement Message, FdoHashValue HashPrev2);
}
