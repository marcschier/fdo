// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;

namespace Fdo.Serialization;

/// <summary>
/// Frames plaintext TO2 ServiceInfo messages. Callers must authenticate and
/// decrypt them and enforce the ServiceInfo protocol state and message limits.
/// </summary>
internal sealed class FdoTo2ServiceInfoCodec
{
    private const int NonceLength = 16;
    private readonly FdoCborCodec _cbor;
    private readonly FdoServiceInfoCodec _serviceInfo;
    private readonly int _maxEncodedBytes;

    public FdoTo2ServiceInfoCodec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _serviceInfo = new FdoServiceInfoCodec(maxEncodedBytes, maxDepth, maxItems);
        _maxEncodedBytes = maxEncodedBytes;
    }

    /// <summary>
    /// Reads the provisional 2.0 form with null in the old HMAC field.
    /// The returned values are not authenticated.
    /// </summary>
    /// <param name="encoded">The encoded CBOR value to read or verify.</param>
    /// <exception cref="CborContentException">
    /// The TO2 setup nonce must contain exactly 16 bytes. The maximum Owner ServiceInfo size must fit in uint16.
    /// </exception>
    public DeviceServiceInfoReady DecodeDeviceReady(ReadOnlyMemory<byte> encoded)
    {
        var reader = CreateReader(encoded);
        RequireArray(reader, 3);
        ReadReplacementHmacPlaceholder(reader);

        ushort? maxOwnerServiceInfoSize = null;
        if (reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
        }
        else
        {
            RequireState(reader, CborReaderState.UnsignedInteger);
            ulong size = reader.ReadUInt64();
            if (size > ushort.MaxValue)
            {
                throw new CborContentException("The maximum Owner ServiceInfo size must fit in uint16.");
            }

            maxOwnerServiceInfoSize = (ushort)size;
        }

        RequireState(reader, CborReaderState.ByteString);
        ReadOnlyMemory<byte> nonce = reader.ReadDefiniteLengthByteString();
        if (nonce.Length != NonceLength)
        {
            throw new CborContentException("The TO2 setup nonce must contain exactly 16 bytes.");
        }

        reader.ReadEndArray();
        return new DeviceServiceInfoReady(maxOwnerServiceInfoSize, nonce);
    }

    /// <summary>
    /// Writes the provisional 2.0 form with null in the old HMAC field.
    /// </summary>
    /// <param name="maxOwnerServiceInfoSize">The maximum encoded Owner ServiceInfo body size, in bytes.</param>
    /// <param name="nonce">The nonce for this exchange.</param>
    /// <exception cref="ArgumentException">The TO2 setup nonce must contain exactly 16 bytes.</exception>
    public ReadOnlyMemory<byte> EncodeDeviceReady(ushort? maxOwnerServiceInfoSize, ReadOnlyMemory<byte> nonce)
    {
        if (nonce.Length != NonceLength)
        {
            throw new ArgumentException("The TO2 setup nonce must contain exactly 16 bytes.", nameof(nonce));
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteNull();
        if (maxOwnerServiceInfoSize is ushort size)
        {
            writer.WriteUInt64(size);
        }
        else
        {
            writer.WriteNull();
        }

        writer.WriteByteString(nonce.Span);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    /// <summary>Reads the provisional 2.0 Device ServiceInfo plaintext.</summary>
    /// <param name="encoded">The encoded CBOR value to read or verify.</param>
    public DeviceServiceInfo DecodeDevice(ReadOnlyMemory<byte> encoded)
    {
        var reader = CreateReader(encoded);
        RequireArray(reader, 3);
        ReadReplacementHmacPlaceholder(reader);
        bool isMoreServiceInfo = ReadBoolean(reader);
        IReadOnlyList<FdoServiceInfoCodec.Entry> serviceInfo = _serviceInfo.Decode(reader.ReadEncodedValue());
        reader.ReadEndArray();
        return new DeviceServiceInfo(isMoreServiceInfo, serviceInfo);
    }

    /// <summary>Writes the provisional 2.0 Device ServiceInfo plaintext.</summary>
    /// <param name="isMoreServiceInfo">Whether another ServiceInfo round follows.</param>
    /// <param name="serviceInfo">The ServiceInfo entries carried by the message.</param>
    public ReadOnlyMemory<byte> EncodeDevice(bool isMoreServiceInfo, IReadOnlyList<FdoServiceInfoCodec.Entry> serviceInfo)
    {
        ReadOnlyMemory<byte> encodedServiceInfo = PrepareServiceInfo(serviceInfo);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteNull();
        writer.WriteBoolean(isMoreServiceInfo);
        writer.WriteEncodedValue(encodedServiceInfo.Span);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    /// <summary>Reads the Owner ServiceInfo plaintext without applying state rules.</summary>
    /// <param name="encoded">The encoded CBOR value to read or verify.</param>
    public OwnerServiceInfo DecodeOwner(ReadOnlyMemory<byte> encoded)
    {
        var reader = CreateReader(encoded);
        RequireArray(reader, 3);
        bool isMoreServiceInfo = ReadBoolean(reader);
        bool isDone = ReadBoolean(reader);
        IReadOnlyList<FdoServiceInfoCodec.Entry> serviceInfo = _serviceInfo.Decode(reader.ReadEncodedValue());
        reader.ReadEndArray();
        return new OwnerServiceInfo(isMoreServiceInfo, isDone, serviceInfo);
    }

    /// <summary>Writes the Owner ServiceInfo plaintext without applying state rules.</summary>
    /// <param name="isMoreServiceInfo">Whether another ServiceInfo round follows.</param>
    /// <param name="isDone">Whether this round ends the ServiceInfo exchange.</param>
    /// <param name="serviceInfo">The ServiceInfo entries carried by the message.</param>
    public ReadOnlyMemory<byte> EncodeOwner(
        bool isMoreServiceInfo,
        bool isDone,
        IReadOnlyList<FdoServiceInfoCodec.Entry> serviceInfo)
    {
        ReadOnlyMemory<byte> encodedServiceInfo = PrepareServiceInfo(serviceInfo);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteBoolean(isMoreServiceInfo);
        writer.WriteBoolean(isDone);
        writer.WriteEncodedValue(encodedServiceInfo.Span);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    private CborReader CreateReader(ReadOnlyMemory<byte> encoded) =>
        new(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);

    private ReadOnlyMemory<byte> PrepareServiceInfo(IReadOnlyList<FdoServiceInfoCodec.Entry> serviceInfo)
    {
        ReadOnlyMemory<byte> encoded = _serviceInfo.Encode(serviceInfo);
        if ((long)encoded.Length + 3 > _maxEncodedBytes)
        {
            throw new CborContentException("The TO2 ServiceInfo body exceeds the encoded byte limit.");
        }

        return encoded;
    }

    private static void RequireArray(CborReader reader, int count)
    {
        RequireState(reader, CborReaderState.StartArray);
        if (reader.ReadStartArray() != count)
        {
            throw new CborContentException("The TO2 ServiceInfo body has the wrong number of fields.");
        }
    }

    private static void ReadReplacementHmacPlaceholder(CborReader reader)
    {
        RequireState(reader, CborReaderState.Null);
        reader.ReadNull();
    }

    private static bool ReadBoolean(CborReader reader)
    {
        RequireState(reader, CborReaderState.Boolean);
        return reader.ReadBoolean();
    }

    private static void RequireState(CborReader reader, CborReaderState expected)
    {
        if (reader.PeekState() != expected)
        {
            throw new CborContentException($"Expected CBOR {expected} in the TO2 ServiceInfo body.");
        }
    }

    public sealed record DeviceServiceInfoReady(ushort? MaxOwnerServiceInfoSize, ReadOnlyMemory<byte> Nonce);

    public sealed record DeviceServiceInfo(
        bool IsMoreServiceInfo,
        IReadOnlyList<FdoServiceInfoCodec.Entry> ServiceInfo);

    public sealed record OwnerServiceInfo(
        bool IsMoreServiceInfo,
        bool IsDone,
        IReadOnlyList<FdoServiceInfoCodec.Entry> ServiceInfo);
}
