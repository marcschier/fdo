// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Fdo.Cryptography;

namespace Fdo.Serialization;

/// <summary>
/// Frames Device Initialize messages. It does not authenticate the
/// manufacturing station, validate voucher fields, or persist credentials.
/// </summary>
internal sealed class FdoDeviceInitializeCodec
{
    private static readonly byte[] EncodedNull = [0xF6];
    private readonly FdoCborCodec _cbor;
    private readonly int _maxEncodedBytes;
    private readonly int _maxItems;

    public FdoDeviceInitializeCodec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _maxEncodedBytes = maxEncodedBytes;
        _maxItems = maxItems;
    }

    public AppStart DecodeAppStart(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 3);
        FdoCapabilityFields.Parsed fields = FdoCapabilityFields.Read(reader);
        ReadOnlyMemory<byte>? deviceMfgInfo = ReadDeviceMfgInfo(reader);
        reader.ReadEndArray();
        return new AppStart(fields.Flags, fields.Vendors, deviceMfgInfo);
    }

    public ReadOnlyMemory<byte> EncodeAppStart(AppStart message)
    {
        ArgumentNullException.ThrowIfNull(message);
        ReadOnlyMemory<byte> deviceMfgInfo = message.EncodedDeviceMfgInfo is ReadOnlyMemory<byte> value
            ? _cbor.ValidateAndCopy(value)
            : EncodedNull;
        long encodedInfoSize = (long)FdoCborCodec.GetHeaderSize((ulong)deviceMfgInfo.Length) +
            deviceMfgInfo.Length;
        FdoCapabilityFields.Prepared fields = FdoCapabilityFields.Prepare(
            message.CapabilityFlags, message.VendorCapabilities, _maxEncodedBytes, _maxItems,
            additionalItems: 1, additionalEncodedBytes: encodedInfoSize);

        var writer = new CborWriter(CborConformanceMode.Canonical, initialCapacity: fields.EncodedSize);
        writer.WriteStartArray(3);
        FdoCapabilityFields.Write(writer, fields);
        writer.WriteByteString(deviceMfgInfo.Span);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    public SetCredentials DecodeSetCredentials(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 3);
        FdoCapabilityFields.Parsed fields = FdoCapabilityFields.Read(reader);
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("DI.SetCredentials must wrap OVHeader in a byte string.");
        }

        ReadOnlyMemory<byte> headerTag = ValidateHeaderTag(reader.ReadEncodedValue());
        reader.ReadEndArray();
        return new SetCredentials(fields.Flags, fields.Vendors, headerTag);
    }

    public ReadOnlyMemory<byte> EncodeSetCredentials(SetCredentials message)
    {
        ArgumentNullException.ThrowIfNull(message);
        ReadOnlyMemory<byte> headerTag = ValidateHeaderTag(message.EncodedHeaderTag);
        FdoCapabilityFields.Prepared fields = FdoCapabilityFields.Prepare(
            message.CapabilityFlags, message.VendorCapabilities, _maxEncodedBytes, _maxItems,
            additionalItems: 1, additionalEncodedBytes: headerTag.Length);

        var writer = new CborWriter(CborConformanceMode.Canonical, initialCapacity: fields.EncodedSize);
        writer.WriteStartArray(3);
        FdoCapabilityFields.Write(writer, fields);
        writer.WriteEncodedValue(headerTag.Span);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    /// <summary>
    /// Computes the provisionally selected DI HMAC over OVHeader contents.
    /// The caller must validate the header and protect the device secret.
    /// </summary>
    public FdoHashValue ComputeSetHmac(
        FdoHashAlgorithm algorithm,
        ReadOnlySpan<byte> deviceHmacSecret,
        SetCredentials credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        FdoDeviceHmacSecretPolicy.ValidateLength(algorithm, deviceHmacSecret.Length);

        ReadOnlyMemory<byte> headerTag = ValidateHeaderTag(credentials.EncodedHeaderTag);
        return FdoOwnershipVoucherHeaderHmac.Compute(algorithm, deviceHmacSecret, headerTag, _cbor);
    }

    public FdoHashValue DecodeSetHmac(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 1);
        FdoHashValue hmac = FdoHashValue.Decode(reader.ReadEncodedValue());
        if (!hmac.IsHmac)
        {
            throw new CborContentException("DI.SetHMAC must contain an HMAC algorithm.");
        }

        reader.ReadEndArray();
        return hmac;
    }

    public ReadOnlyMemory<byte> EncodeSetHmac(FdoHashValue hmac)
    {
        ArgumentNullException.ThrowIfNull(hmac);
        if (!hmac.IsHmac)
        {
            throw new ArgumentException("DI.SetHMAC must contain an HMAC algorithm.", nameof(hmac));
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(1);
        writer.WriteEncodedValue(hmac.Encode().Span);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    public void DecodeDone(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 0);
        reader.ReadEndArray();
    }

    public ReadOnlyMemory<byte> EncodeDone() => _cbor.ValidateAndCopy(new byte[] { 0x80 });

    private ReadOnlyMemory<byte>? ReadDeviceMfgInfo(CborReader reader)
    {
        if (reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
            return null;
        }

        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("DeviceMfgInfo must be a byte string or bare null.");
        }

        ReadOnlyMemory<byte> value = _cbor.ValidateAndCopy(reader.ReadDefiniteLengthByteString());
        if (value.Span.SequenceEqual(EncodedNull))
        {
            return null;
        }

        return value;
    }

    private ReadOnlyMemory<byte> ValidateHeaderTag(ReadOnlyMemory<byte> encodedHeaderTag)
    {
        ReadOnlyMemory<byte> copy = _cbor.ValidateAndCopy(encodedHeaderTag);
        var wrapper = new CborReader(copy, CborConformanceMode.Canonical);
        if (wrapper.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("OVHeader must be wrapped in a byte string.");
        }

        ReadOnlyMemory<byte> header = _cbor.ValidateAndCopy(wrapper.ReadDefiniteLengthByteString());
        var reader = new CborReader(header, CborConformanceMode.Canonical);
        RequireArray(reader, 6);
        return copy;
    }

    private static void RequireArray(CborReader reader, int count)
    {
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != count)
        {
            throw new CborContentException("The DI message has the wrong array shape.");
        }
    }

    /// <summary>
    /// An absent manufacturing value is null. A present value is one encoded
    /// CBOR item without its surrounding byte string.
    /// </summary>
    public sealed record AppStart(
        ReadOnlyMemory<byte> CapabilityFlags,
        IReadOnlyList<string> VendorCapabilities,
        ReadOnlyMemory<byte>? EncodedDeviceMfgInfo);

    /// <summary>An unverified voucher header, including its byte-string wrapper.</summary>
    public sealed record SetCredentials(
        ReadOnlyMemory<byte> CapabilityFlags,
        IReadOnlyList<string> VendorCapabilities,
        ReadOnlyMemory<byte> EncodedHeaderTag);
}
