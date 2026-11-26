// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Text;
using Fdo.Serialization;

namespace Fdo.Cryptography;

/// <summary>Reads the fields of an FDO 2.0 Ownership Voucher header.</summary>
internal sealed class FdoOwnershipVoucherHeader
{
    private FdoOwnershipVoucherHeader(
        ReadOnlyMemory<byte> contents,
        ReadOnlyMemory<byte> guid,
        ReadOnlyMemory<byte> rendezvousInfo,
        string deviceInfo,
        ReadOnlyMemory<byte> manufacturerKey,
        FdoHashValue certificateChainHash,
        bool hasLocalRendezvous,
        bool hasInvalidDns)
    {
        Contents = contents;
        Guid = guid;
        RendezvousInfo = rendezvousInfo;
        DeviceInfo = deviceInfo;
        ManufacturerKey = manufacturerKey;
        CertificateChainHash = certificateChainHash;
        HasLocalRendezvous = hasLocalRendezvous;
        HasInvalidDns = hasInvalidDns;
    }

    public ReadOnlyMemory<byte> Contents { get; }
    public ReadOnlyMemory<byte> Guid { get; }
    public ReadOnlyMemory<byte> RendezvousInfo { get; }
    public string DeviceInfo { get; }
    public ReadOnlyMemory<byte> ManufacturerKey { get; }
    public FdoHashValue CertificateChainHash { get; }
    public bool HasLocalRendezvous { get; }
    public bool HasInvalidDns { get; }

    public byte[] CreateHeaderInfo()
    {
        int deviceInfoLength = Encoding.UTF8.GetByteCount(DeviceInfo);
        byte[] result = new byte[checked(Guid.Length + deviceInfoLength)];
        Guid.Span.CopyTo(result);
        Encoding.UTF8.GetBytes(DeviceInfo, result.AsSpan(Guid.Length));
        return result;
    }

    public byte[] CreateInitialEntryHashInput(ReadOnlySpan<byte> encodedHeaderHmac)
    {
        byte[] result = new byte[checked(Contents.Length + encodedHeaderHmac.Length)];
        Contents.Span.CopyTo(result);
        encodedHeaderHmac.CopyTo(result.AsSpan(Contents.Length));
        return result;
    }

    public static FdoOwnershipVoucherHeader Decode(
        ReadOnlyMemory<byte> encodedHeaderTag,
        FdoCborCodec cbor)
    {
        ReadOnlyMemory<byte> header = cbor.ValidateAndCopy(cbor.ReadByteStringPayload(encodedHeaderTag));
        var reader = new CborReader(header, CborConformanceMode.Canonical);
        RequireArray(reader, 6);
        if (ReadUnsigned(reader) != 200)
        {
            throw new CborContentException("The paired voucher profile requires an FDO 2.0 header.");
        }

        ReadOnlyMemory<byte> guid = ReadByteString(reader);
        if (guid.Length != 16)
        {
            throw new CborContentException("The ownership voucher GUID must contain 16 bytes.");
        }

        ReadOnlyMemory<byte> rendezvous = reader.ReadEncodedValue();
        (bool hasLocal, bool hasInvalidDns) = ReadRendezvousInfo(rendezvous, cbor);
        if (reader.PeekState() != CborReaderState.TextString)
        {
            throw new CborContentException("The ownership voucher DeviceInfo must be a text string.");
        }

        string deviceInfo = reader.ReadTextString();
        ReadOnlyMemory<byte> manufacturerKey = reader.ReadEncodedValue();
        FdoHashValue certificateChainHash = FdoHashValue.Decode(reader.ReadEncodedValue());
        if (certificateChainHash.IsHmac)
        {
            throw new CborContentException("The device certificate-chain hash must be an unkeyed digest.");
        }

        reader.ReadEndArray();
        return new FdoOwnershipVoucherHeader(
            header, guid, rendezvous, deviceInfo, manufacturerKey, certificateChainHash,
            hasLocal, hasInvalidDns);
    }

    private static (bool HasLocal, bool HasInvalidDns) ReadRendezvousInfo(
        ReadOnlyMemory<byte> encoded,
        FdoCborCodec cbor)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Canonical);
        int directives = ReadNonEmptyArray(reader);
        bool hasLocal = false;
        bool hasInvalidDns = false;
        for (int i = 0; i < directives; i++)
        {
            int instructions = ReadNonEmptyArray(reader);
            bool ownerOnly = false;
            bool hasDns = false;
            string? dns = null;
            for (int j = 0; j < instructions; j++)
            {
                RequireArray(reader, 2);
                ulong variable = ReadUnsigned(reader);
                if (variable > byte.MaxValue)
                {
                    throw new CborContentException("An FDO rendezvous variable must fit in uint8.");
                }

                ReadOnlyMemory<byte> value = cbor.ValidateEmbeddedValueAndCopy(ReadByteString(reader));
                if (variable == 1)
                {
                    ownerOnly = true;
                }
                else if (variable == 5)
                {
                    var valueReader = new CborReader(value, CborConformanceMode.Strict);
                    if (hasDns || valueReader.PeekState() != CborReaderState.TextString)
                    {
                        hasInvalidDns = true;
                    }
                    else
                    {
                        dns = valueReader.ReadTextString();
                    }

                    hasDns = true;
                }

                reader.ReadEndArray();
            }

            if (!ownerOnly && string.Equals(dns, "rvserver.local", StringComparison.Ordinal))
            {
                hasLocal = true;
            }

            reader.ReadEndArray();
        }

        reader.ReadEndArray();
        return (hasLocal, hasInvalidDns);
    }

    private static int ReadNonEmptyArray(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.StartArray)
        {
            throw new CborContentException("FDO rendezvous information requires an array.");
        }

        int? count = reader.ReadStartArray();
        if (count is null or 0)
        {
            throw new CborContentException("An FDO rendezvous array must be definite and non-empty.");
        }

        return count.Value;
    }

    private static void RequireArray(CborReader reader, int count)
    {
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != count)
        {
            throw new CborContentException("The ownership voucher array has the wrong number of fields.");
        }
    }

    private static ulong ReadUnsigned(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("An ownership voucher integer must be unsigned.");
        }

        return reader.ReadUInt64();
    }

    private static ReadOnlyMemory<byte> ReadByteString(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("The ownership voucher field must be a byte string.");
        }

        return reader.ReadDefiniteLengthByteString();
    }
}
