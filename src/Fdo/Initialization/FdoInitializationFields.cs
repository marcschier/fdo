// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Fdo.Cryptography;
using Fdo.Enrollment;
using Fdo.Serialization;

namespace Fdo.Initialization;

[UnsupportedOSPlatform("browser")]
internal static class FdoInitializationFields
{
    private const int P384KeyType = 11;
    private static readonly FdoCborCodec Cbor = new();
    private static readonly FdoPublicKeyCodec Keys = new();

    public static void RequireFdo20(ReadOnlyMemory<byte> flags)
    {
        if (flags.IsEmpty || (flags.Span[0] & (byte)FdoKnownCapabilities.Fdo20) == 0)
        {
            throw new CborContentException("Device Initialize requires FDO 2.0 capabilities.");
        }
    }

    public static FdoOwnershipVoucherHeader ReadHeader(ReadOnlyMemory<byte> encodedHeaderTag)
    {
        FdoOwnershipVoucherHeader header = FdoOwnershipVoucherHeader.Decode(encodedHeaderTag, Cbor);
        if (!header.HasLocalRendezvous || header.HasInvalidDns)
        {
            throw new CborContentException(
                "Device Initialize requires a Device-applicable rvserver.local DNS entry and valid DNS instructions.");
        }

        return header;
    }

    public static int GetKeyType(ECDsa key)
    {
        using FdoPublicKeyCodec.DecodedKey decoded = Keys.Decode(Keys.Encode(key));
        return decoded.KeyType;
    }

    public static int GetKeyType(ReadOnlyMemory<byte> encodedKey)
    {
        using FdoPublicKeyCodec.DecodedKey decoded = Keys.Decode(encodedKey);
        return decoded.KeyType;
    }

    public static FdoDeviceHmacAlgorithm SelectHmac(int deviceKeyType, int manufacturerKeyType) =>
        deviceKeyType == P384KeyType || manufacturerKeyType == P384KeyType
            ? FdoDeviceHmacAlgorithm.HmacSha384
            : FdoDeviceHmacAlgorithm.HmacSha256;

    public static FdoHashAlgorithm HmacAlgorithm(FdoDeviceHmacAlgorithm algorithm) => algorithm switch
    {
        FdoDeviceHmacAlgorithm.HmacSha256 => FdoHashAlgorithm.HmacSha256,
        FdoDeviceHmacAlgorithm.HmacSha384 => FdoHashAlgorithm.HmacSha384,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "The Device HMAC algorithm is not supported."),
    };

    public static void ValidateHmacSecretHandle(
        IFdoDeviceInitializeHmacSecret secret, FdoDeviceHmacAlgorithm expectedAlgorithm)
    {
        if (secret.Algorithm != expectedAlgorithm)
        {
            throw new CryptographicException("The Device HMAC secret handle reports a different algorithm.");
        }

        FdoDeviceHmacSecretPolicy.ValidateLength(HmacAlgorithm(expectedAlgorithm), secret.KeySizeInBytes);
    }

    public static FdoHashAlgorithm DigestAlgorithm(FdoDeviceHmacAlgorithm algorithm) => algorithm switch
    {
        FdoDeviceHmacAlgorithm.HmacSha256 => FdoHashAlgorithm.Sha256,
        FdoDeviceHmacAlgorithm.HmacSha384 => FdoHashAlgorithm.Sha384,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "The Device HMAC algorithm is not supported."),
    };

    public static int GetDeviceKeyType(ReadOnlyMemory<byte> encodedChain)
    {
        IReadOnlyList<ReadOnlyMemory<byte>> certificates = new FdoX5ChainCodec().Decode(encodedChain);
        int keyType = 0;
        for (int i = 0; i < certificates.Count; i++)
        {
            using X509Certificate2 certificate = FdoDerEncoding.LoadCertificate(certificates[i]);
            if (i == 0)
            {
                FdoDerEncoding.RequireSigningKeyUsage(certificate);
                using ECDsa key = certificate.GetECDsaPublicKey()
                    ?? throw new CryptographicException("The Device certificate must contain an ECDSA public key.");
                keyType = GetKeyType(key);
            }
        }

        return keyType;
    }

    public static (ReadOnlyMemory<byte> HeaderTag, ReadOnlyMemory<byte> Chain) CreateProposal(
        string deviceInfo,
        AsymmetricAlgorithm manufacturerKey,
        IReadOnlyList<ReadOnlyMemory<byte>> deviceCertificates,
        ReadOnlyMemory<byte>? encodedRendezvousInfo,
        bool restrictedRsa = false)
    {
        ArgumentNullException.ThrowIfNull(deviceInfo);
        ArgumentNullException.ThrowIfNull(manufacturerKey);
        ArgumentNullException.ThrowIfNull(deviceCertificates);
        if (Encoding.UTF8.GetByteCount(deviceInfo) > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(deviceInfo));
        }

        ReadOnlyMemory<byte> rendezvous = encodedRendezvousInfo is ReadOnlyMemory<byte> supplied
            ? Cbor.ValidateAndCopy(supplied)
            : CreateLocalRendezvous();
        ReadOnlyMemory<byte> chain = new FdoX5ChainCodec().Encode(deviceCertificates);
        int deviceKeyType = GetDeviceKeyType(chain);
        ReadOnlyMemory<byte> encodedKey = manufacturerKey switch
        {
            ECDsa ec => Keys.Encode(ec),
            RSA rsa => Keys.EncodeRsa(rsa, restrictedRsa),
            _ => throw new NotSupportedException("The manufacturer key must be a supported ECDSA or RSA key."),
        };
        int manufacturerKeyType = GetKeyType(encodedKey);
        FdoDeviceHmacAlgorithm hmac = SelectHmac(deviceKeyType, manufacturerKeyType);
        FdoHashValue chainHash = new FdoCertificateChainHash().Compute(DigestAlgorithm(hmac), chain);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(6);
        writer.WriteInt32(200);
        writer.WriteByteString(RandomNumberGenerator.GetBytes(16));
        writer.WriteEncodedValue(rendezvous.Span);
        writer.WriteTextString(deviceInfo);
        writer.WriteEncodedValue(encodedKey.Span);
        writer.WriteEncodedValue(chainHash.Encode().Span);
        writer.WriteEndArray();
        ReadOnlyMemory<byte> header = Cbor.ValidateAndCopy(writer.Encode());
        var wrapper = new CborWriter(CborConformanceMode.Canonical);
        wrapper.WriteByteString(header.Span);
        ReadOnlyMemory<byte> headerTag = Cbor.ValidateAndCopy(wrapper.Encode());
        _ = ReadHeader(headerTag);
        return (headerTag, chain);
    }

    public static ReadOnlyMemory<byte> CreateVoucher(
        ReadOnlyMemory<byte> encodedHeaderTag,
        FdoHashValue hmac,
        ReadOnlyMemory<byte> encodedChain)
    {
        ReadOnlyMemory<byte> encodedHmac = hmac.Encode();
        if (4L + encodedHeaderTag.Length + encodedHmac.Length + encodedChain.Length > ushort.MaxValue)
        {
            throw new CborContentException("The zero-entry Ownership Voucher exceeds the byte limit.");
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(5);
        writer.WriteInt32(200);
        writer.WriteEncodedValue(encodedHeaderTag.Span);
        writer.WriteEncodedValue(encodedHmac.Span);
        writer.WriteEncodedValue(encodedChain.Span);
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndArray();
        return Cbor.ValidateAndCopy(writer.Encode());
    }

    public static ReadOnlyMemory<byte> CreateReplacementHeader(
        ReadOnlyMemory<byte> encodedPreviousHeaderTag,
        ReadOnlyMemory<byte> guid,
        ReadOnlyMemory<byte> rendezvousInfo,
        ReadOnlyMemory<byte> ownerKey)
    {
        FdoOwnershipVoucherHeader previous = ReadHeader(encodedPreviousHeaderTag);
        if (guid.Length != 16 || CryptographicOperations.FixedTimeEquals(previous.Guid.Span, guid.Span))
        {
            throw new CborContentException("The replacement GUID must contain 16 bytes and differ from the current GUID.");
        }

        ReadOnlyMemory<byte> rendezvous = Cbor.ValidateAndCopy(rendezvousInfo);
        ReadOnlyMemory<byte> key = Cbor.ValidateAndCopy(ownerKey);
        using FdoPublicKeyCodec.DecodedKey decoded = Keys.Decode(key);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(6);
        writer.WriteInt32(200);
        writer.WriteByteString(guid.Span);
        writer.WriteEncodedValue(rendezvous.Span);
        writer.WriteTextString(previous.DeviceInfo);
        writer.WriteEncodedValue(key.Span);
        writer.WriteEncodedValue(previous.CertificateChainHash.Encode().Span);
        writer.WriteEndArray();
        ReadOnlyMemory<byte> header = Cbor.ValidateAndCopy(writer.Encode());
        var wrapper = new CborWriter(CborConformanceMode.Canonical);
        wrapper.WriteByteString(header.Span);
        ReadOnlyMemory<byte> tag = Cbor.ValidateAndCopy(wrapper.Encode());
        _ = ReadHeader(tag);
        return tag;
    }

    private static ReadOnlyMemory<byte> CreateLocalRendezvous()
    {
        var dns = new CborWriter(CborConformanceMode.Canonical);
        dns.WriteTextString("rvserver.local");
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(1);
        writer.WriteStartArray(1);
        writer.WriteStartArray(2);
        writer.WriteInt32(5);
        writer.WriteByteString(dns.Encode());
        writer.WriteEndArray();
        writer.WriteEndArray();
        writer.WriteEndArray();
        return writer.Encode();
    }
}
