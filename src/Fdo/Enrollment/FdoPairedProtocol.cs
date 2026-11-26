// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Fdo.Cryptography;
using Fdo.Serialization;
using Fdo.ServiceInfo;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.Enrollment;

[UnsupportedOSPlatform("browser")]
internal static class FdoPairedProtocol
{
    public static FdoKeyExchangeSuite MapKeyExchangeSuite(FdoPairedKeyExchangeSuite suite) => suite switch
    {
        FdoPairedKeyExchangeSuite.Ecdh256 => FdoKeyExchangeSuite.Ecdh256,
        FdoPairedKeyExchangeSuite.Ecdh384 => FdoKeyExchangeSuite.Ecdh384,
        FdoPairedKeyExchangeSuite.DhkexId14 => FdoKeyExchangeSuite.DhkexId14,
        FdoPairedKeyExchangeSuite.DhkexId15 => FdoKeyExchangeSuite.DhkexId15,
        FdoPairedKeyExchangeSuite.Asymkex2048 => FdoKeyExchangeSuite.Asymkex2048,
        FdoPairedKeyExchangeSuite.Asymkex3072 => FdoKeyExchangeSuite.Asymkex3072,
        _ => throw new ArgumentOutOfRangeException(nameof(suite), suite, "The key-exchange suite is not supported."),
    };

    public static void RequireExchangeOptIn(FdoKeyExchangeSuite suite, bool useDh, bool useAsym)
    {
        if (FdoKeyExchangeSuites.IsDh(suite))
        {
            if (!useDh)
            {
                throw new InvalidOperationException("The paired DH encoding requires explicit opt-in.");
            }

            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException("Paired finite-field DH currently requires OpenSSL 3 on Linux.");
            }
        }
        else if (FdoKeyExchangeSuites.IsAsym(suite) && !useAsym)
        {
            throw new InvalidOperationException("Paired ASYMKEX requires explicit opt-in.");
        }
    }

    public static IFdoPairedKeyExchange CreateDeviceExchange(
        FdoKeyExchangeSuite suite, ReadOnlyMemory<byte> provisionedOwnerKey) => suite switch
        {
            FdoKeyExchangeSuite.Ecdh256 or FdoKeyExchangeSuite.Ecdh384 =>
                FdoEcdhKeyExchange.Create(suite, FdoEcdhParty.Device),
            FdoKeyExchangeSuite.DhkexId14 => FdoDhKeyExchange.Create(FdoDhGroup.DhkexId14),
            FdoKeyExchangeSuite.DhkexId15 => FdoDhKeyExchange.Create(FdoDhGroup.DhkexId15),
            FdoKeyExchangeSuite.Asymkex2048 or FdoKeyExchangeSuite.Asymkex3072 =>
                CreateAsymDeviceExchange(suite, provisionedOwnerKey),
            _ => throw new ArgumentOutOfRangeException(nameof(suite)),
        };

    public static IFdoPairedKeyExchange CreateOwnerExchange(
        FdoKeyExchangeSuite suite, AsymmetricAlgorithm ownerKey) => suite switch
        {
            FdoKeyExchangeSuite.Ecdh256 or FdoKeyExchangeSuite.Ecdh384 =>
                FdoEcdhKeyExchange.Create(suite, FdoEcdhParty.Owner),
            FdoKeyExchangeSuite.DhkexId14 => FdoDhKeyExchange.Create(FdoDhGroup.DhkexId14),
            FdoKeyExchangeSuite.DhkexId15 => FdoDhKeyExchange.Create(FdoDhGroup.DhkexId15),
            FdoKeyExchangeSuite.Asymkex2048 or FdoKeyExchangeSuite.Asymkex3072 =>
                FdoAsymKeyExchange.Create(
                    suite == FdoKeyExchangeSuite.Asymkex2048 ? FdoAsymSuite.Asym2048 : FdoAsymSuite.Asym3072,
                    FdoAsymParty.Owner,
                    ownerKey as RSA ?? throw new CryptographicException("Paired ASYMKEX requires an RSA Owner key.")),
            _ => throw new ArgumentOutOfRangeException(nameof(suite)),
        };

    private static FdoAsymKeyExchange CreateAsymDeviceExchange(
        FdoKeyExchangeSuite suite, ReadOnlyMemory<byte> provisionedOwnerKey)
    {
        using FdoPublicKeyCodec.DecodedKey owner = new FdoPublicKeyCodec().Decode(provisionedOwnerKey);
        FdoTo2OwnerProofCodec.RequireOwnerSuite(suite, owner);
        return FdoAsymKeyExchange.Create(
            suite == FdoKeyExchangeSuite.Asymkex2048 ? FdoAsymSuite.Asym2048 : FdoAsymSuite.Asym3072,
            FdoAsymParty.Device, owner.RsaPublicKey);
    }

    public static void RequireProvisionedAsymOwner(
        ReadOnlyMemory<byte> provisionedOwnerKey, ReadOnlyMemory<byte> authenticatedOwnerKey)
    {
        var codec = new FdoPublicKeyCodec();
        using FdoPublicKeyCodec.DecodedKey expected = codec.Decode(provisionedOwnerKey);
        using FdoPublicKeyCodec.DecodedKey actual = codec.Decode(authenticatedOwnerKey);
        if (!expected.HasSamePublicKey(actual))
        {
            throw new CryptographicException("The provisioned ASYMKEX Owner key does not match the authenticated voucher Owner.");
        }
    }

    public static FdoCoseAeadAlgorithm MapCipherSuite(FdoPairedCipherSuite cipher) => cipher switch
    {
        FdoPairedCipherSuite.A128Gcm => FdoCoseAeadAlgorithm.A128Gcm,
        FdoPairedCipherSuite.A256Gcm => FdoCoseAeadAlgorithm.A256Gcm,
        FdoPairedCipherSuite.AesCcm16_128_128 => FdoCoseAeadAlgorithm.AesCcm16_128_128,
        FdoPairedCipherSuite.AesCcm16_128_256 => FdoCoseAeadAlgorithm.AesCcm16_128_256,
        FdoPairedCipherSuite.AesCcm64_128_128 => FdoCoseAeadAlgorithm.AesCcm64_128_128,
        FdoPairedCipherSuite.AesCcm64_128_256 => FdoCoseAeadAlgorithm.AesCcm64_128_256,
        FdoPairedCipherSuite.AesCtr128HmacSha256 => FdoCoseAeadAlgorithm.AesCtr128HmacSha256,
        FdoPairedCipherSuite.AesCtr256HmacSha384 => FdoCoseAeadAlgorithm.AesCtr256HmacSha384,
        FdoPairedCipherSuite.AesCbc128HmacSha256 => FdoCoseAeadAlgorithm.AesCbc128HmacSha256,
        FdoPairedCipherSuite.AesCbc256HmacSha384 => FdoCoseAeadAlgorithm.AesCbc256HmacSha384,
        _ => throw new ArgumentOutOfRangeException(nameof(cipher), cipher, "The cipher suite is not supported."),
    };

    /// <summary>
    /// Derives the TO2 session key. AEAD suites receive one SEVK; encrypt-then-MAC
    /// suites receive SVK followed by SEK, derived with the suite's PRF.
    /// </summary>
    public static byte[] DeriveSessionKey(
        IFdoPairedKeyExchange exchange, ReadOnlyMemory<byte> peerParameter, FdoCoseAeadAlgorithm cipher)
    {
        int length = FdoTo2CipherSuites.GetSessionKeyLength(cipher);
        byte[] shared = exchange.DeriveSharedSecret(peerParameter.Span, out byte[] contextRand);
        var key = new byte[length];
        bool completed = false;
        try
        {
            if (FdoTo2CipherSuites.IsEncryptThenMac(cipher))
            {
                FdoTo2CipherSuites.EncryptThenMacParameters parameters =
                    FdoTo2CipherSuites.GetEncryptThenMacParameters(cipher);
                FdoKeyDerivation.DeriveEncryptThenMac(
                    shared, contextRand, parameters.Hash,
                    key.AsSpan(0, parameters.VerificationKeySize), key.AsSpan(parameters.VerificationKeySize));
            }
            else
            {
                FdoKeyDerivation.Derive(shared, contextRand, FdoTo2CipherSuites.GetKdfHash(cipher), key);
            }

            completed = true;
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
            CryptographicOperations.ZeroMemory(contextRand);
            if (!completed)
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    public static ReadOnlyMemory<byte> EncodeEntryRequest(int index)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(1);
        writer.WriteInt32(index);
        writer.WriteEndArray();
        return writer.Encode();
    }

    public static int DecodeEntryRequest(FdoCborCodec cbor, ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 1);
        int index = ReadEntryIndex(reader);
        reader.ReadEndArray();
        return index;
    }

    public static ReadOnlyMemory<byte> EncodeEntryResponse(int index, ReadOnlyMemory<byte> entry)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(2);
        writer.WriteInt32(index);
        writer.WriteEncodedValue(entry.Span);
        writer.WriteEndArray();
        return writer.Encode();
    }

    public static ReadOnlyMemory<byte> DecodeEntryResponse(
        FdoCborCodec cbor, ReadOnlyMemory<byte> encoded, int expectedIndex)
    {
        var reader = new CborReader(cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 2);
        if (ReadEntryIndex(reader) != expectedIndex)
        {
            throw new CborContentException("The voucher entry response has the wrong index.");
        }

        ReadOnlyMemory<byte> entry = reader.ReadEncodedValue();
        reader.ReadEndArray();
        return entry;
    }

    public static IReadOnlyList<Entry> EncodeInventory(FdoDeviceMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata.Os);
        ArgumentNullException.ThrowIfNull(metadata.Architecture);
        ArgumentNullException.ThrowIfNull(metadata.Version);
        ArgumentNullException.ThrowIfNull(metadata.Device);
        ArgumentNullException.ThrowIfNull(metadata.Separator);
        ArgumentNullException.ThrowIfNull(metadata.BinaryFormats);
        var modules = new CborWriter(CborConformanceMode.Canonical);
        modules.WriteStartArray(4);
        modules.WriteInt32(0);
        modules.WriteInt32(2);
        modules.WriteTextString("devmod");
        modules.WriteTextString("fdo.csr");
        modules.WriteEndArray();
        return
        [
            new Entry("devmod:active", new byte[] { 0xF5 }),
            TextEntry("devmod:os", metadata.Os),
            TextEntry("devmod:arch", metadata.Architecture),
            TextEntry("devmod:version", metadata.Version),
            TextEntry("devmod:device", metadata.Device),
            TextEntry("devmod:sep", metadata.Separator),
            TextEntry("devmod:bin", metadata.BinaryFormats),
            new Entry("devmod:nummodules", new byte[] { 0x02 }),
            new Entry("devmod:modules", modules.Encode()),
        ];
    }

    public static void ValidateInventory(FdoTo2ServiceInfoCodec.DeviceServiceInfo message)
    {
        if (message.IsMoreServiceInfo || message.ServiceInfo.Count != 9)
        {
            throw new CborContentException("The paired profile requires its complete devmod inventory once assembled.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (Entry entry in message.ServiceInfo)
        {
            if (!seen.Add(entry.Key))
            {
                throw new CborContentException("The devmod inventory contains a duplicate field.");
            }

            var reader = new CborReader(entry.EncodedValue, CborConformanceMode.Strict);
            switch (entry.Key)
            {
                case "devmod:active":
                    if (reader.PeekState() != CborReaderState.Boolean || !reader.ReadBoolean())
                    {
                        throw new CborContentException("The devmod module must be active.");
                    }

                    break;
                case "devmod:os":
                case "devmod:arch":
                case "devmod:version":
                case "devmod:device":
                case "devmod:sep":
                case "devmod:bin":
                    if (reader.PeekState() != CborReaderState.TextString)
                    {
                        throw new CborContentException("A devmod metadata value must be text.");
                    }

                    reader.ReadTextString();
                    break;
                case "devmod:nummodules":
                    if (reader.PeekState() != CborReaderState.UnsignedInteger || reader.ReadUInt64() != 2)
                    {
                        throw new CborContentException("The paired Device must advertise two modules.");
                    }

                    break;
                case "devmod:modules":
                    RequireInventoryModules(reader);
                    break;
                default:
                    throw new CborContentException("The paired devmod inventory contains an unsupported field.");
            }

            if (reader.BytesRemaining != 0)
            {
                throw new CborContentException("A devmod value contains trailing data.");
            }
        }
    }

    public static (byte[] Request, bool IsReenrollment, bool IsServerKeyGeneration) DecodeEnrollmentRequest(
        FdoTo2ServiceInfoCodec.DeviceServiceInfo message,
        FdoCsrBase64TextCodec codec,
        bool includesActivation = true)
    {
        int requestIndex = includesActivation ? 1 : 0;
        if (message.IsMoreServiceInfo || message.ServiceInfo.Count != requestIndex + 1 ||
            (includesActivation && !IsActive(message.ServiceInfo[0])))
        {
            throw new CborContentException("The Device did not send an activated enrollment request.");
        }

        Entry entry = message.ServiceInfo[requestIndex];
        (bool isReenrollment, bool isServerKeyGeneration) = entry.Key switch
        {
            "fdo.csr:simpleenroll-req" => (false, false),
            "fdo.csr:simplereenroll-req" => (true, false),
            "fdo.csr:serverkeygen-req" => (false, true),
            _ => throw new CborContentException("The Device sent an unsupported enrollment request."),
        };
        return (codec.DecodeRequest(entry, isReenrollment, isServerKeyGeneration),
            isReenrollment, isServerKeyGeneration);
    }

    public static bool IsCaCertificatesRequest(FdoTo2ServiceInfoCodec.DeviceServiceInfo message) =>
        message.ServiceInfo.Count == 2 && message.ServiceInfo[1].Key == "fdo.csr:cacerts-req";

    public static ulong DecodeCaCertificatesRequest(FdoTo2ServiceInfoCodec.DeviceServiceInfo message)
    {
        if (message.IsMoreServiceInfo || message.ServiceInfo.Count != 2 ||
            !IsActive(message.ServiceInfo[0]))
        {
            throw new CborContentException("The Device did not activate and request CA certificates.");
        }

        return FdoCsrCaCertificatesCodec.DecodeRequest(message.ServiceInfo[1]);
    }

    public static bool IsCsrAttributesRequest(
        FdoTo2ServiceInfoCodec.DeviceServiceInfo message, bool includesActivation)
    {
        int requestIndex = includesActivation ? 1 : 0;
        return message.ServiceInfo.Count == requestIndex + 1 &&
            message.ServiceInfo[requestIndex].Key == "fdo.csr:csrattrs-req";
    }

    public static void ValidateCsrAttributesRequest(
        FdoTo2ServiceInfoCodec.DeviceServiceInfo message, bool includesActivation)
    {
        int requestIndex = includesActivation ? 1 : 0;
        if (message.IsMoreServiceInfo || message.ServiceInfo.Count != requestIndex + 1 ||
            (includesActivation && !IsActive(message.ServiceInfo[0])))
        {
            throw new CborContentException("The Device did not send an activated CSR attributes request.");
        }

        FdoCsrAttributesRequestCodec.Validate(message.ServiceInfo[requestIndex]);
    }

    private static bool IsActive(Entry entry) =>
        entry.Key == "fdo.csr:active" && entry.EncodedValue.Span.SequenceEqual(new byte[] { 0xF5 });

    private static Entry TextEntry(string key, string value)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString(value);
        return new Entry(key, writer.Encode());
    }

    private static int ReadEntryIndex(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("The voucher entry index must be uint8.");
        }

        ulong index = reader.ReadUInt64();
        return index <= byte.MaxValue
            ? (int)index
            : throw new CborContentException("The voucher entry index must be uint8.");
    }

    private static void RequireArray(CborReader reader, int count)
    {
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != count)
        {
            throw new CborContentException("The voucher entry message has the wrong shape.");
        }
    }

    private static void RequireInventoryModules(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != 4 ||
            reader.PeekState() != CborReaderState.UnsignedInteger || reader.ReadUInt64() != 0 ||
            reader.PeekState() != CborReaderState.UnsignedInteger || reader.ReadUInt64() != 2 ||
            reader.PeekState() != CborReaderState.TextString)
        {
            throw new CborContentException("The paired module inventory has an invalid range.");
        }

        string first = reader.ReadTextString();
        if (reader.PeekState() != CborReaderState.TextString)
        {
            throw new CborContentException("The paired module inventory requires two names.");
        }

        string second = reader.ReadTextString();
        reader.ReadEndArray();
        if (!((first == "devmod" && second == "fdo.csr") ||
            (first == "fdo.csr" && second == "devmod")))
        {
            throw new CborContentException("The paired Device must advertise devmod and fdo.csr.");
        }
    }
}
