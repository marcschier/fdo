using System;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Fdo.Cryptography;

namespace Fdo.Serialization;

/// <summary>
/// Signs and checks the paired FDO 2.0 ProveDevice20. A valid
/// signature does not establish Device certificate or supply-chain trust.
/// Only the three required EAT claims and an absent MAROEPrefix are supported.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoTo2DeviceProofCodec
{
    private const int NonceLength = 16;
    private const int UeidLength = 17;
    private const int EatNonce = 10;
    private const int EatUeid = 256;
    private const int EatFdo = -257;
    private readonly FdoCborCodec _cbor;
    private readonly FdoPublicKeyCodec _keys;
    private readonly FdoCoseSign1Codec _signatures;
    private readonly FdoTo2InitialCodec _initial;

    public FdoTo2DeviceProofCodec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _keys = new FdoPublicKeyCodec(maxEncodedBytes, maxDepth, maxItems);
        _signatures = new FdoCoseSign1Codec(maxEncodedBytes, maxDepth, maxItems);
        _initial = new FdoTo2InitialCodec(maxEncodedBytes, maxDepth, maxItems);
    }

    /// <summary>
    /// Signs a proof of the exact checked probe and acknowledgement. The
    /// caller supplies a fresh Owner-proof nonce and a one-use Device exchange
    /// parameter, and must retain the matching private exchange key.
    /// </summary>
    public ReadOnlyMemory<byte> Sign(
        ReadOnlyMemory<byte> sentProbe,
        ReadOnlyMemory<byte> receivedAcknowledgement,
        FdoKeyExchangeSuite exchange,
        FdoCoseAeadAlgorithm cipher,
        ReadOnlyMemory<byte> deviceParameter,
        ReadOnlyMemory<byte> ownerNonce,
        ECDsa devicePrivateKey)
    {
        ArgumentNullException.ThrowIfNull(devicePrivateKey);
        ReadOnlyMemory<byte> probe = _cbor.ValidateAndCopy(sentProbe);
        ReadOnlyMemory<byte> acknowledgement = _cbor.ValidateAndCopy(receivedAcknowledgement);
        FdoTo2InitialCodec.CheckedAcknowledgement checkedAck = _initial.CheckAcknowledgement(probe, acknowledgement);
        _initial.RequireOfferedSuites(acknowledgement, exchange, cipher);
        FdoKeyExchangeSuites.RequireParameterShape(exchange, isOwner: false, deviceParameter.Span);
        byte[] parameter = deviceParameter.ToArray();
        byte[] nonce = CopyNonce(ownerNonce);
        FdoKeyExchangeSuites.RequireParameterShape(exchange, isOwner: false, parameter);
        using FdoPublicKeyCodec.DecodedKey deviceKey = _keys.Decode(_keys.Encode(devicePrivateKey));

        byte[] ueid = new byte[UeidLength];
        ueid[0] = 1;
        checkedAck.Message.Guid.Span.CopyTo(ueid.AsSpan(1));
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(EatNonce);
        writer.WriteByteString(checkedAck.Message.NonceTo2ProveDv.Span);
        writer.WriteInt32(EatUeid);
        writer.WriteByteString(ueid);
        writer.WriteInt32(EatFdo);
        writer.WriteStartArray(5);
        writer.WriteTextString(FdoKeyExchangeSuites.GetName(exchange));
        writer.WriteInt32((int)cipher);
        writer.WriteByteString(parameter);
        writer.WriteByteString(nonce);
        writer.WriteEncodedValue(checkedAck.HashPrev2.Encode().Span);
        writer.WriteEndArray();
        writer.WriteEndMap();
        return _signatures.Sign(
            FdoSignatureOperation.TO2ProveDevice, deviceKey.Algorithm, devicePrivateKey, writer.Encode());
    }

    /// <summary>
    /// Verifies the Device signature, GUID, nonce, selected suites, and both
    /// transcript hashes. The caller must establish the supplied key's
    /// certificate and supply-chain trust and bind it to this same run.
    /// </summary>
    public DeviceProof Verify(
        ReadOnlyMemory<byte> receivedProbe,
        ReadOnlyMemory<byte> sentAcknowledgement,
        ReadOnlyMemory<byte> encodedProof,
        ECDsa devicePublicKey)
    {
        ArgumentNullException.ThrowIfNull(devicePublicKey);
        ReadOnlyMemory<byte> probe = _cbor.ValidateAndCopy(receivedProbe);
        ReadOnlyMemory<byte> acknowledgement = _cbor.ValidateAndCopy(sentAcknowledgement);
        FdoTo2InitialCodec.CheckedAcknowledgement checkedAck = _initial.CheckAcknowledgement(probe, acknowledgement);
        using FdoPublicKeyCodec.DecodedKey deviceKey = _keys.Decode(_keys.Encode(devicePublicKey));
        ReadOnlyMemory<byte> payload = deviceKey.VerifySignature(
            _signatures, FdoSignatureOperation.TO2ProveDevice, encodedProof);

        var reader = new CborReader(payload, CborConformanceMode.Strict);
        if (reader.PeekState() != CborReaderState.StartMap || reader.ReadStartMap() != 3)
        {
            throw new CborContentException("The paired Device EAT requires exactly three claims.");
        }

        ReadOnlyMemory<byte> nonce = default;
        ReadOnlyMemory<byte> ueid = default;
        ProofFields? fields = null;
        for (int i = 0; i < 3; i++)
        {
            long claim = ReadInteger(reader);
            switch (claim)
            {
                case EatNonce:
                    nonce = ReadBytes(reader, NonceLength);
                    break;
                case EatUeid:
                    ueid = ReadBytes(reader, UeidLength);
                    break;
                case EatFdo:
                    fields = ReadProofFields(reader);
                    break;
                default:
                    throw new NotSupportedException("Additional Device EAT claims are not supported.");
            }
        }

        reader.ReadEndMap();
        if (nonce.IsEmpty || ueid.IsEmpty || fields is null)
        {
            throw new CborContentException("The Device EAT is missing a required claim.");
        }

        Span<byte> expectedUeid = stackalloc byte[UeidLength];
        expectedUeid[0] = 1;
        checkedAck.Message.Guid.Span.CopyTo(expectedUeid[1..]);
        if (!CryptographicOperations.FixedTimeEquals(nonce.Span, checkedAck.Message.NonceTo2ProveDv.Span) ||
            !CryptographicOperations.FixedTimeEquals(ueid.Span, expectedUeid))
        {
            throw new CryptographicException("The Device EAT nonce or GUID does not match the TO2 transcript.");
        }

        _initial.VerifyAcknowledgementHash(acknowledgement, fields.HashPrev2);
        _initial.RequireOfferedSuites(acknowledgement, fields.Exchange, fields.Cipher);
        FdoKeyExchangeSuites.RequireParameterShape(fields.Exchange, isOwner: false, fields.DeviceParameter.Span);
        return new DeviceProof(
            checkedAck.Message.Guid, fields.Exchange, fields.Cipher,
            fields.DeviceParameter, fields.OwnerNonce);
    }

    private static ProofFields ReadProofFields(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != 5)
        {
            throw new CborContentException("The TO2 Device proof has the wrong payload shape.");
        }

        if (reader.PeekState() != CborReaderState.TextString)
        {
            throw new CborContentException("The TO2 key-exchange suite must be text.");
        }

        FdoKeyExchangeSuite exchange = FdoKeyExchangeSuites.ParseName(reader.ReadTextString());
        FdoCoseAeadAlgorithm cipher = ReadInteger(reader) switch
        {
            1 => FdoCoseAeadAlgorithm.A128Gcm,
            3 => FdoCoseAeadAlgorithm.A256Gcm,
            30 => FdoCoseAeadAlgorithm.AesCcm16_128_128,
            31 => FdoCoseAeadAlgorithm.AesCcm16_128_256,
            32 => FdoCoseAeadAlgorithm.AesCcm64_128_128,
            33 => FdoCoseAeadAlgorithm.AesCcm64_128_256,
            -17760703 => FdoCoseAeadAlgorithm.AesCbc128HmacSha256,
            -17760704 => FdoCoseAeadAlgorithm.AesCtr128HmacSha256,
            -17760705 => FdoCoseAeadAlgorithm.AesCbc256HmacSha384,
            -17760706 => FdoCoseAeadAlgorithm.AesCtr256HmacSha384,
            _ => throw new NotSupportedException("The paired TO2 cipher suite is not supported."),
        };
        ReadOnlyMemory<byte> parameter = ReadBytes(reader);
        ReadOnlyMemory<byte> ownerNonce = ReadBytes(reader, NonceLength);
        FdoHashValue hashPrev2 = FdoHashValue.Decode(reader.ReadEncodedValue());
        reader.ReadEndArray();
        return new ProofFields(exchange, cipher, parameter, ownerNonce, hashPrev2);
    }

    private static byte[] CopyNonce(ReadOnlyMemory<byte> nonce)
    {
        if (nonce.Length != NonceLength)
        {
            throw new ArgumentException("The Owner-proof nonce must contain exactly 16 bytes.", nameof(nonce));
        }

        return nonce.ToArray();
    }

    private static long ReadInteger(CborReader reader) => reader.PeekState() switch
    {
        CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger => reader.ReadInt64(),
        _ => throw new CborContentException("The Device EAT claim or suite must be an integer."),
    };

    private static ReadOnlyMemory<byte> ReadBytes(CborReader reader, int? length = null)
    {
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("The Device EAT field must be a byte string.");
        }

        ReadOnlyMemory<byte> value = reader.ReadDefiniteLengthByteString();
        if (length is int expected && value.Length != expected)
        {
            throw new CborContentException("The Device EAT field has an invalid length.");
        }

        return value;
    }

    private sealed record ProofFields(
        FdoKeyExchangeSuite Exchange,
        FdoCoseAeadAlgorithm Cipher,
        ReadOnlyMemory<byte> DeviceParameter,
        ReadOnlyMemory<byte> OwnerNonce,
        FdoHashValue HashPrev2);

    /// <summary>
    /// Signed transcript fields; Device identity and certificate trust remain
    /// the caller's responsibility.
    /// </summary>
    public sealed record DeviceProof(
        ReadOnlyMemory<byte> Guid,
        FdoKeyExchangeSuite Exchange,
        FdoCoseAeadAlgorithm Cipher,
        ReadOnlyMemory<byte> DeviceParameter,
        ReadOnlyMemory<byte> OwnerNonce);
}
