// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Fdo.Cryptography;

namespace Fdo.Serialization;

/// <summary>
/// Signs and verifies paired SetupDevice20 messages, with or without a
/// Delegate. The role must authenticate the protected channel, enforce message
/// order, check Delegate permissions, and apply Device and Owner authorization
/// policy. Owner2 signs replacement credentials in both cases.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoTo2SetupDeviceCodec
{
    private const int ReuseDisposition = 2;
    private const int ReplacementDisposition = 1;
    private readonly FdoCborCodec _cbor;
    private readonly FdoPublicKeyCodec _keys;
    private readonly FdoCoseSign1Codec _signatures;

    public FdoTo2SetupDeviceCodec(
        int maxEncodedBytes = ushort.MaxValue,
        int maxDepth = 32,
        int maxItems = ushort.MaxValue)
    {
        _cbor = new FdoCborCodec(maxEncodedBytes, maxDepth, maxItems);
        _keys = new FdoPublicKeyCodec(maxEncodedBytes, maxDepth, maxItems);
        _signatures = new FdoCoseSign1Codec(maxEncodedBytes, maxDepth, maxItems);
    }

    /// <summary>
    /// Signs with the authenticated voucher's final Owner key, or with the
    /// Delegate leaf key when the Owner proof was delegated. Credential reuse
    /// requires explicit Owner opt-in; this does not authorize enrollment.
    /// </summary>
    /// <param name="authenticatedDevice">The verified identity and proof of the enrolling Device.</param>
    /// <param name="ownerSigningKey">The private key used to sign as the Owner.</param>
    /// <param name="allowCredentialReuse">Whether the Device may retain its existing FDO credential.</param>
    /// <param name="maxDeviceServiceInfoSize">The maximum encoded Device ServiceInfo body size, in bytes.</param>
    /// <param name="delegateKey">The verified Delegate public key.</param>
    /// <remarks>
    /// <paramref name="delegateKey"/> is the FDO PublicKey of the Delegate leaf
    /// that signed the Owner proof, or empty for a nondelegated run.
    /// </remarks>
    /// <exception cref="CryptographicException">
    /// The SetupDevice signing key is not the verified voucher Owner key.
    /// </exception>
    public ReadOnlyMemory<byte> Sign(
        FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice authenticatedDevice,
        AsymmetricAlgorithm ownerSigningKey,
        bool allowCredentialReuse,
        ushort? maxDeviceServiceInfoSize,
        ReadOnlyMemory<byte> delegateKey = default)
    {
        ArgumentNullException.ThrowIfNull(authenticatedDevice);
        ArgumentNullException.ThrowIfNull(ownerSigningKey);
        RequireCredentialReuse(allowCredentialReuse);
        using FdoPublicKeyCodec.DecodedKey verifiedOwner =
            _keys.Decode(delegateKey.IsEmpty ? authenticatedDevice.OwnerKey : delegateKey);
        using FdoPublicKeyCodec.DecodedKey signingOwner =
            _keys.Decode(_keys.EncodeOwnerKey(ownerSigningKey, verifiedOwner.KeyType));
        if (!verifiedOwner.HasSamePublicKey(signingOwner))
        {
            throw new CryptographicException(delegateKey.IsEmpty
                ? "The SetupDevice signing key is not the verified voucher Owner key."
                : "The SetupDevice signing key is not the Delegate leaf key.");
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteInt32(ReuseDisposition);
        writer.WriteNull();
        if (maxDeviceServiceInfoSize is ushort size)
        {
            writer.WriteUInt64(size);
        }
        else
        {
            writer.WriteNull();
        }

        writer.WriteEndArray();
        return _signatures.Sign(
            FdoSignatureOperation.TO2SetupDevice, verifiedOwner.Algorithm, ownerSigningKey, writer.Encode());
    }

    /// <summary>
    /// Verifies with the key that signed the Owner proof: the Owner key
    /// released after the Device checked the whole voucher, or the verified
    /// Delegate leaf key. The role must separately verify a TO1 redirect or
    /// explicitly select rendezvous bypass, decrypt the current protected
    /// message, and check the Delegate reuse permission.
    /// </summary>
    /// <param name="verifiedOwner">The verified Owner proof and identity.</param>
    /// <param name="encoded">The encoded CBOR value to read or verify.</param>
    /// <param name="allowCredentialReuse">Whether the Device may retain its existing FDO credential.</param>
    /// <exception cref="CborContentException">
    /// Credential reuse cannot contain replacement credentials. SetupDevice20 must contain three fields. The Device
    /// ServiceInfo size must be uint16 or null. The Device ServiceInfo size must fit in uint16. The SetupDevice20
    /// disposition must be an unsigned integer.
    /// </exception>
    /// <exception cref="NotSupportedException">Only credential reuse is supported in the paired setup.</exception>
    public ushort? Verify(
        FdoTo2OwnerProofCodec.OwnerProof verifiedOwner,
        ReadOnlyMemory<byte> encoded,
        bool allowCredentialReuse)
    {
        ArgumentNullException.ThrowIfNull(verifiedOwner);
        RequireCredentialReuse(allowCredentialReuse);
        using FdoPublicKeyCodec.DecodedKey owner = _keys.Decode(verifiedOwner.SigningKey);
        ReadOnlyMemory<byte> payload = owner.VerifySignature(
            _signatures, FdoSignatureOperation.TO2SetupDevice, encoded);
        var reader = new CborReader(payload, CborConformanceMode.Strict);
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != 3)
        {
            throw new CborContentException("SetupDevice20 must contain three fields.");
        }

        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("The SetupDevice20 disposition must be an unsigned integer.");
        }

        if (reader.ReadUInt64() != ReuseDisposition)
        {
            throw new NotSupportedException("Only credential reuse is supported in the paired setup.");
        }

        if (reader.PeekState() != CborReaderState.Null)
        {
            throw new CborContentException("Credential reuse cannot contain replacement credentials.");
        }

        reader.ReadNull();
        ushort? maxSize;
        if (reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
            maxSize = null;
        }
        else
        {
            if (reader.PeekState() != CborReaderState.UnsignedInteger)
            {
                throw new CborContentException("The Device ServiceInfo size must be uint16 or null.");
            }

            ulong size = reader.ReadUInt64();
            if (size > ushort.MaxValue)
            {
                throw new CborContentException("The Device ServiceInfo size must fit in uint16.");
            }

            maxSize = (ushort)size;
        }

        reader.ReadEndArray();
        return maxSize;
    }

    public ReadOnlyMemory<byte> SignReplacement(
        FdoTo2OwnerDeviceAuthenticator.AuthenticatedDevice authenticatedDevice,
        AsymmetricAlgorithm owner2SigningKey,
        ReadOnlyMemory<byte> rendezvousInfo,
        ReadOnlyMemory<byte> guid,
        ReadOnlyMemory<byte> nonce,
        ushort? maxDeviceServiceInfoSize)
    {
        ArgumentNullException.ThrowIfNull(authenticatedDevice);
        ArgumentNullException.ThrowIfNull(owner2SigningKey);
        RequireNonce(nonce);
        using FdoPublicKeyCodec.DecodedKey current = _keys.Decode(authenticatedDevice.OwnerKey);
        ReadOnlyMemory<byte> encodedKey = _keys.EncodeOwnerKey(owner2SigningKey, current.KeyType);
        using FdoPublicKeyCodec.DecodedKey replacement = _keys.Decode(encodedKey);
        RequireReplacementKey(current, replacement);
        _ = Fdo.Initialization.FdoInitializationFields.CreateReplacementHeader(
            authenticatedDevice.Header, guid, rendezvousInfo, encodedKey);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteInt32(ReplacementDisposition);
        writer.WriteStartArray(4);
        writer.WriteEncodedValue(rendezvousInfo.Span);
        writer.WriteByteString(guid.Span);
        writer.WriteByteString(nonce.Span);
        writer.WriteEncodedValue(encodedKey.Span);
        writer.WriteEndArray();
        if (maxDeviceServiceInfoSize is ushort size)
        {
            writer.WriteUInt64(size);
        }
        else
        {
            writer.WriteNull();
        }
        writer.WriteEndArray();
        return _signatures.Sign(
            FdoSignatureOperation.TO2SetupDevice, replacement.Algorithm, owner2SigningKey, writer.Encode());
    }

    public ulong ReadUntrustedDisposition(ReadOnlyMemory<byte> encoded)
    {
        ReadOnlyMemory<byte> payload = ReadUntrustedPayload(encoded);
        var reader = new CborReader(payload, CborConformanceMode.Strict);
        RequireArray(reader, 3);
        return ReadUnsigned(reader);
    }

    public Replacement VerifyReplacement(
        FdoTo2OwnerProofCodec.OwnerProof verifiedOwner,
        ReadOnlyMemory<byte> encoded,
        ReadOnlyMemory<byte> expectedNonce)
    {
        ArgumentNullException.ThrowIfNull(verifiedOwner);
        RequireNonce(expectedNonce);
        Replacement untrusted = ReadReplacement(ReadUntrustedPayload(encoded));
        using FdoPublicKeyCodec.DecodedKey current = _keys.Decode(verifiedOwner.OwnerKey);
        using FdoPublicKeyCodec.DecodedKey owner2 = _keys.Decode(untrusted.OwnerKey);
        RequireReplacementKey(current, owner2);
        ReadOnlyMemory<byte> verifiedPayload = owner2.VerifySignature(
            _signatures, FdoSignatureOperation.TO2SetupDevice, encoded);
        Replacement replacement = ReadReplacement(verifiedPayload);
        if (!CryptographicOperations.FixedTimeEquals(expectedNonce.Span, replacement.Nonce.Span))
        {
            throw new CryptographicException("The replacement setup nonce does not match the Device challenge.");
        }

        _ = Fdo.Initialization.FdoInitializationFields.CreateReplacementHeader(
            verifiedOwner.HeaderTag, replacement.Guid, replacement.RendezvousInfo, replacement.OwnerKey);
        return replacement;
    }

    private ReadOnlyMemory<byte> ReadUntrustedPayload(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        if (reader.PeekState() != CborReaderState.Tag || reader.ReadTag() != (CborTag)18)
        {
            throw new CborContentException("SetupDevice20 requires a tagged COSE_Sign1.");
        }
        RequireArray(reader, 4);
        reader.ReadEncodedValue();
        reader.ReadEncodedValue();
        ReadOnlyMemory<byte> payload = ReadBytes(reader);
        reader.ReadEncodedValue();
        reader.ReadEndArray();
        return _cbor.ValidateEmbeddedValueAndCopy(payload);
    }

    private static Replacement ReadReplacement(ReadOnlyMemory<byte> payload)
    {
        var reader = new CborReader(payload, CborConformanceMode.Canonical);
        RequireArray(reader, 3);
        if (ReadUnsigned(reader) != ReplacementDisposition)
        {
            throw new CborContentException("The SetupDevice20 disposition is not credential replacement.");
        }
        RequireArray(reader, 4);
        ReadOnlyMemory<byte> rendezvous = reader.ReadEncodedValue();
        ReadOnlyMemory<byte> guid = ReadBytes(reader);
        ReadOnlyMemory<byte> nonce = ReadBytes(reader);
        ReadOnlyMemory<byte> ownerKey = reader.ReadEncodedValue();
        reader.ReadEndArray();
        ushort? size;
        if (reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
            size = null;
        }
        else
        {
            ulong value = ReadUnsigned(reader);
            if (value > ushort.MaxValue)
            {
                throw new CborContentException("The Device ServiceInfo size must fit in uint16.");
            }
            size = (ushort)value;
        }
        reader.ReadEndArray();
        return new Replacement(rendezvous.ToArray(), guid.ToArray(), nonce.ToArray(), ownerKey.ToArray(), size);
    }

    private static void RequireReplacementKey(
        FdoPublicKeyCodec.DecodedKey current, FdoPublicKeyCodec.DecodedKey replacement)
    {
        if (current.KeyType != replacement.KeyType || current.Algorithm != replacement.Algorithm ||
            current.HasSamePublicKey(replacement))
        {
            throw new CryptographicException("The replacement Owner key must be distinct and use the current key type.");
        }
    }

    private static void RequireNonce(ReadOnlyMemory<byte> nonce)
    {
        if (nonce.Length != 16)
        {
            throw new CborContentException("The replacement setup nonce must contain exactly 16 bytes.");
        }
    }

    private static void RequireArray(CborReader reader, int count)
    {
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != count)
        {
            throw new CborContentException("The SetupDevice20 value has the wrong array shape.");
        }
    }

    private static ulong ReadUnsigned(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("The SetupDevice20 field must be an unsigned integer.");
        }
        return reader.ReadUInt64();
    }

    private static ReadOnlyMemory<byte> ReadBytes(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("The SetupDevice20 field must be a byte string.");
        }
        return reader.ReadDefiniteLengthByteString();
    }

    public sealed record Replacement(
        ReadOnlyMemory<byte> RendezvousInfo,
        ReadOnlyMemory<byte> Guid,
        ReadOnlyMemory<byte> Nonce,
        ReadOnlyMemory<byte> OwnerKey,
        ushort? MaxDeviceServiceInfoSize);

    private static void RequireCredentialReuse(bool allowed)
    {
        if (!allowed)
        {
            throw new InvalidOperationException("Credential reuse was not explicitly enabled.");
        }
    }
}
