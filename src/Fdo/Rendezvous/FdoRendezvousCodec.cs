// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Rendezvous;

/// <summary>Paired TO0 and TO1 framing and proof operations.</summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoRendezvousCodec
{
    private const int IdentifierLength = 16;
    internal const int MaxRedirectBlobs = 8;
    private readonly FdoCborCodec _cbor = new();
    private readonly FdoInitialMessageCodec _initial = new();
    private readonly FdoCoseSign1Codec _signatures = new();
    private readonly FdoPublicKeyCodec _keys = new();

    public ReadOnlyMemory<byte> EncodeInitial(
        ushort type, ReadOnlyMemory<byte>? identifier = null, bool delegated = false) =>
        _initial.Encode(new FdoInitialMessageCodec.InitialMessage(
            type, new byte[] { Capabilities(delegated) }, Array.Empty<string>(), identifier));

    public FdoInitialMessageCodec.InitialMessage ReadInitial(
        ushort type, ReadOnlyMemory<byte> encoded, bool allowDelegation = false)
    {
        FdoInitialMessageCodec.InitialMessage message = _initial.Decode(type, encoded);
        RequireCapabilities(message.CapabilityFlags, message.VendorCapabilities, allowDelegation);
        return message;
    }

    public FdoInitialMessageCodec.InitialMessage ReadHello(
        ushort type, ReadOnlyMemory<byte> encoded, bool allowDelegation)
    {
        FdoInitialMessageCodec.InitialMessage message = _initial.Decode(type, encoded);
        const FdoKnownCapabilities versions = FdoKnownCapabilities.Fdo10 |
            FdoKnownCapabilities.Fdo11 | FdoKnownCapabilities.Fdo20;
        FdoKnownCapabilities allowed = versions |
            (allowDelegation ? FdoKnownCapabilities.Delegation : FdoKnownCapabilities.None);
        ReadOnlySpan<byte> flags = message.CapabilityFlags.Span;
        if (flags.Length != 1 || message.VendorCapabilities.Count != 0 ||
            (flags[0] & (byte)FdoKnownCapabilities.Fdo20) == 0 || (flags[0] & ~(byte)allowed) != 0)
        {
            throw new NotSupportedException("The paired Rendezvous server requires a known capability offer that includes FDO 2.0.");
        }

        return message;
    }

    public static bool IsDelegated(ReadOnlyMemory<byte> flags) =>
        flags.Length == 1 && flags.Span[0] == Capabilities(delegated: true);

    public ReadOnlyMemory<byte> EncodeVoucher(
        ReadOnlyMemory<byte> header,
        ReadOnlyMemory<byte> hmac,
        ReadOnlyMemory<byte> chain,
        IReadOnlyList<ReadOnlyMemory<byte>> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        if (entries.Count is < 1 or > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(entries), "Rendezvous requires 1 to 255 voucher entries.");
        }

        ReadOnlyMemory<byte> checkedHeader = _cbor.ValidateAndCopy(header);
        ReadOnlyMemory<byte> checkedHmac = _cbor.ValidateAndCopy(hmac);
        ReadOnlyMemory<byte> checkedChain = _cbor.ValidateAndCopy(chain);
        long length = checkedHeader.Length + (long)checkedHmac.Length + checkedChain.Length;
        var checkedEntries = new ReadOnlyMemory<byte>[entries.Count];
        for (int i = 0; i < checkedEntries.Length; i++)
        {
            checkedEntries[i] = _cbor.ValidateAndCopy(entries[i]);
            length += checkedEntries[i].Length;
            if (length > ushort.MaxValue)
            {
                throw new CborContentException("The Ownership Voucher exceeds the message limit.");
            }
        }

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(5);
        writer.WriteInt32(200);
        writer.WriteEncodedValue(checkedHeader.Span);
        writer.WriteEncodedValue(checkedHmac.Span);
        writer.WriteEncodedValue(checkedChain.Span);
        writer.WriteStartArray(checkedEntries.Length);
        foreach (ReadOnlyMemory<byte> entry in checkedEntries)
        {
            writer.WriteEncodedValue(entry.Span);
        }

        writer.WriteEndArray();
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    public Voucher ReadVoucher(ReadOnlyMemory<byte> encoded, int maxEntries)
    {
        ReadOnlyMemory<byte> copy = _cbor.ValidateEmbeddedValueAndCopy(encoded);
        var reader = new CborReader(copy, CborConformanceMode.Strict);
        RequireArray(reader, 5);
        if (ReadUnsigned(reader) != 200)
        {
            throw new CborContentException("The Ownership Voucher version must be 200.");
        }

        ReadOnlyMemory<byte> header = reader.ReadEncodedValue();
        ReadOnlyMemory<byte> hmac = reader.ReadEncodedValue();
        ReadOnlyMemory<byte> chain = reader.ReadEncodedValue();
        if (reader.PeekState() != CborReaderState.StartArray)
        {
            throw new CborContentException("The Ownership Voucher entries must be an array.");
        }

        int count = reader.ReadStartArray()
            ?? throw new CborContentException("The Ownership Voucher entries require a definite length.");
        if (count < 1 || count > maxEntries || count > byte.MaxValue)
        {
            throw new CborContentException("The Ownership Voucher entry count is not permitted.");
        }

        var entries = new ReadOnlyMemory<byte>[count];
        for (int i = 0; i < count; i++)
        {
            entries[i] = reader.ReadEncodedValue();
        }

        reader.ReadEndArray();
        reader.ReadEndArray();
        return new Voucher(header, hmac, chain, Array.AsReadOnly(entries));
    }

    public CheckedVoucher CheckVoucher(
        Voucher voucher,
        IFdoOwnerDeviceTrustPolicy trustPolicy,
        AsymmetricAlgorithm? expectedOwner = null)
    {
        ArgumentNullException.ThrowIfNull(voucher);
        ArgumentNullException.ThrowIfNull(trustPolicy);
        using var verifier = new FdoOwnershipVoucherChainVerifier(
            voucher.Header, voucher.Hmac, voucher.Entries.Count);
        for (int i = 0; i < voucher.Entries.Count; i++)
        {
            verifier.AppendEntry(i, voucher.Entries[i]);
        }

        FdoOwnershipVoucherChainVerifier.CheckedRendezvousVoucher checkedVoucher =
            verifier.CompleteRendezvousChecks(voucher.CertificateChain);
        using FdoPublicKeyCodec.DecodedKey owner = _keys.Decode(checkedVoucher.OwnerKey);
        if (expectedOwner is not null)
        {
            using FdoPublicKeyCodec.DecodedKey supplied =
                _keys.Decode(_keys.EncodeOwnerKey(expectedOwner, owner.KeyType));
            if (!owner.HasSamePublicKey(supplied))
            {
                throw new CryptographicException("The signing key does not match the voucher's final Owner key.");
            }
        }

        IReadOnlyList<ReadOnlyMemory<byte>> certificates =
            new FdoX5ChainCodec().Decode(checkedVoucher.Voucher.DeviceCertificateChain);
        trustPolicy.Validate(new FdoOwnerDeviceTrustEvidence(
            checkedVoucher.Voucher.Guid, checkedVoucher.Voucher.ManufacturerKey, certificates));
        using X509Certificate2 leaf = FdoDerEncoding.LoadCertificate(certificates[0]);
        FdoDerEncoding.RequireSigningKeyUsage(leaf);
        using ECDsa deviceKey = leaf.GetECDsaPublicKey()
            ?? throw new CryptographicException("The Device certificate must contain an ECDSA public key.");
        using FdoPublicKeyCodec.DecodedKey decodedDevice = _keys.Decode(_keys.Encode(deviceKey));
        FdoHashValue hmac = FdoHashValue.Decode(voucher.Hmac);
        FdoHashAlgorithm hash = owner.KeyType == 11 || decodedDevice.KeyType == 11 ||
            hmac.Algorithm == FdoHashAlgorithm.HmacSha384
                ? FdoHashAlgorithm.Sha384 : FdoHashAlgorithm.Sha256;
        return new CheckedVoucher(
            checkedVoucher.Voucher.Guid.ToArray(), checkedVoucher.Voucher.ManufacturerKey.ToArray(),
            checkedVoucher.Voucher.DeviceCertificateChain.ToArray(), checkedVoucher.OwnerKey.ToArray(), hash);
    }

    public ReadOnlyMemory<byte> EncodeOwnerSign(
        ReadOnlyMemory<byte> encodedVoucher,
        uint waitSeconds,
        ReadOnlyMemory<byte> nonce,
        FdoRendezvousAddress address,
        FdoHashAlgorithm hashAlgorithm,
        AsymmetricAlgorithm ownerKey,
        ReadOnlyMemory<byte> delegateChain = default,
        IReadOnlyList<FdoRendezvousAddress>? additionalAddresses = null)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(ownerKey);
        if (waitSeconds == 0 || nonce.Length != IdentifierLength)
        {
            throw new ArgumentException("Registration requires a nonzero wait and a 16-byte nonce.");
        }

        ReadOnlyMemory<byte> voucher = _cbor.ValidateAndCopy(encodedVoucher);
        var to0 = new CborWriter(CborConformanceMode.Canonical);
        to0.WriteStartArray(3);
        to0.WriteEncodedValue(voucher.Span);
        to0.WriteUInt32(waitSeconds);
        to0.WriteByteString(nonce.Span);
        to0.WriteEndArray();
        ReadOnlyMemory<byte> to0Data = _cbor.ValidateAndCopy(to0.Encode());

        var payload = new CborWriter(CborConformanceMode.Canonical);
        payload.WriteStartArray(3);
        int extraCount = additionalAddresses?.Count ?? 0;
        if (extraCount > 2 || (extraCount != 0 && delegateChain.IsEmpty))
        {
            throw new ArgumentException("Only a delegated redirect can contain up to two additional routes.", nameof(additionalAddresses));
        }

        var addresses = new FdoRendezvousAddress[1 + extraCount];
        addresses[0] = address;
        for (int i = 0; i < extraCount; i++)
        {
            addresses[i + 1] = additionalAddresses![i];
        }

        if (extraCount != 0)
        {
            FdoDelegatedRendezvousRoutes.Validate(addresses);
        }

        payload.WriteStartArray(addresses.Length);
        foreach (FdoRendezvousAddress route in addresses)
        {
            WriteAddress(payload, route);
        }

        payload.WriteEndArray();
        payload.WriteEncodedValue(FdoHashValue.ComputeDigest(hashAlgorithm, to0Data.Span).Encode().Span);
        if (delegateChain.IsEmpty)
        {
            payload.WriteByteString(new byte[] { 0xf6 });
        }
        else
        {
            payload.WriteByteString(delegateChain.Span);
        }
        payload.WriteEndArray();
        using FdoPublicKeyCodec.DecodedKey owner = _keys.Decode(_keys.EncodeOwnerKey(ownerKey));
        ReadOnlyMemory<byte> signedRedirect = _signatures.Sign(
            FdoSignatureOperation.TO0OwnerSign, owner.Algorithm, ownerKey, payload.Encode());

        var message = new CborWriter(CborConformanceMode.Canonical);
        message.WriteStartArray(4);
        message.WriteByteString(new byte[] { Capabilities(!delegateChain.IsEmpty) });
        message.WriteStartArray(0);
        message.WriteEndArray();
        message.WriteByteString(to0Data.Span);
        message.WriteEncodedValue(signedRedirect.Span);
        message.WriteEndArray();
        return _cbor.ValidateAndCopy(message.Encode());
    }

    public OwnerSubmission ReadOwnerSign(ReadOnlyMemory<byte> encoded, int maxEntries, bool delegated = false)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 4);
        FdoCapabilityFields.Parsed capabilities = FdoCapabilityFields.Read(reader);
        RequireCapabilities(capabilities.Flags, capabilities.Vendors, delegated);
        if (IsDelegated(capabilities.Flags) != delegated)
        {
            throw new NotSupportedException("TO0.OwnerSign does not match the selected delegation capability.");
        }
        ReadOnlyMemory<byte> to0 = _cbor.ValidateEmbeddedValueAndCopy(ReadBytes(reader));
        ReadOnlyMemory<byte> signedRedirect = reader.ReadEncodedValue();
        reader.ReadEndArray();

        var parameters = new CborReader(to0, CborConformanceMode.Strict);
        RequireArray(parameters, 3);
        Voucher voucher = ReadVoucher(parameters.ReadEncodedValue(), maxEntries);
        ulong wait = ReadUnsigned(parameters);
        if (wait is 0 or > uint.MaxValue)
        {
            throw new CborContentException("The paired registration wait must be a nonzero uint32.");
        }

        ReadOnlyMemory<byte> nonce = ReadBytes(parameters);
        if (nonce.Length != IdentifierLength)
        {
            throw new CborContentException("The TO0 nonce must contain exactly 16 bytes.");
        }

        parameters.ReadEndArray();
        return new OwnerSubmission(to0, voucher, (uint)wait, nonce, signedRedirect);
    }

    public FdoRendezvousAddress VerifyRedirect(
        ReadOnlyMemory<byte> signedRedirect,
        ReadOnlyMemory<byte> encodedOwnerKey,
        ReadOnlyMemory<byte>? expectedTo0 = null,
        FdoHashAlgorithm? expectedHash = null)
    {
        using FdoPublicKeyCodec.DecodedKey owner = _keys.Decode(encodedOwnerKey);
        ReadOnlyMemory<byte> payload = owner.VerifySignature(
            _signatures, FdoSignatureOperation.TO0OwnerSign, signedRedirect);
        RedirectFields fields = ReadRedirectPayload(payload, allowDelegateChain: false);
        if (expectedTo0 is ReadOnlyMemory<byte> to0 &&
            (expectedHash is not FdoHashAlgorithm hash ||
             !fields.To0Hash.MatchesDigest(hash, to0.Span)))
        {
            throw new CryptographicException("The signed redirect does not bind the exact TO0 data.");
        }

        return fields.Addresses[0];
    }

    /// <summary>
    /// Returns whether an untrusted rendezvous blob carries a non-null
    /// DelegateChain. Nothing about the blob is authenticated.
    /// </summary>
    public bool HasUntrustedDelegateChain(ReadOnlyMemory<byte> signedRedirect) =>
        !ReadUntrustedRedirect(signedRedirect, allowDelegateChain: true).DelegateChain.IsEmpty;

    /// <summary>
    /// Verifies a single delegated to1d blob (§3.4.6.5, §3.5): the chain must
    /// be authentic for the raw voucher Owner key at the supplied time, carry
    /// the redirect permission, and its leaf key must have signed the exact
    /// blob. The chain is not compared with any TO2 Delegate.
    /// </summary>
    /// <exception cref="NotSupportedException">The blob carries no DelegateChain.</exception>
    /// <exception cref="FdoDelegateChainException">The chain is not authentic for the Owner key.</exception>
    /// <exception cref="FdoDelegateNotPermittedException">The chain lacks the redirect permission.</exception>
    /// <exception cref="CryptographicException">The leaf key did not sign the blob.</exception>
    public (IReadOnlyList<FdoRendezvousAddress> Addresses, FdoVerifiedDelegateChain Delegate) VerifyDelegatedRedirect(
        ReadOnlyMemory<byte> signedRedirect,
        ReadOnlyMemory<byte> encodedOwnerKey,
        DateTimeOffset verificationTime,
        ReadOnlyMemory<byte>? expectedTo0 = null,
        FdoHashAlgorithm? expectedHash = null,
        FdoDelegateOfflineRevocationPolicy? offlineRevocation = null) =>
        VerifyDelegatedRedirectCore(signedRedirect, encodedOwnerKey, verificationTime, expectedTo0,
            expectedHash, offlineRevocation, requireRedirect: true);

    internal FdoVerifiedDelegateChain AuthenticateDelegatedOwnerSign(
        OwnerSubmission submission, CheckedVoucher voucher, DateTimeOffset verificationTime,
        FdoDelegateOfflineRevocationPolicy? offlineRevocation) =>
        VerifyDelegatedRedirectCore(submission.SignedRedirect, voucher.OwnerKey, verificationTime, submission.To0Data,
            voucher.HashAlgorithm, offlineRevocation, requireRedirect: false).Delegate;

    private (IReadOnlyList<FdoRendezvousAddress> Addresses, FdoVerifiedDelegateChain Delegate) VerifyDelegatedRedirectCore(
        ReadOnlyMemory<byte> signedRedirect, ReadOnlyMemory<byte> encodedOwnerKey, DateTimeOffset verificationTime,
        ReadOnlyMemory<byte>? expectedTo0, FdoHashAlgorithm? expectedHash,
        FdoDelegateOfflineRevocationPolicy? offlineRevocation, bool requireRedirect)
    {
        ReadOnlyMemory<byte> blob = _cbor.ValidateAndCopy(signedRedirect);
        ReadOnlyMemory<byte> untrustedChain = ReadUntrustedRedirect(blob, allowDelegateChain: true).DelegateChain;
        if (untrustedChain.IsEmpty)
        {
            throw new NotSupportedException("The rendezvous blob is not delegated.");
        }

        IReadOnlyList<ReadOnlyMemory<byte>> chain = new FdoX5ChainCodec().Decode(untrustedChain);
        FdoVerifiedDelegateChain verified = new FdoDelegateChainVerifier(X509RevocationMode.NoCheck)
            .Verify(chain, encodedOwnerKey, verificationTime, captureRevocationTargets: offlineRevocation is not null);
        using FdoPublicKeyCodec.DecodedKey leaf = _keys.Decode(verified.DelegateKey);
        ReadOnlyMemory<byte> payload = leaf.VerifySignature(_signatures, FdoSignatureOperation.TO0OwnerSign, blob);
        RedirectFields fields = ReadRedirectPayload(payload, allowDelegateChain: true);
        if (!fields.DelegateChain.Span.SequenceEqual(untrustedChain.Span))
        {
            throw new CryptographicException("The signed redirect DelegateChain differs from the verified chain.");
        }

        if (expectedTo0 is ReadOnlyMemory<byte> to0 &&
            (expectedHash is not FdoHashAlgorithm hash || !fields.To0Hash.MatchesDigest(hash, to0.Span)))
        {
            throw new CryptographicException("The signed redirect does not bind this TO0 data.");
        }

        if (requireRedirect)
        {
            verified.Require(FdoDelegatePermissions.Redirect);
        }

        verified.RequireOfflineStatus(offlineRevocation, verificationTime);
        return (fields.Addresses, verified);
    }

    public FdoRendezvousAddress ReadUntrustedRedirectAddress(
        ReadOnlyMemory<byte> signedRedirect, bool allowDelegateChain = false)
    {
        IReadOnlyList<FdoRendezvousAddress> addresses = ReadUntrustedRedirectAddresses(signedRedirect, allowDelegateChain);
        return addresses.Count == 1 ? addresses[0] : throw new NotSupportedException("The redirect has multiple addresses.");
    }

    public IReadOnlyList<FdoRendezvousAddress> ReadUntrustedRedirectAddresses(
        ReadOnlyMemory<byte> signedRedirect, bool allowDelegateChain) =>
        ReadUntrustedRedirect(signedRedirect, allowDelegateChain).Addresses;

    private RedirectFields ReadUntrustedRedirect(ReadOnlyMemory<byte> signedRedirect, bool allowDelegateChain)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(signedRedirect), CborConformanceMode.Canonical);
        if (reader.PeekState() != CborReaderState.Tag || reader.ReadTag() != (CborTag)18)
        {
            throw new CborContentException("The rendezvous blob must be a tagged COSE_Sign1.");
        }

        RequireArray(reader, 4);
        ReadBytes(reader);
        if (reader.PeekState() != CborReaderState.StartMap || reader.ReadStartMap() != 0)
        {
            throw new CborContentException("The paired rendezvous blob requires an empty unprotected header.");
        }

        reader.ReadEndMap();
        ReadOnlyMemory<byte> payload = _cbor.ValidateEmbeddedValueAndCopy(ReadBytes(reader));
        if (ReadBytes(reader).IsEmpty)
        {
            throw new CborContentException("The rendezvous blob signature is empty.");
        }

        reader.ReadEndArray();
        RedirectFields fields = ReadRedirectPayload(payload, allowDelegateChain);
        if (!fields.DelegateChain.IsEmpty)
        {
            new FdoX5ChainCodec().Decode(fields.DelegateChain);
        }

        return fields;
    }

    public ReadOnlyMemory<byte> EncodeAcceptOwner(uint waitSeconds)
    {
        ArgumentOutOfRangeException.ThrowIfZero(waitSeconds);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(1);
        writer.WriteUInt32(waitSeconds);
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    public uint ReadAcceptOwner(ReadOnlyMemory<byte> encoded, uint requested)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 1);
        ulong wait = ReadUnsigned(reader);
        reader.ReadEndArray();
        if (wait is 0 or > uint.MaxValue || wait > requested)
        {
            throw new CborContentException("The accepted wait must be nonzero and no greater than requested.");
        }

        return (uint)wait;
    }

    public ReadOnlyMemory<byte> SignDeviceProof(
        ReadOnlyMemory<byte> guid,
        ReadOnlyMemory<byte> nonce,
        ECDsa deviceKey)
    {
        ArgumentNullException.ThrowIfNull(deviceKey);
        if (guid.Length != IdentifierLength || nonce.Length != IdentifierLength)
        {
            throw new ArgumentException("The TO1 GUID and nonce must contain 16 bytes.");
        }

        byte[] ueid = new byte[IdentifierLength + 1];
        ueid[0] = 1;
        guid.Span.CopyTo(ueid.AsSpan(1));
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(10);
        writer.WriteByteString(nonce.Span);
        writer.WriteInt32(256);
        writer.WriteByteString(ueid);
        writer.WriteEndMap();
        using FdoPublicKeyCodec.DecodedKey key = _keys.Decode(_keys.Encode(deviceKey));
        return _signatures.Sign(FdoSignatureOperation.TO1ProveToRV, key.Algorithm, deviceKey, writer.Encode());
    }

    public void VerifyDeviceProof(
        ReadOnlyMemory<byte> encodedProof,
        ReadOnlyMemory<byte> expectedGuid,
        ReadOnlyMemory<byte> expectedNonce,
        ECDsa deviceKey)
    {
        ArgumentNullException.ThrowIfNull(deviceKey);
        if (expectedGuid.Length != IdentifierLength || expectedNonce.Length != IdentifierLength)
        {
            throw new ArgumentException("The TO1 GUID and nonce must contain 16 bytes.");
        }

        using FdoPublicKeyCodec.DecodedKey key = _keys.Decode(_keys.Encode(deviceKey));
        ReadOnlyMemory<byte> payload = key.VerifySignature(
            _signatures, FdoSignatureOperation.TO1ProveToRV, encodedProof);
        var reader = new CborReader(payload, CborConformanceMode.Strict);
        if (reader.PeekState() != CborReaderState.StartMap || reader.ReadStartMap() != 2)
        {
            throw new CborContentException("The paired TO1 EAT requires exactly two claims.");
        }

        ReadOnlyMemory<byte> nonce = default;
        ReadOnlyMemory<byte> ueid = default;
        for (int i = 0; i < 2; i++)
        {
            ulong claim = ReadUnsigned(reader);
            if (claim == 10)
            {
                nonce = ReadBytes(reader);
            }
            else if (claim == 256)
            {
                ueid = ReadBytes(reader);
            }
            else
            {
                throw new NotSupportedException("Additional TO1 EAT claims are not supported.");
            }
        }

        reader.ReadEndMap();
        Span<byte> expectedUeid = stackalloc byte[IdentifierLength + 1];
        expectedUeid[0] = 1;
        expectedGuid.Span.CopyTo(expectedUeid[1..]);
        if (!CryptographicOperations.FixedTimeEquals(nonce.Span, expectedNonce.Span) ||
            !CryptographicOperations.FixedTimeEquals(ueid.Span, expectedUeid))
        {
            throw new CryptographicException("The TO1 Device proof nonce or GUID does not match this run.");
        }
    }

    public ReadOnlyMemory<byte> EncodeRedirect(ReadOnlyMemory<byte> signedRedirect)
    {
        ReadOnlyMemory<byte> blob = _cbor.ValidateAndCopy(signedRedirect);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteUInt32(1);
        writer.WriteUInt32(0);
        writer.WriteStartArray(1);
        writer.WriteEncodedValue(blob.Span);
        writer.WriteEndArray();
        writer.WriteEndArray();
        return _cbor.ValidateAndCopy(writer.Encode());
    }

    internal ReadOnlyMemory<byte> EncodeRedirectPage(
        IReadOnlyList<FdoRendezvousRegistrationRecord> records, int index, int count)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteUInt32((uint)records.Count);
        writer.WriteUInt32((uint)index);
        writer.WriteStartArray(count);
        for (int i = index; i < index + count; i++)
        {
            writer.WriteEncodedValue(records[i].Registration.SignedRedirect.Span);
        }

        writer.WriteEndArray();
        writer.WriteEndArray();
        return writer.Encode();
    }

    internal (int Total, int Index, ReadOnlyMemory<byte>[] Blobs) ReadRedirectPage(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 3);
        ulong total = ReadUnsigned(reader);
        ulong index = ReadUnsigned(reader);
        if (total is 0 or > MaxRedirectBlobs || index >= total ||
            reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() is not int count ||
            count < 1 || (ulong)count > total - index)
        {
            throw new CborContentException("The TO1 redirect page has invalid bounds.");
        }

        var blobs = new ReadOnlyMemory<byte>[count];
        for (int i = 0; i < count; i++)
        {
            blobs[i] = reader.ReadEncodedValue();
        }

        reader.ReadEndArray();
        reader.ReadEndArray();
        return ((int)total, (int)index, blobs);
    }

    internal static ReadOnlyMemory<byte> EncodeRvMore(int index)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(1);
        writer.WriteUInt32((uint)index);
        writer.WriteEndArray();
        return writer.Encode();
    }

    internal int ReadRvMore(ReadOnlyMemory<byte> encoded)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 1);
        ulong index = ReadUnsigned(reader);
        reader.ReadEndArray();
        return index is > 0 and < MaxRedirectBlobs
            ? (int)index : throw new CborContentException("The RVMore index is outside the paired bounds.");
    }

    public ReadOnlyMemory<byte> ReadRedirect(ReadOnlyMemory<byte> encoded, bool allowDelegateChain = false)
    {
        var reader = new CborReader(_cbor.ValidateAndCopy(encoded), CborConformanceMode.Canonical);
        RequireArray(reader, 3);
        if (ReadUnsigned(reader) != 1 || ReadUnsigned(reader) != 0)
        {
            throw new NotSupportedException("Only a single TO1 redirect is supported.");
        }

        RequireArray(reader, 1);
        ReadOnlyMemory<byte> blob = reader.ReadEncodedValue();
        reader.ReadEndArray();
        reader.ReadEndArray();
        ReadUntrustedRedirectAddresses(blob, allowDelegateChain);
        return blob.ToArray();
    }

    private RedirectFields ReadRedirectPayload(ReadOnlyMemory<byte> encoded, bool allowDelegateChain)
    {
        var reader = new CborReader(_cbor.ValidateEmbeddedValueAndCopy(encoded), CborConformanceMode.Strict);
        RequireArray(reader, 3);
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() is not int count ||
            count < 1 || count > (allowDelegateChain ? 3 : 1))
        {
            throw new CborContentException("The rendezvous message has an unexpected array shape.");
        }

        var addresses = new FdoRendezvousAddress[count];
        for (int i = 0; i < count; i++)
        {
            addresses[i] = ReadAddress(reader);
        }

        reader.ReadEndArray();
        FdoHashValue hash = FdoHashValue.Decode(reader.ReadEncodedValue());
        if (hash.IsHmac)
        {
            throw new CborContentException("The TO0 data hash must be a digest.");
        }

        ReadOnlyMemory<byte> delegateChain = ReadBytes(reader);
        ReadOnlyMemory<byte> chain = default;
        if (delegateChain.Length != 1 || delegateChain.Span[0] != 0xf6)
        {
            if (!allowDelegateChain)
            {
                throw new NotSupportedException("Only an explicitly wrapped null DelegateChain is supported.");
            }

            chain = _cbor.ValidateEmbeddedValueAndCopy(delegateChain);
        }

        if (count > 1)
        {
            if (chain.IsEmpty)
            {
                throw new NotSupportedException("Only a delegated redirect may contain multiple addresses.");
            }

            FdoDelegatedRendezvousRoutes.Validate(addresses);
        }

        reader.ReadEndArray();
        return new RedirectFields(Array.AsReadOnly(addresses), hash, chain);
    }

    private static FdoRendezvousAddress ReadAddress(CborReader reader)
    {
        RequireArray(reader, 5);
        ReadOnlyMemory<byte>? ip = ReadNullableBytes(reader);
        string? dns = ReadNullableText(reader);
        ulong port = ReadUnsigned(reader);
        ulong protocol = ReadUnsigned(reader);
        if (reader.PeekState() != CborReaderState.Null)
        {
            throw new NotSupportedException("Delegated address preferences are not supported.");
        }

        reader.ReadNull();
        reader.ReadEndArray();
        if ((ip is ReadOnlyMemory<byte> bytes && bytes.Length is not (4 or 16)) ||
            (dns is not null && Uri.CheckHostName(dns) != UriHostNameType.Dns) ||
            (ip is null && dns is null) || port is 0 or > ushort.MaxValue ||
            protocol is not (3 or 5))
        {
            throw new CborContentException("The paired Owner address is invalid or unsupported.");
        }

        return new FdoRendezvousAddress(ip, dns, (ushort)port, (FdoRendezvousTransportProtocol)protocol);
    }

    private static void WriteAddress(CborWriter writer, FdoRendezvousAddress address)
    {
        writer.WriteStartArray(5);
        if (address.IpAddress is ReadOnlyMemory<byte> ip)
        {
            writer.WriteByteString(ip.Span);
        }
        else
        {
            writer.WriteNull();
        }

        if (address.DnsName is string dns)
        {
            writer.WriteTextString(dns);
        }
        else
        {
            writer.WriteNull();
        }

        writer.WriteUInt32(address.Port);
        writer.WriteUInt32((uint)address.Protocol);
        writer.WriteNull();
        writer.WriteEndArray();
    }

    private static byte Capabilities(bool delegated) =>
        (byte)(FdoKnownCapabilities.Fdo20 | (delegated ? FdoKnownCapabilities.Delegation : FdoKnownCapabilities.None));

    private static void RequireCapabilities(
        ReadOnlyMemory<byte> flags, IReadOnlyList<string> vendors, bool allowDelegation)
    {
        if (flags.Length != 1 || vendors.Count != 0 ||
            (flags.Span[0] != Capabilities(delegated: false) && !(allowDelegation && IsDelegated(flags))))
        {
            throw new NotSupportedException("The paired rendezvous profile requires only FDO 2.0 capabilities.");
        }
    }

    private static void RequireArray(CborReader reader, int count)
    {
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != count)
        {
            throw new CborContentException("The rendezvous message has an unexpected array shape.");
        }
    }

    private static ulong ReadUnsigned(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.UnsignedInteger)
        {
            throw new CborContentException("The rendezvous field must be an unsigned integer.");
        }

        return reader.ReadUInt64();
    }

    private static ReadOnlyMemory<byte> ReadBytes(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException("The rendezvous field must be a byte string.");
        }

        return reader.ReadDefiniteLengthByteString();
    }

    private static ReadOnlyMemory<byte>? ReadNullableBytes(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.Null)
        {
            return ReadBytes(reader);
        }

        reader.ReadNull();
        return null;
    }

    private static string? ReadNullableText(CborReader reader)
    {
        if (reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
            return null;
        }

        if (reader.PeekState() != CborReaderState.TextString)
        {
            throw new CborContentException("The Owner DNS address must be text or null.");
        }

        return reader.ReadTextString();
    }

    public sealed record Voucher(
        ReadOnlyMemory<byte> Header,
        ReadOnlyMemory<byte> Hmac,
        ReadOnlyMemory<byte> CertificateChain,
        IReadOnlyList<ReadOnlyMemory<byte>> Entries);

    public sealed record CheckedVoucher(
        ReadOnlyMemory<byte> Guid,
        ReadOnlyMemory<byte> ManufacturerKey,
        ReadOnlyMemory<byte> CertificateChain,
        ReadOnlyMemory<byte> OwnerKey,
        FdoHashAlgorithm HashAlgorithm);

    public sealed record OwnerSubmission(
        ReadOnlyMemory<byte> To0Data,
        Voucher Voucher,
        uint WaitSeconds,
        ReadOnlyMemory<byte> Nonce,
        ReadOnlyMemory<byte> SignedRedirect);

    private sealed record RedirectFields(
        IReadOnlyList<FdoRendezvousAddress> Addresses, FdoHashValue To0Hash, ReadOnlyMemory<byte> DelegateChain);
}
