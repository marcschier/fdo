// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Ownership;

/// <summary>Appends a signed transfer to a checked Ownership Voucher.</summary>
[UnsupportedOSPlatform("browser")]
public static class FdoOwnershipVoucherTransfer
{
    /// <summary>
    /// Extends a canonical FDO 2.0 voucher to the supplied Owner key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The host must authorize the exact input voucher and the new Owner key.
    /// It retains the signing key and must keep it available without concurrent
    /// use for this call. The result is not persisted by the library.
    /// </para>
    /// <para>
    /// This operation checks the certificate-chain hash and all transfer entries,
    /// binding the signing key to the final current Owner. It does not validate certificate
    /// trust or the Device-held header HMAC. The new key uses
    /// SubjectPublicKeyInfo, and the Owner key types must match.
    /// </para>
    /// </remarks>
    /// <param name="encodedZeroEntryVoucher">The retained encoded voucher, with or without prior entries.</param>
    /// <param name="currentOwnerSigningKey">The private key for the voucher's current Owner.</param>
    /// <param name="approvedNewOwnerPublicKey">The public key the host approved for this transfer.</param>
    /// <returns>The extended voucher and its exact components for a paired Owner.</returns>
    public static FdoTransferredOwnershipVoucher Extend(
        ReadOnlyMemory<byte> encodedZeroEntryVoucher,
        ECDsa currentOwnerSigningKey,
        ECDsa approvedNewOwnerPublicKey) =>
        ExtendCore(encodedZeroEntryVoucher, currentOwnerSigningKey, approvedNewOwnerPublicKey);

    /// <summary>Extends a voucher to the approved ECDSA key of a leaf-first DER certificate chain.</summary>
    /// <param name="encodedVoucher">The exact bytes of the ownership voucher.</param>
    /// <param name="currentOwnerSigningKey">The private key of the current voucher Owner.</param>
    /// <param name="approvedNewOwnerCertificates">
    /// The approved new Owner certificate chain, starting with the leaf.
    /// </param>
    /// <remarks>
    /// The new voucher entry retains the exact certificates using FDO X5CHAIN.
    /// The caller authorizes the leaf key and any use of attached certificates.
    /// This does not establish certificate trust or support a CA Owner.
    /// </remarks>
    public static FdoTransferredOwnershipVoucher ExtendWithCertificateChain(
        ReadOnlyMemory<byte> encodedVoucher, ECDsa currentOwnerSigningKey,
        IReadOnlyList<ReadOnlyMemory<byte>> approvedNewOwnerCertificates) =>
        ExtendCore(encodedVoucher, currentOwnerSigningKey, null,
            new FdoPublicKeyCodec().EncodeCertificateChain(approvedNewOwnerCertificates));

    /// <summary>Extends an Ownership Voucher to an approved RSA Owner key.</summary>
    /// <remarks>
    /// The host must authorize the voucher and new key. RSA key type and size
    /// must remain consistent throughout the chain. This does not establish
    /// Device certificate trust or verify the Device-held header HMAC.
    /// </remarks>
    /// <param name="encodedZeroEntryVoucher">The retained encoded voucher, with or without prior entries.</param>
    /// <param name="currentOwnerSigningKey">The private key for the voucher's current Owner.</param>
    /// <param name="approvedNewOwnerPublicKey">The public key the host approved for this transfer.</param>
    /// <returns>The extended voucher and its exact components for a paired Owner.</returns>
    public static FdoTransferredOwnershipVoucher ExtendRsa(
        ReadOnlyMemory<byte> encodedZeroEntryVoucher,
        RSA currentOwnerSigningKey,
        RSA approvedNewOwnerPublicKey) =>
        ExtendCore(encodedZeroEntryVoucher, currentOwnerSigningKey, approvedNewOwnerPublicKey);

    private static FdoTransferredOwnershipVoucher ExtendCore(
        ReadOnlyMemory<byte> encodedZeroEntryVoucher,
        AsymmetricAlgorithm currentOwnerSigningKey,
        AsymmetricAlgorithm? approvedNewOwnerPublicKey,
        ReadOnlyMemory<byte>? encodedNewOwnerPublicKey = null)
    {
        ArgumentNullException.ThrowIfNull(currentOwnerSigningKey);
        if (encodedNewOwnerPublicKey is null)
        {
            ArgumentNullException.ThrowIfNull(approvedNewOwnerPublicKey);
        }

        var cbor = new FdoCborCodec();
        var reader = new CborReader(cbor.ValidateAndCopy(encodedZeroEntryVoucher), CborConformanceMode.Canonical);
        if (reader.PeekState() != CborReaderState.StartArray || reader.ReadStartArray() != 5)
        {
            throw new CborContentException("An Ownership Voucher must contain five fields.");
        }

        ReadOnlyMemory<byte> version = reader.ReadEncodedValue();
        var versionReader = new CborReader(version, CborConformanceMode.Canonical);
        if (versionReader.PeekState() != CborReaderState.UnsignedInteger || versionReader.ReadUInt64() != 200)
        {
            throw new CborContentException("The Ownership Voucher must use FDO 2.0.");
        }

        ReadOnlyMemory<byte> headerTag = reader.ReadEncodedValue();
        ReadOnlyMemory<byte> encodedHmac = reader.ReadEncodedValue();
        ReadOnlyMemory<byte> certificateChain = reader.ReadEncodedValue();
        if (reader.PeekState() != CborReaderState.StartArray)
        {
            throw new CborContentException("The Ownership Voucher must contain a transfer-entry array.");
        }

        int entryCount = reader.ReadStartArray()
            ?? throw new CborContentException("The transfer-entry array must have a definite length.");
        if (entryCount >= byte.MaxValue)
        {
            throw new CborContentException("The extended Ownership Voucher would exceed the transfer-entry limit.");
        }

        var entries = new List<ReadOnlyMemory<byte>>(entryCount + 1);
        long entryBytes = 0;
        for (int i = 0; i < entryCount; i++)
        {
            ReadOnlyMemory<byte> priorEntry = reader.ReadEncodedValue();
            entries.Add(priorEntry);
            entryBytes += priorEntry.Length;
        }

        reader.ReadEndArray();
        reader.ReadEndArray();

        FdoOwnershipVoucherHeader header = FdoOwnershipVoucherHeader.Decode(headerTag, cbor);
        FdoHashValue hmac = FdoHashValue.Decode(encodedHmac);
        FdoHashAlgorithm digest = hmac.Algorithm switch
        {
            FdoHashAlgorithm.HmacSha256 => FdoHashAlgorithm.Sha256,
            FdoHashAlgorithm.HmacSha384 => FdoHashAlgorithm.Sha384,
            _ => throw new CborContentException("An Ownership Voucher header requires an HMAC."),
        };
        var keys = new FdoPublicKeyCodec();
        using FdoPublicKeyCodec.DecodedKey originalOwner = keys.Decode(header.ManufacturerKey);
        using FdoPublicKeyCodec.DecodedKey signingKey =
            keys.Decode(keys.EncodeOwnerKey(currentOwnerSigningKey, originalOwner.KeyType));
        using FdoPublicKeyCodec.DecodedKey newOwner =
            keys.Decode(encodedNewOwnerPublicKey ?? keys.EncodeOwnerKey(approvedNewOwnerPublicKey!, originalOwner.KeyType));
        if (originalOwner.KeyType != newOwner.KeyType || originalOwner.Algorithm != newOwner.Algorithm)
        {
            throw new CryptographicException("The new Owner key type and algorithm must match the voucher's current Owner.");
        }

        using (var original = new FdoOwnershipVoucherChainVerifier(headerTag, encodedHmac, entryCount))
        {
            original.CheckDeviceCertificateChain(certificateChain);
            for (int i = 0; i < entryCount; i++)
            {
                original.AppendEntry(i, entries[i]);
            }

            digest = original.CompleteInternalConsistency(signingKey.Encoded) ?? digest;
        }

        FdoHashValue previousHash = FdoHashValue.ComputeDigest(
            digest, entryCount == 0
                ? header.CreateInitialEntryHashInput(encodedHmac.Span) : entries[^1].Span);
        FdoHashValue headerInfoHash = FdoHashValue.ComputeDigest(digest, header.CreateHeaderInfo());
        var payloadWriter = new CborWriter(CborConformanceMode.Canonical);
        payloadWriter.WriteStartArray(4);
        payloadWriter.WriteEncodedValue(previousHash.Encode().Span);
        payloadWriter.WriteEncodedValue(headerInfoHash.Encode().Span);
        payloadWriter.WriteNull();
        payloadWriter.WriteEncodedValue(newOwner.Encoded.Span);
        payloadWriter.WriteEndArray();

        var signatures = new FdoCoseSign1Codec();
        ReadOnlyMemory<byte> entry = signatures.Sign(
            FdoSignatureOperation.OVEntry, originalOwner.Algorithm,
            currentOwnerSigningKey, payloadWriter.Encode());
        entries.Add(entry);
        using (var extended = new FdoOwnershipVoucherChainVerifier(headerTag, encodedHmac, entries.Count))
        {
            for (int i = 0; i < entries.Count; i++)
            {
                extended.AppendEntry(i, entries[i]);
            }

            extended.CompleteInternalConsistency(newOwner.Encoded);
        }

        long encodedLength = 1L + version.Length + headerTag.Length + encodedHmac.Length +
            certificateChain.Length + FdoCborCodec.GetHeaderSize((ulong)entries.Count) + entryBytes + entry.Length;
        if (encodedLength > ushort.MaxValue)
        {
            throw new CborContentException("The extended Ownership Voucher exceeds the byte limit.");
        }

        var writer = new CborWriter(CborConformanceMode.Canonical, initialCapacity: (int)encodedLength);
        writer.WriteStartArray(5);
        writer.WriteEncodedValue(version.Span);
        writer.WriteEncodedValue(headerTag.Span);
        writer.WriteEncodedValue(encodedHmac.Span);
        writer.WriteEncodedValue(certificateChain.Span);
        writer.WriteStartArray(entries.Count);
        foreach (ReadOnlyMemory<byte> retainedEntry in entries)
        {
            writer.WriteEncodedValue(retainedEntry.Span);
        }
        writer.WriteEndArray();
        writer.WriteEndArray();
        ReadOnlyMemory<byte> voucher = cbor.ValidateAndCopy(writer.Encode());
        return new FdoTransferredOwnershipVoucher(voucher, headerTag, encodedHmac, certificateChain, entries);
    }
}

/// <summary>An extended Ownership Voucher and the components needed by the paired Owner.</summary>
public sealed class FdoTransferredOwnershipVoucher
{
    private readonly byte[] _voucher;
    private readonly byte[] _headerTag;
    private readonly byte[] _headerHmac;
    private readonly byte[] _certificateChain;
    private readonly byte[][] _entries;

    internal FdoTransferredOwnershipVoucher(
        ReadOnlyMemory<byte> voucher,
        ReadOnlyMemory<byte> headerTag,
        ReadOnlyMemory<byte> headerHmac,
        ReadOnlyMemory<byte> certificateChain,
        IReadOnlyList<ReadOnlyMemory<byte>> entries)
    {
        _voucher = voucher.ToArray();
        _headerTag = headerTag.ToArray();
        _headerHmac = headerHmac.ToArray();
        _certificateChain = certificateChain.ToArray();
        _entries = new byte[entries.Count][];
        for (int i = 0; i < entries.Count; i++)
        {
            _entries[i] = entries[i].ToArray();
        }
    }

    /// <summary>The complete encoded voucher with all signed entries.</summary>
    public ReadOnlyMemory<byte> EncodedVoucher => (byte[])_voucher.Clone();

    /// <summary>The original encoded voucher header, including its byte-string wrapper.</summary>
    public ReadOnlyMemory<byte> EncodedVoucherHeaderTag => (byte[])_headerTag.Clone();

    /// <summary>The original encoded voucher header HMAC.</summary>
    public ReadOnlyMemory<byte> EncodedVoucherHeaderHmac => (byte[])_headerHmac.Clone();

    /// <summary>The original encoded Device attestation certificate chain.</summary>
    public ReadOnlyMemory<byte> EncodedDeviceCertificateChain => (byte[])_certificateChain.Clone();

    /// <summary>All signed transfer entries in their original order, suitable for the paired Owner.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> EncodedVoucherEntries
    {
        get
        {
            var entries = new ReadOnlyMemory<byte>[_entries.Length];
            for (int i = 0; i < entries.Length; i++)
            {
                entries[i] = (byte[])_entries[i].Clone();
            }

            return Array.AsReadOnly(entries);
        }
    }
}
