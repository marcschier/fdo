// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Initialization;

namespace Fdo.Enrollment;

/// <summary>Owner configuration for the provisional paired replacement disposition.</summary>
public sealed class FdoOwnerReplacementOptions
{
    /// <summary>
    /// The distinct Owner2 signing key, using the current Owner's FDO key type
    /// and signing algorithm. The caller retains it without concurrent use
    /// until the Owner session is disposed.
    /// </summary>
    public required AsymmetricAlgorithm Owner2SigningKey { get; init; }

    /// <summary>Encoded replacement RendezvousInfo, including rvserver.local.</summary>
    public required ReadOnlyMemory<byte> EncodedRendezvousInfo { get; init; }

    /// <summary>Host callback for the replacement voucher's durable commit.</summary>
    public required IFdoOwnerReplacementHandler Handler { get; init; }
}

/// <summary>Persists a replacement voucher after authenticated Done20.</summary>
/// <remarks>
/// A successful return does not prove receipt of DoneAck20. If this callback
/// throws or is canceled, its durable outcome can be unknown. The host must
/// reconcile it, and any separate enrollment commit, before another run.
/// The Owner cannot independently verify the Device-held HMAC secret.
/// </remarks>
public interface IFdoOwnerReplacementHandler
{
    /// <summary>Durably commits the exact replacement voucher.</summary>
    /// <param name="replacement">The options or evidence for replacing the Device credential.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask CommitAsync(FdoOwnerReplacementCommit replacement, CancellationToken cancellationToken);
}

/// <summary>Authenticated replacement voucher evidence for one Owner run.</summary>
public sealed class FdoOwnerReplacementCommit
{
    private readonly byte[] _previousGuid;
    private readonly byte[] _replacementGuid;
    private readonly byte[] _header;
    private readonly byte[] _hmac;
    private readonly byte[] _voucher;

    internal FdoOwnerReplacementCommit(
        Guid runId,
        ReadOnlyMemory<byte> previousGuid,
        ReadOnlyMemory<byte> replacementGuid,
        ReadOnlyMemory<byte> header,
        ReadOnlyMemory<byte> hmac,
        ReadOnlyMemory<byte> voucher)
    {
        RunId = runId;
        _previousGuid = previousGuid.ToArray();
        _replacementGuid = replacementGuid.ToArray();
        _header = header.ToArray();
        _hmac = hmac.ToArray();
        _voucher = voucher.ToArray();
    }

    /// <summary>The local Owner run identifier.</summary>
    public Guid RunId { get; }
    /// <summary>The authenticated previous Device GUID in wire order.</summary>
    public ReadOnlyMemory<byte> PreviousDeviceGuid => (byte[])_previousGuid.Clone();
    /// <summary>The proposed replacement Device GUID in wire order.</summary>
    public ReadOnlyMemory<byte> ReplacementDeviceGuid => (byte[])_replacementGuid.Clone();
    /// <summary>The exact encoded replacement voucher header tag.</summary>
    public ReadOnlyMemory<byte> EncodedVoucherHeaderTag => (byte[])_header.Clone();
    /// <summary>The exact HMAC received in authenticated Done20.</summary>
    public ReadOnlyMemory<byte> EncodedVoucherHeaderHmac => (byte[])_hmac.Clone();
    /// <summary>The encoded zero-entry replacement voucher.</summary>
    public ReadOnlyMemory<byte> EncodedVoucher => (byte[])_voucher.Clone();
}

/// <summary>Reserves, stages, and activates a Device replacement credential.</summary>
/// <remarks>
/// The host must generate a fresh, confidential HMAC secret with a
/// cryptographically secure random number generator and keep its handle durable
/// without exporting the secret. It must authorize the new rendezvous
/// information and Owner key. The library cannot determine whether different
/// handles refer to the same secret. Staging must not replace the active
/// credential. Activation atomically replaces the old
/// credential and leaves FDO dormant for resale. A throwing or canceled
/// callback can have an unknown durable outcome. A lost DoneAck can leave the
/// Owner committed while the old Device credential remains active; reconcile all
/// uncertain effects and any staged, inactive credential before another run.
/// Activation after DoneAck20 is a paired choice that differs from the
/// credential transition in FDO sections 5.5.11 and 5.5.14.
/// </remarks>
public interface IFdoDeviceReplacementHandler
{
    /// <summary>Reserves a fresh protected HMAC secret for the proposal.</summary>
    /// <param name="proposal">The manufacturer's proposed voucher header and Device certificate chain.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask<IFdoDeviceInitializeHmacSecret> ReserveSecretAsync(
        FdoDeviceReplacementProposal proposal, CancellationToken cancellationToken);

    /// <summary>Durably stages the proposal and secret without replacing the active credential.</summary>
    /// <param name="credential">The Device credential for this operation.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask StageAsync(FdoDeviceReplacementCredential credential, CancellationToken cancellationToken);

    /// <summary>Atomically installs the staged credential after authenticated DoneAck20.</summary>
    /// <param name="credential">The Device credential for this operation.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask ActivateAsync(FdoDeviceReplacementCredential credential, CancellationToken cancellationToken);
}

/// <summary>Authenticated replacement values, awaiting host authorization and a secret.</summary>
public sealed class FdoDeviceReplacementProposal
{
    private readonly byte[] _previousGuid;
    private readonly byte[] _guid;
    private readonly byte[] _header;
    private readonly byte[] _rendezvous;
    private readonly byte[] _ownerKey;
    private readonly byte[] _ownerKeyHash;

    internal FdoDeviceReplacementProposal(
        Guid runId,
        ReadOnlyMemory<byte> previousGuid,
        ReadOnlyMemory<byte> guid,
        ReadOnlyMemory<byte> header,
        ReadOnlyMemory<byte> rendezvous,
        ReadOnlyMemory<byte> ownerKey,
        ReadOnlyMemory<byte> ownerKeyHash,
        FdoDeviceHmacAlgorithm algorithm)
    {
        RunId = runId;
        _previousGuid = previousGuid.ToArray();
        _guid = guid.ToArray();
        _header = header.ToArray();
        _rendezvous = rendezvous.ToArray();
        _ownerKey = ownerKey.ToArray();
        _ownerKeyHash = ownerKeyHash.ToArray();
        VoucherHmacAlgorithm = algorithm;
    }

    /// <summary>The local Device run identifier.</summary>
    public Guid RunId { get; }
    /// <summary>The current Device GUID in wire order.</summary>
    public ReadOnlyMemory<byte> PreviousDeviceGuid => (byte[])_previousGuid.Clone();
    /// <summary>The replacement Device GUID in wire order.</summary>
    public ReadOnlyMemory<byte> ReplacementDeviceGuid => (byte[])_guid.Clone();
    /// <summary>The exact replacement voucher header tag.</summary>
    public ReadOnlyMemory<byte> EncodedVoucherHeaderTag => (byte[])_header.Clone();
    /// <summary>The encoded replacement rendezvous instructions.</summary>
    public ReadOnlyMemory<byte> EncodedRendezvousInfo => (byte[])_rendezvous.Clone();
    /// <summary>The encoded replacement Owner public key.</summary>
    public ReadOnlyMemory<byte> EncodedOwnerPublicKey => (byte[])_ownerKey.Clone();
    /// <summary>The encoded FDO Hash of the replacement Owner public key.</summary>
    public ReadOnlyMemory<byte> EncodedOwnerPublicKeyHash => (byte[])_ownerKeyHash.Clone();
    /// <summary>The HMAC algorithm required for the new secret.</summary>
    public FdoDeviceHmacAlgorithm VoucherHmacAlgorithm { get; }
}

/// <summary>A replacement proposal and its opaque, host-owned secret handle.</summary>
public sealed class FdoDeviceReplacementCredential
{
    internal FdoDeviceReplacementCredential(
        FdoDeviceReplacementProposal proposal, IFdoDeviceInitializeHmacSecret secret)
    {
        Proposal = proposal;
        VoucherHmacSecret = secret;
    }

    /// <summary>The authenticated and host-authorized replacement values.</summary>
    public FdoDeviceReplacementProposal Proposal { get; }
    /// <summary>The host-owned replacement secret handle.</summary>
    public IFdoDeviceInitializeHmacSecret VoucherHmacSecret { get; }
}
