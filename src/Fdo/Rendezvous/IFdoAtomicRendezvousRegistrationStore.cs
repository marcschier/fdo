// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Rendezvous;

/// <summary>Host-owned durable storage for direct Owner and delegated Rendezvous records.</summary>
/// <remarks>
/// This interface does not enable delegated TO0 or TO1. Use one storage
/// authority for a Device: do not write its records through the legacy
/// GUID-only store at the same time. Only trusted host code may construct
/// mutations, after authenticating the registration and authorizing its
/// admission. The adapter protects persisted records and receipts from
/// modification and enforces host storage limits.
/// </remarks>
public interface IFdoAtomicRendezvousRegistrationStore
{
    /// <summary>Reads one consistent snapshot with all live records for the Device.</summary>
    /// <param name="deviceId">The Device identity associated with the operation.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <remarks>
    /// Use the adapter's trusted clock. A record is live only while the clock
    /// is strictly earlier than its expiry. Return the current revision even
    /// if every record expired; null denotes a Device with no successful write.
    /// Do not truncate results. Consumers must recheck expiry before use.
    /// </remarks>
    ValueTask<FdoRendezvousRegistrationSnapshot> ReadAsync(
        Guid deviceId, CancellationToken cancellationToken);

    /// <summary>Conditionally writes one record and its mutation receipt.</summary>
    /// <param name="mutation">The proposed atomic change to the registration.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <remarks>
    /// <para>
    /// In one transaction check the receipt, expected revision, expiry,
    /// replacement authorization and storage limits, then write the record,
    /// the new revision (the incoming registration ID), and the receipt.
    /// The slot is the direct Owner slot or the slot for the normalized
    /// delegate source address. Do not modify another slot. A live occupant
    /// with a different authenticated identity may be replaced only if this
    /// mutation authorizes replacing that exact registration ID. After
    /// expiry a slot is vacant, but the revision still fences stale writers.
    /// A mutation with an expired incoming record must not commit.
    /// </para>
    /// <para>
    /// Return <see cref="FdoRendezvousMutationResult.Applied"/> only after the
    /// commit is durable or if a durable receipt already matches the exact
    /// mutation. Compare every input, including original encoded bytes,
    /// normalized address, identity, expiry, authorization and expected
    /// revision; reusing the ID with different inputs is a conflict. An
    /// exception or cancellation does not prove that the mutation rolled back.
    /// </para>
    /// </remarks>
    ValueTask<FdoRendezvousMutationResult> TryWriteAsync(
        FdoRendezvousRegistrationMutation mutation, CancellationToken cancellationToken);

    /// <summary>Checks whether the exact mutation is known to have committed.</summary>
    /// <param name="mutation">The proposed atomic change to the registration.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    /// <remarks>
    /// A successful receipt remains queryable after replacement and expiry
    /// throughout the host's reconciliation window, which must cover all
    /// outstanding uncertain writes. Return false when no receipt is present;
    /// that alone does not prove an in-flight write did not commit. The host
    /// must reconcile or fence the outstanding writer before attempting a
    /// fresh authenticated protocol run. Do not replay a protocol exchange.
    /// </remarks>
    ValueTask<bool> HasCommittedAsync(
        FdoRendezvousRegistrationMutation mutation, CancellationToken cancellationToken);
}

/// <summary>A direct Owner or Delegate record admitted by the host.</summary>
public sealed class FdoRendezvousRegistrationRecord
{
    private readonly byte[]? _delegateSource;

    /// <summary>Snapshots a record and its verified storage identity.</summary>
    /// <param name="registration">Detached accepted registration fields, including the exact signed blob.</param>
    /// <param name="authenticatedIdentity">
    /// A stable, nonempty identity assigned by the host after authentication.
    /// It must not be a caller-supplied ID or be derived solely from an address.
    /// </param>
    /// <param name="delegateSource">
    /// Null for a direct Owner; otherwise the host-observed delegate source
    /// address, not the signed TO2 destination. Behind a reverse proxy the
    /// host must resolve the observed address through an explicitly trusted
    /// proxy path; do not pass an unverified forwarded address or the proxy
    /// address in place of the submitter's. IPv4-mapped IPv6 becomes IPv4.
    /// Nonzero IPv6 scope IDs are unsupported.
    /// </param>
    public FdoRendezvousRegistrationRecord(
        FdoRendezvousRegistration registration, Guid authenticatedIdentity, IPAddress? delegateSource)
    {
        ArgumentNullException.ThrowIfNull(registration);
        if (authenticatedIdentity == Guid.Empty)
        {
            throw new ArgumentException("An authenticated identity must not be empty.", nameof(authenticatedIdentity));
        }

        _delegateSource = delegateSource is null ? null : NormalizeSource(delegateSource);

        Registration = registration;
        AuthenticatedIdentity = authenticatedIdentity;
        DeviceId = new Guid(registration.DeviceGuid.Span, bigEndian: true);
    }

    internal static byte[] NormalizeSource(IPAddress source)
    {
        if (source.AddressFamily == AddressFamily.InterNetworkV6 && source.ScopeId != 0)
        {
            throw new ArgumentException("Scoped IPv6 submitter addresses are unsupported.", nameof(source));
        }

        return (source.IsIPv4MappedToIPv6 ? source.MapToIPv4() : source).GetAddressBytes();
    }

    /// <summary>The Device GUID interpreted in wire byte order.</summary>
    public Guid DeviceId { get; }

    /// <summary>The exact accepted registration fields.</summary>
    public FdoRendezvousRegistration Registration { get; }

    /// <summary>The host-authenticated record identity.</summary>
    public Guid AuthenticatedIdentity { get; }

    /// <summary>The normalized source address, or null for a direct Owner record.</summary>
    public IPAddress? DelegateSource => _delegateSource is null ? null : new IPAddress(_delegateSource);
}

/// <summary>One conditional mutation of a Device's Rendezvous records.</summary>
public sealed class FdoRendezvousRegistrationMutation
{
    /// <summary>Creates a mutation with an expected revision and optional replacement authorization.</summary>
    /// <param name="record">
    /// The admitted record. Its registration ID is the mutation ID; never reuse it
    /// for different inputs for this Device, even after expiry.
    /// </param>
    /// <param name="expectedRevision">The snapshot revision, or null before the first write.</param>
    /// <param name="authorizedReplacementOf">
    /// A live incumbent registration ID, or null. Set this only if trusted host
    /// policy authorized this exact incoming mutation and authenticated identity
    /// to replace that exact incumbent. Sharing a source IP is not authorization.
    /// </param>
    public FdoRendezvousRegistrationMutation(
        FdoRendezvousRegistrationRecord record, Guid? expectedRevision, Guid? authorizedReplacementOf = null)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (expectedRevision == Guid.Empty || expectedRevision == record.Registration.RegistrationId)
        {
            throw new ArgumentException("The expected revision must be a different, nonempty ID.", nameof(expectedRevision));
        }

        if (authorizedReplacementOf == Guid.Empty || authorizedReplacementOf == record.Registration.RegistrationId)
        {
            throw new ArgumentException("The incumbent must have a different, nonempty ID.", nameof(authorizedReplacementOf));
        }

        Record = record;
        ExpectedRevision = expectedRevision;
        AuthorizedReplacementOf = authorizedReplacementOf;
    }

    /// <summary>The admitted record to write.</summary>
    public FdoRendezvousRegistrationRecord Record { get; }

    /// <summary>The required current Device revision.</summary>
    public Guid? ExpectedRevision { get; }

    /// <summary>The exact incumbent the host has explicitly authorized this mutation to replace.</summary>
    public Guid? AuthorizedReplacementOf { get; }
}

/// <summary>A detached, consistent view of one Device's live Rendezvous records.</summary>
public sealed class FdoRendezvousRegistrationSnapshot
{
    /// <summary>Snapshots one view returned by the host store.</summary>
    /// <param name="revision">The revision of the registration to compare or update.</param>
    /// <param name="records">The ordered registration snapshot.</param>
    public FdoRendezvousRegistrationSnapshot(Guid? revision, IReadOnlyList<FdoRendezvousRegistrationRecord> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        if (revision == Guid.Empty || (revision is null && records.Count != 0))
        {
            throw new ArgumentException("A snapshot with records must have a nonempty revision.", nameof(revision));
        }

        var copy = new FdoRendezvousRegistrationRecord[records.Count];
        var slots = new HashSet<IPAddress?>();
        Guid? deviceId = null;
        for (int i = 0; i < copy.Length; i++)
        {
            FdoRendezvousRegistrationRecord record = records[i] ??
                throw new ArgumentException("Snapshot records must not be null.", nameof(records));
            deviceId ??= record.DeviceId;
            if (deviceId != record.DeviceId || !slots.Add(record.DelegateSource))
            {
                throw new ArgumentException("Records must share a Device and occupy distinct slots.", nameof(records));
            }

            copy[i] = record;
        }

        Revision = revision;
        Records = Array.AsReadOnly(copy);
    }

    /// <summary>The current revision, including when there are no live records.</summary>
    public Guid? Revision { get; }

    /// <summary>All live records observed at read time, in no prescribed order.</summary>
    public IReadOnlyList<FdoRendezvousRegistrationRecord> Records { get; }
}

/// <summary>The outcome of an atomic Rendezvous write.</summary>
public enum FdoRendezvousMutationResult
{
    /// <summary>No mutation was applied because the expected revision was stale.</summary>
    RevisionConflict = 0,

    /// <summary>The exact mutation committed durably.</summary>
    Applied = 1,

    /// <summary>The write was denied because it would replace a live record without authorization.</summary>
    ReplacementNotAuthorized = 2,

    /// <summary>The incoming record expired before the write.</summary>
    Expired = 3,

    /// <summary>Host storage limits prevented the write.</summary>
    CapacityExceeded = 4,

    /// <summary>The registration ID already identifies a different committed mutation.</summary>
    MutationIdConflict = 5,
}
