using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Rendezvous;

/// <summary>Host policy for an authenticated atomic Rendezvous registration.</summary>
public interface IFdoRendezvousRegistrationAdmission
{
    /// <summary>Returns a trusted storage identity and any explicit replacement permission, or null to deny.</summary>
    /// <remarks>
    /// The callback runs after voucher, nonce, redirect signature, and any
    /// Delegate permission checks. It does not write the store. A subsequent
    /// write uses this snapshot's revision and can be rejected as stale.
    /// Assign identities from authenticated keys and host policy, never from
    /// caller claims, the observed source alone, or the signed TO2 address.
    /// </remarks>
    ValueTask<FdoRendezvousRegistrationGrant?> AuthorizeAsync(
        FdoRendezvousRegistrationEvidence evidence, CancellationToken cancellationToken);
}

/// <summary>A host decision authorizing one authenticated registration.</summary>
/// <param name="AuthenticatedIdentity">A stable, nonempty identity assigned by trusted host policy.</param>
/// <param name="AuthorizedReplacementOf">
/// The current registration ID the policy permits this exact write to replace,
/// or null if no cross-identity replacement is allowed.
/// </param>
public sealed record FdoRendezvousRegistrationGrant(Guid AuthenticatedIdentity, Guid? AuthorizedReplacementOf = null);

/// <summary>Detached evidence of a verified direct Owner or Delegate registration.</summary>
public sealed class FdoRendezvousRegistrationEvidence
{
    private readonly byte[] _signingKey;
    private readonly byte[]? _delegateSource;

    internal FdoRendezvousRegistrationEvidence(
        FdoRendezvousRegistration registration, ReadOnlyMemory<byte> signingKey, IPAddress? delegateSource,
        FdoRendezvousRegistrationSnapshot current)
    {
        Registration = registration;
        _signingKey = signingKey.ToArray();
        _delegateSource = delegateSource?.GetAddressBytes();
        Current = current;
    }

    /// <summary>The verified voucher fields, exact signed redirect and proposed expiry.</summary>
    public FdoRendezvousRegistration Registration { get; }

    /// <summary>The exact encoded FDO key that verified the redirect signature.</summary>
    public ReadOnlyMemory<byte> SigningKey => (byte[])_signingKey.Clone();

    /// <summary>The normalized observed submitter address; null for a direct Owner.</summary>
    public IPAddress? DelegateSource => _delegateSource is null ? null : new IPAddress(_delegateSource);

    /// <summary>The snapshot whose revision fences the subsequent write.</summary>
    public FdoRendezvousRegistrationSnapshot Current { get; }
}
