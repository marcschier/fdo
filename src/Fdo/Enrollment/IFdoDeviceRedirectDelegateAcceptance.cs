// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Rendezvous;

namespace Fdo.Enrollment;

/// <summary>
/// Decides whether a Device accepts a Delegate that signed its TO1 redirect.
/// </summary>
/// <remarks>
/// The session calls this once for a delegated rendezvous blob. By then the
/// Delegate chain has verified against the voucher's final Owner key, carries
/// the redirect permission, and its leaf key has signed the exact blob; the
/// Owner key is bound to the whole voucher and the TO2 Owner proof signature
/// has verified. The session has not derived a session key or exchanged
/// ServiceInfo. Acceptance covers only the redirect: it does not authorize
/// any Delegate to onboard the Device, and a TO2 Delegate is accepted
/// separately through <see cref="IFdoDeviceDelegateAcceptance"/>. Returning
/// false or throwing ends the run before any protected message is sent.
/// </remarks>
public interface IFdoDeviceRedirectDelegateAcceptance
{
    /// <summary>Returns true to continue the run after this redirect Delegate.</summary>
    ValueTask<bool> AcceptAsync(FdoRedirectDelegateEvidence evidence, CancellationToken cancellationToken);
}

/// <summary>
/// The verified Delegate that signed a TO1 redirect, detached from the
/// session. Byte values are copies.
/// </summary>
public sealed class FdoRedirectDelegateEvidence
{
    private readonly byte[] _leafCertificate;
    private readonly byte[] _delegateKey;
    private readonly byte[] _ownerKey;

    internal FdoRedirectDelegateEvidence(
        ReadOnlyMemory<byte> leafCertificate,
        ReadOnlyMemory<byte> delegateKey,
        ReadOnlyMemory<byte> ownerKey,
        FdoRendezvousAddress address)
    {
        _leafCertificate = leafCertificate.ToArray();
        _delegateKey = delegateKey.ToArray();
        _ownerKey = ownerKey.ToArray();
        Address = address;
    }

    /// <summary>The DER Delegate leaf certificate.</summary>
    public ReadOnlyMemory<byte> LeafCertificate => (byte[])_leafCertificate.Clone();

    /// <summary>The Delegate leaf key as a CBOR-encoded FDO PublicKey.</summary>
    public ReadOnlyMemory<byte> DelegatePublicKey => (byte[])_delegateKey.Clone();

    /// <summary>The voucher's final Owner key as a CBOR-encoded FDO PublicKey.</summary>
    public ReadOnlyMemory<byte> OwnerPublicKey => (byte[])_ownerKey.Clone();

    /// <summary>The Owner address from the verified signed blob.</summary>
    public FdoRendezvousAddress Address { get; }
}

/// <summary>The Device host did not accept the Delegate that signed the TO1 redirect.</summary>
public sealed class FdoRedirectDelegateNotAcceptedException : InvalidOperationException
{
    /// <summary>Creates the exception.</summary>
    public FdoRedirectDelegateNotAcceptedException()
        : base("The Device host did not accept the rendezvous redirect Delegate.")
    {
    }
}
