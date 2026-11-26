using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Enrollment;

/// <summary>
/// Decides whether a Device accepts a Delegate that signed the Owner proof.
/// </summary>
/// <remarks>
/// The session calls this once per delegated run. By then the Delegate chain
/// has verified against the voucher's final Owner key, the Owner key is bound
/// to the whole voucher, the proof signature has verified, and any TO1
/// redirect has verified against the Owner key, including acceptance of a
/// separate redirect Delegate. The session has not derived a
/// session key or exchanged ServiceInfo. A valid chain only shows that the
/// Owner issued the Delegate; return true only when host policy also allows
/// this Delegate to onboard the Device. Returning false or throwing ends the
/// run before any protected message is sent.
/// </remarks>
public interface IFdoDeviceDelegateAcceptance
{
    /// <summary>Returns true to continue the run with this Delegate.</summary>
    ValueTask<bool> AcceptAsync(FdoDelegateEvidence evidence, CancellationToken cancellationToken);
}

/// <summary>
/// The verified Delegate that signed an Owner proof, detached from the
/// session. Byte values are copies.
/// </summary>
public sealed class FdoDelegateEvidence
{
    private readonly byte[] _leafCertificate;
    private readonly byte[] _delegateKey;
    private readonly byte[] _ownerKey;

    internal FdoDelegateEvidence(
        ReadOnlyMemory<byte> leafCertificate,
        ReadOnlyMemory<byte> delegateKey,
        ReadOnlyMemory<byte> ownerKey,
        bool mayRedirect,
        bool mayOnboardNewCredentials,
        bool mayOnboardReuseCredentials)
    {
        _leafCertificate = leafCertificate.ToArray();
        _delegateKey = delegateKey.ToArray();
        _ownerKey = ownerKey.ToArray();
        MayRedirect = mayRedirect;
        MayOnboardNewCredentials = mayOnboardNewCredentials;
        MayOnboardReuseCredentials = mayOnboardReuseCredentials;
    }

    /// <summary>The DER Delegate leaf certificate.</summary>
    public ReadOnlyMemory<byte> LeafCertificate => (byte[])_leafCertificate.Clone();

    /// <summary>The Delegate leaf key as a CBOR-encoded FDO PublicKey.</summary>
    public ReadOnlyMemory<byte> DelegatePublicKey => (byte[])_delegateKey.Clone();

    /// <summary>The voucher's final Owner key as a CBOR-encoded FDO PublicKey.</summary>
    public ReadOnlyMemory<byte> OwnerPublicKey => (byte[])_ownerKey.Clone();

    /// <summary>Whether every certificate in the chain permits signing a TO1 redirect.</summary>
    public bool MayRedirect { get; }

    /// <summary>Whether every certificate in the chain permits the credential-replacement disposition.</summary>
    public bool MayOnboardNewCredentials { get; }

    /// <summary>Whether every certificate in the chain permits the credential-reuse disposition.</summary>
    public bool MayOnboardReuseCredentials { get; }
}

/// <summary>The Device host did not accept the Delegate that signed the Owner proof.</summary>
public sealed class FdoDelegateNotAcceptedException : InvalidOperationException
{
    /// <summary>Creates the exception.</summary>
    public FdoDelegateNotAcceptedException()
        : base("The Device host did not accept the Owner Delegate.")
    {
    }
}
