using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fdo.Serialization;

namespace Fdo.Cryptography;

/// <summary>
/// Applies the paired TO2 restrictions to a Delegate chain. Both roles use
/// these checks: the Owner before it signs, and the Device before it derives
/// a session key. A chain that passes is authentic and usable for this run;
/// the Device host still decides whether it accepts the Delegate.
/// </summary>
/// <remarks>
/// The Delegate leaf key must match the selected key-exchange suite on its own,
/// in the same way that the voucher Owner key must. A suite that would accept
/// only one of the two keys is rejected rather than treated as a mixed-key
/// combination. ASYMKEX is rejected because its Owner exchange key would have
/// to be bound to the Delegate. A chain without any onboarding permission,
/// such as one that may only redirect, is not permitted to onboard and never
/// reaches the onboarding checks. A chain that may onboard but whose
/// permissions require FDO disable is rejected because this library does not
/// implement disable. On the Device, every rejection here happens before key
/// derivation, so the Device sends no Error message.
/// </remarks>
[UnsupportedOSPlatform("browser")]
internal static class FdoTo2DelegatePolicy
{
    private const FdoDelegatePermissions OnboardingPermissions =
        FdoDelegatePermissions.OnboardNewCredentials | FdoDelegatePermissions.OnboardReuseCredentials |
        FdoDelegatePermissions.OnboardDisable;

    /// <summary>
    /// Verifies the chain against the advertised voucher Owner key and applies
    /// the paired TO2 restrictions.
    /// </summary>
    /// <exception cref="FdoDelegateChainException">The chain is not authentic for the Owner key.</exception>
    /// <exception cref="FdoDelegateNotPermittedException">
    /// The chain carries no onboarding permission, for example a chain that may only redirect.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The suite is ASYMKEX, or the chain may onboard but its permissions require FDO disable.
    /// </exception>
    /// <exception cref="CryptographicException">The Delegate key does not match the selected suite.</exception>
    public static FdoVerifiedDelegateChain Verify(
        IReadOnlyList<ReadOnlyMemory<byte>> chain,
        ReadOnlyMemory<byte> ownerKey,
        FdoKeyExchangeSuite exchange,
        DateTimeOffset verificationTime,
        bool captureRevocationTargets = false)
    {
        RequireExchange(exchange);
        FdoVerifiedDelegateChain verified = new FdoDelegateChainVerifier(X509RevocationMode.NoCheck)
            .Verify(chain, ownerKey, verificationTime, captureRevocationTargets);
        if ((verified.Permissions & OnboardingPermissions) == 0)
        {
            throw new FdoDelegateNotPermittedException(OnboardingPermissions);
        }

        if (RequiresDisable(verified.Permissions))
        {
            throw new NotSupportedException("The Delegate permissions require FDO disable, which is not supported.");
        }

        using FdoPublicKeyCodec.DecodedKey delegateKey = new FdoPublicKeyCodec().Decode(verified.DelegateKey);
        FdoTo2OwnerProofCodec.RequireOwnerSuite(exchange, delegateKey);
        return verified;
    }

    /// <summary>Rejects the ASYMKEX suites for a delegated run.</summary>
    /// <exception cref="NotSupportedException">The suite is ASYMKEX.</exception>
    public static void RequireExchange(FdoKeyExchangeSuite exchange)
    {
        if (exchange is FdoKeyExchangeSuite.Asymkex2048 or FdoKeyExchangeSuite.Asymkex3072)
        {
            throw new NotSupportedException("Delegated TO2 does not support ASYMKEX.");
        }
    }

    /// <summary>
    /// Returns true when §5.6 requires FDO disable: the disable permission is
    /// present, or neither credential permission is.
    /// </summary>
    public static bool RequiresDisable(FdoDelegatePermissions permissions) =>
        (permissions & FdoDelegatePermissions.OnboardDisable) != 0 ||
        (permissions & (FdoDelegatePermissions.OnboardNewCredentials |
            FdoDelegatePermissions.OnboardReuseCredentials)) == 0;
}
