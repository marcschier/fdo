// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using Fdo.Cryptography;

namespace Fdo.Transport.Http;

/// <summary>One configured private CA trust anchor for an HTTPS role run.</summary>
/// <remarks>
/// The platform still validates the server name, certificate validity and
/// server authentication usage. Only the configured CA is trusted; a failed
/// chain check does not fall back to platform roots. This bounded policy
/// does not fetch certificates or check revocation. Select the anchor
/// independently of the untrusted endpoint or Rendezvous result.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoHttpPrivateTrust
{
    private readonly byte[] _anchor;

    /// <summary>Snapshots one nonempty DER-encoded CA certificate, up to 65,535 bytes.</summary>
    public FdoHttpPrivateTrust(ReadOnlyMemory<byte> derTrustAnchor)
    {
        if (derTrustAnchor.IsEmpty || derTrustAnchor.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(derTrustAnchor));
        }

        _anchor = derTrustAnchor.ToArray();
        using X509Certificate2 anchor = OpenAnchor();
        if (anchor.Extensions["2.5.29.19"] is not X509BasicConstraintsExtension { CertificateAuthority: true } ||
            (anchor.Extensions["2.5.29.15"] is X509KeyUsageExtension usage &&
             !usage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign)))
        {
            throw new ArgumentException("The private HTTPS trust anchor must be a certificate authority.", nameof(derTrustAnchor));
        }
    }

    internal X509Certificate2 OpenAnchor() => FdoDerEncoding.LoadCertificate(_anchor);
}
