// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

/// <summary>Trusted host adapter for already-authenticated local Delegate revocation evidence.</summary>
/// <remarks>
/// Configure this source independently of the peer. The source authenticates
/// and assesses completeness of the underlying evidence for each exact
/// certificate and issuer. It must use only locally available evidence and
/// must not fetch certificates, CRLs or online status. For a bare voucher
/// Owner key it must establish revocation authority independently or return
/// <see cref="FdoDelegateCertificateStatus.NoAuthority"/>.
/// </remarks>
public interface IFdoDelegateOfflineStatusSource
{
    /// <summary>Returns one detached decision per target; missing or ambiguous coverage does not grant authorization.</summary>
    /// <param name="path">The ordered path of certificates or verification targets.</param>
    IReadOnlyList<FdoDelegateOfflineStatus> GetStatuses(IReadOnlyList<FdoDelegateRevocationTarget> path);
}

/// <summary>Identifies one certificate and its actual verified issuer.</summary>
public sealed class FdoDelegateRevocationTarget
{
    private readonly byte[] _certificate;
    private readonly byte[] _issuerKey;
    private readonly byte[]? _issuerCertificate;

    internal FdoDelegateRevocationTarget(
        ReadOnlyMemory<byte> certificate, ReadOnlyMemory<byte> issuerKey, ReadOnlyMemory<byte>? issuerCertificate)
    {
        _certificate = certificate.ToArray();
        _issuerKey = issuerKey.ToArray();
        _issuerCertificate = issuerCertificate?.ToArray();
        CertificateSha256 = Convert.ToHexString(SHA256.HashData(_certificate));
        IssuerKeySha256 = Convert.ToHexString(SHA256.HashData(_issuerKey));
    }

    /// <summary>The exact DER certificate to check.</summary>
    public ReadOnlyMemory<byte> Certificate => (byte[])_certificate.Clone();

    /// <summary>The FDO PublicKey that verified this certificate, encoded as provided by the verifier.</summary>
    public ReadOnlyMemory<byte> IssuerPublicKey => (byte[])_issuerKey.Clone();

    /// <summary>The DER issuer certificate, or null for a bare voucher Owner key.</summary>
    public ReadOnlyMemory<byte>? IssuerCertificate =>
        _issuerCertificate is null ? (ReadOnlyMemory<byte>?)null : (byte[])_issuerCertificate.Clone();

    /// <summary>The uppercase SHA-256 hex digest of <see cref="Certificate"/>.</summary>
    public string CertificateSha256 { get; }

    /// <summary>The uppercase SHA-256 hex digest of <see cref="IssuerPublicKey"/>.</summary>
    public string IssuerKeySha256 { get; }
}

/// <summary>What the authoritative host source established about one certificate.</summary>
public enum FdoDelegateCertificateStatus
{
    /// <summary>The source could not establish revocation status.</summary>
    Unknown = 0,

    /// <summary>The source verified current, complete evidence that the certificate is not revoked.</summary>
    Good = 1,

    /// <summary>The certificate is revoked.</summary>
    Revoked = 2,

    /// <summary>The source lacks revocation authority for this issuer.</summary>
    NoAuthority = 3,
}

/// <summary>An exact local revocation decision returned by the configured source.</summary>
/// <param name="CertificateSha256">The target certificate's uppercase SHA-256 hex digest.</param>
/// <param name="IssuerKeySha256">The target issuer key's uppercase SHA-256 hex digest.</param>
/// <param name="Status">The decision the host authenticated.</param>
/// <param name="ThisUpdate">The start of validity of the underlying evidence.</param>
/// <param name="NextUpdate">The exclusive expiry of the underlying evidence.</param>
public sealed record FdoDelegateOfflineStatus(
    string CertificateSha256, string IssuerKeySha256, FdoDelegateCertificateStatus Status,
    DateTimeOffset ThisUpdate, DateTimeOffset NextUpdate);

/// <summary>Requires current host-authenticated offline status for every verified Delegate certificate.</summary>
/// <remarks>
/// The library checks exact path coverage, binding and freshness. It does
/// not validate the underlying revocation signature or general PKIX. A
/// configured policy never falls back to NoCheck after a denial.
/// </remarks>
public sealed class FdoDelegateOfflineRevocationPolicy
{
    private readonly IFdoDelegateOfflineStatusSource _source;
    private readonly TimeSpan _maximumAge;
    private readonly TimeSpan _maximumLifetime;

    /// <summary>Configures an authoritative offline source and explicit freshness bounds.</summary>
    /// <param name="source">A trusted local source configured by the host.</param>
    /// <param name="maximumAge">Maximum time since ThisUpdate, greater than zero and at most 30 days.</param>
    /// <param name="maximumLifetime">Maximum validity interval, greater than zero and at most 30 days.</param>
    public FdoDelegateOfflineRevocationPolicy(
        IFdoDelegateOfflineStatusSource source, TimeSpan maximumAge, TimeSpan maximumLifetime)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maximumAge, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumAge, TimeSpan.FromDays(30));
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maximumLifetime, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumLifetime, TimeSpan.FromDays(30));
        _source = source;
        _maximumAge = maximumAge;
        _maximumLifetime = maximumLifetime;
    }

    internal void Require(IReadOnlyList<FdoDelegateRevocationTarget> path, DateTimeOffset now)
    {
        IReadOnlyList<FdoDelegateOfflineStatus> supplied = _source.GetStatuses(path);
        if (supplied is null || supplied.Count != path.Count)
        {
            throw new CryptographicException("Offline revocation status does not cover the Delegate path exactly.");
        }

        var seen = new bool[path.Count];
        for (int i = 0; i < path.Count; i++)
        {
            FdoDelegateOfflineStatus? status = supplied[i];
            int matched = -1;
            if (status is not null)
            {
                for (int j = 0; j < path.Count; j++)
                {
                    if (path[j].CertificateSha256 == status.CertificateSha256 &&
                        path[j].IssuerKeySha256 == status.IssuerKeySha256)
                    {
                        matched = j;
                        break;
                    }
                }
            }

            if (matched < 0 || seen[matched])
            {
                throw new CryptographicException("Offline revocation status is duplicated or not bound to the verified Delegate path.");
            }

            seen[matched] = true;
            if (status!.Status == FdoDelegateCertificateStatus.NoAuthority)
            {
                throw new NotSupportedException("The configured offline source has no authority for a Delegate issuer.");
            }

            if (status.Status != FdoDelegateCertificateStatus.Good)
            {
                throw new CryptographicException("Offline revocation status does not establish that the Delegate certificate is good.");
            }

            if (status.ThisUpdate > now || status.NextUpdate <= now ||
                status.NextUpdate <= status.ThisUpdate || now - status.ThisUpdate > _maximumAge ||
                status.NextUpdate - status.ThisUpdate > _maximumLifetime)
            {
                throw new CryptographicException("Offline revocation status has an invalid or stale validity interval.");
            }
        }
    }
}
