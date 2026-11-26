// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fdo.Serialization;

namespace Fdo.Cryptography;

/// <summary>
/// FDO operations an Owner may permit a Delegate to perform (§3.5.5). Each
/// value maps to one fdo-ekt-permit extended key usage. There is no generic
/// onboarding permission: the caller requires the permission for the chosen
/// disposition.
/// </summary>
[Flags]
internal enum FdoDelegatePermissions
{
    None = 0,

    /// <summary>fdo-ekt-permit-redirect, required for TO0 and TO1 redirect.</summary>
    Redirect = 1,

    /// <summary>fdo-ekt-permit-onboard-new-cred, required for credential replacement.</summary>
    OnboardNewCredentials = 2,

    /// <summary>fdo-ekt-permit-onboard-reuse-cred, required for credential reuse.</summary>
    OnboardReuseCredentials = 4,

    /// <summary>fdo-ekt-permit-onboard-fdo-disable, required to disable FDO.</summary>
    OnboardDisable = 8,
}

/// <summary>
/// Thrown when an authentic Delegate chain lacks the permission for the
/// requested operation. FDO reports this case as DELEGATE_NOT_PERMITTED,
/// which differs from an invalid chain.
/// </summary>
internal sealed class FdoDelegateNotPermittedException : InvalidOperationException
{
    public FdoDelegateNotPermittedException(FdoDelegatePermissions required)
        : base("The Delegate certificate chain does not permit the requested FDO operation.")
    {
        Required = required;
    }

    public FdoDelegatePermissions Required { get; }
}

/// <summary>
/// A Delegate chain whose authenticity was verified against the Owner key.
/// Authenticity does not authorize the Delegate: the caller requires the
/// operation-specific permission, and the host decides whether it accepts
/// this Delegate at all.
/// </summary>
internal sealed class FdoVerifiedDelegateChain
{
    internal FdoVerifiedDelegateChain(
        ReadOnlyMemory<byte> delegateKey, FdoDelegatePermissions permissions, ReadOnlyMemory<byte> leafCertificate,
        DateTimeOffset notBefore, DateTimeOffset notAfter,
        IReadOnlyList<FdoDelegateRevocationTarget>? revocationTargets = null)
    {
        DelegateKey = delegateKey;
        Permissions = permissions;
        LeafCertificate = leafCertificate;
        NotBefore = notBefore;
        NotAfter = notAfter;
        RevocationTargets = revocationTargets;
    }

    /// <summary>The leaf certificate key encoded as an FDO PublicKey; an RSA key uses RSAPKCS.</summary>
    public ReadOnlyMemory<byte> DelegateKey { get; }

    /// <summary>The permissions that every certificate in the chain carries.</summary>
    public FdoDelegatePermissions Permissions { get; }

    /// <summary>The DER leaf certificate, for host authorization of the Delegate.</summary>
    public ReadOnlyMemory<byte> LeafCertificate { get; }

    private IReadOnlyList<FdoDelegateRevocationTarget>? RevocationTargets { get; }
    private DateTimeOffset NotBefore { get; }
    private DateTimeOffset NotAfter { get; }

    internal void RequireValidityAt(DateTimeOffset now)
    {
        if (now < NotBefore || now > NotAfter)
        {
            throw new FdoDelegateChainException(FdoDelegateChainFailure.Validity,
                "A Delegate certificate is not valid at the acceptance time.");
        }
    }

    internal void RequireOfflineStatus(FdoDelegateOfflineRevocationPolicy? policy, DateTimeOffset now)
    {
        policy?.Require(RevocationTargets ??
                throw new InvalidOperationException("The verified Delegate path was not retained for offline checking."), now);
    }

    /// <summary>Requires exactly one operation permission.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not exactly one defined permission.</exception>
    /// <exception cref="FdoDelegateNotPermittedException">The chain does not carry the permission.</exception>
    public void Require(FdoDelegatePermissions permission)
    {
        if (permission is not (FdoDelegatePermissions.Redirect or FdoDelegatePermissions.OnboardNewCredentials
            or FdoDelegatePermissions.OnboardReuseCredentials or FdoDelegatePermissions.OnboardDisable))
        {
            throw new ArgumentOutOfRangeException(nameof(permission));
        }

        if ((Permissions & permission) == 0)
        {
            throw new FdoDelegateNotPermittedException(permission);
        }
    }
}

/// <summary>The specific reason a Delegate chain was rejected.</summary>
internal enum FdoDelegateChainFailure
{
    /// <summary>The chain is empty or exceeds the configured certificate count or size limits.</summary>
    ChainBounds = 0,

    /// <summary>A certificate or one of its recognized extensions is not valid DER.</summary>
    MalformedCertificate = 1,

    /// <summary>A certificate is signed with an algorithm that FDO does not define.</summary>
    UnsupportedSignatureAlgorithm = 2,

    /// <summary>A certificate repeats or contradicts a signed field, or uses a field this verifier does not process.</summary>
    InconsistentSignedFields = 3,

    /// <summary>The Owner key did not sign the terminating certificate.</summary>
    OwnerSignature = 4,

    /// <summary>A certificate issuer name differs from the subject name of the next certificate.</summary>
    IssuerNameMismatch = 5,

    /// <summary>An authority key identifier differs from the subject key identifier of the next certificate.</summary>
    KeyIdentifierMismatch = 6,

    /// <summary>The next certificate key did not sign a certificate.</summary>
    HopSignature = 7,

    /// <summary>An issuing or leaf key is not an FDO key type.</summary>
    UnsupportedKey = 8,

    /// <summary>A certificate is not valid at the verification time.</summary>
    Validity = 9,

    /// <summary>Two certificates share a subject name.</summary>
    DuplicateSubject = 10,

    /// <summary>A certificate violates its basic constraints or path length.</summary>
    CaConstraints = 11,

    /// <summary>A certificate key usage does not permit its role.</summary>
    KeyUsage = 12,

    /// <summary>A certificate carries a path-affecting feature that this verifier does not process, such as NOM.</summary>
    UnsupportedPathFeature = 13,

    /// <summary>A certificate carries a critical extension this verifier does not recognize.</summary>
    UnknownCriticalExtension = 14,
}

/// <summary>Thrown when a Delegate chain is not authentic for the Owner key.</summary>
internal sealed class FdoDelegateChainException : CryptographicException
{
    public FdoDelegateChainException(FdoDelegateChainFailure reason, string message, Exception? inner = null)
        : base(message, inner)
    {
        Reason = reason;
    }

    public FdoDelegateChainFailure Reason { get; }
}

/// <summary>
/// Verifies an FDO Delegate certificate chain (§3.5.2, §3.5.5) against the raw
/// Owner key from the last voucher entry.
/// </summary>
/// <remarks>
/// The chain is leaf first, and the Owner key must sign the last (terminating)
/// certificate directly. Platform path building can't use that certificate as
/// a trust anchor: Windows reports a partial chain for an anchor that isn't
/// self-signed. This verifier therefore validates the exact supplied path
/// itself and doesn't search, reorder, download or consult any trust store.
/// Each certificate's issuer name must equal the next certificate's subject
/// name byte for byte, and the next certificate's key must verify its
/// signature. It is not a general PKIX validator: it rejects name constraints,
/// policy mappings, policy constraints, inhibit anyPolicy, NOM, NOM Constraint
/// and any unrecognized critical extension instead of ignoring them.
/// This builds only the authenticated path. It does not check revocation.
/// When the caller requires offline status, it retains exact path targets
/// and checks them against an explicitly configured host source.
/// </remarks>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoDelegateChainVerifier
{
    internal const string RedirectOid = "1.3.6.1.4.1.45724.3.1.1";
    internal const string OnboardNewCredentialsOid = "1.3.6.1.4.1.45724.3.1.2";
    internal const string OnboardReuseCredentialsOid = "1.3.6.1.4.1.45724.3.1.3";
    internal const string OnboardDisableOid = "1.3.6.1.4.1.45724.3.1.4";
    internal const string NameOwnerMatchOid = "1.3.6.1.4.1.45724.3.2";
    internal const string NameOwnerMatchConstraintOid = "1.3.6.1.4.1.45724.3.3";
    private const string SubjectKeyIdentifierOid = "2.5.29.14";
    private const string KeyUsageOid = "2.5.29.15";
    private const string BasicConstraintsOid = "2.5.29.19";
    private const string NameConstraintsOid = "2.5.29.30";
    private const string PolicyMappingsOid = "2.5.29.33";
    private const string AuthorityKeyIdentifierOid = "2.5.29.35";
    private const string PolicyConstraintsOid = "2.5.29.36";
    private const string ExtendedKeyUsageOid = "2.5.29.37";
    private const string InhibitAnyPolicyOid = "2.5.29.54";
    private const string EcdsaSha256Oid = "1.2.840.10045.4.3.2";
    private const string EcdsaSha384Oid = "1.2.840.10045.4.3.3";
    private const string RsaSha256Oid = "1.2.840.113549.1.1.11";
    private const string RsaSha384Oid = "1.2.840.113549.1.1.12";
    private static readonly Asn1Tag VersionTag = new(TagClass.ContextSpecific, 0, true);
    private static readonly Asn1Tag IssuerUniqueIdTag = new(TagClass.ContextSpecific, 1);
    private static readonly Asn1Tag SubjectUniqueIdTag = new(TagClass.ContextSpecific, 2);
    private static readonly Asn1Tag ExtensionsTag = new(TagClass.ContextSpecific, 3, true);
    private readonly FdoPublicKeyCodec _keys = new();
    private readonly int _maxCertificates;
    private readonly int _maxCertificateBytes;
    private readonly int _maxTotalBytes;

    /// <summary>
    /// Creates a verifier with the default certificate and chain size limits.
    /// </summary>
    /// <param name="revocationMode">Must be <see cref="X509RevocationMode.NoCheck"/>.</param>
    /// <exception cref="NotSupportedException">Offline or online revocation checking was requested.</exception>
    public FdoDelegateChainVerifier(X509RevocationMode revocationMode)
        : this(revocationMode, 8, 16 * 1024, 64 * 1024)
    {
    }

    internal FdoDelegateChainVerifier(
        X509RevocationMode revocationMode, int maxCertificates, int maxCertificateBytes, int maxTotalBytes)
    {
        if (revocationMode is X509RevocationMode.Offline or X509RevocationMode.Online)
        {
            throw new NotSupportedException("Delegate chain revocation checking is not supported.");
        }

        if (revocationMode != X509RevocationMode.NoCheck)
        {
            throw new ArgumentOutOfRangeException(nameof(revocationMode));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(maxCertificates, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxCertificateBytes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxTotalBytes, maxCertificateBytes);
        _maxCertificates = maxCertificates;
        _maxCertificateBytes = maxCertificateBytes;
        _maxTotalBytes = maxTotalBytes;
    }

    /// <summary>Verifies chain authenticity and computes the effective permissions.</summary>
    /// <param name="chain">DER certificates, leaf first; the last one is signed by the Owner key.</param>
    /// <param name="ownerKey">The FDO PublicKey of the last voucher entry.</param>
    /// <param name="verificationTime">The time at which every certificate must be valid.</param>
    /// <param name="captureRevocationTargets">Retains detached targets for a later offline status check.</param>
    /// <exception cref="FdoDelegateChainException">The chain is not an authentic Delegate chain for the Owner key.</exception>
    public FdoVerifiedDelegateChain Verify(
        IReadOnlyList<ReadOnlyMemory<byte>> chain, ReadOnlyMemory<byte> ownerKey, DateTimeOffset verificationTime,
        bool captureRevocationTargets = false)
    {
        ArgumentNullException.ThrowIfNull(chain);
        if (chain.Count == 0 || chain.Count > _maxCertificates)
        {
            throw Fail(FdoDelegateChainFailure.ChainBounds, "The Delegate chain has an unsupported number of certificates.");
        }

        long total = 0;
        foreach (ReadOnlyMemory<byte> encoded in chain)
        {
            if (encoded.Length > _maxCertificateBytes)
            {
                throw Fail(FdoDelegateChainFailure.ChainBounds, "A Delegate certificate exceeds the configured size limit.");
            }

            total += encoded.Length;
        }

        if (total > _maxTotalBytes)
        {
            throw Fail(FdoDelegateChainFailure.ChainBounds, "The Delegate chain exceeds the configured size limit.");
        }

        using FdoPublicKeyCodec.DecodedKey owner = _keys.Decode(ownerKey);
        var certificates = new List<ParsedCertificate>(chain.Count);
        try
        {
            foreach (ReadOnlyMemory<byte> encoded in chain)
            {
                certificates.Add(ParsedCertificate.Parse(encoded));
            }

            int last = certificates.Count - 1;
            ParsedCertificate terminating = certificates[last];
            if (!owner.VerifyCertificateSignature(
                terminating.SignedData.Span, terminating.Signature, terminating.SignatureAlgorithm))
            {
                throw Fail(FdoDelegateChainFailure.OwnerSignature,
                    "The Owner key did not sign the terminating Delegate certificate.");
            }

            for (int i = 0; i < last; i++)
            {
                VerifyHop(certificates[i], certificates[i + 1]);
            }

            (FdoDelegatePermissions permissions, DateTimeOffset notBefore, DateTimeOffset notAfter) =
                CheckCertificates(certificates, verificationTime);
            ReadOnlyMemory<byte> delegateKey = EncodeKey(certificates[0].Certificate);
            return new FdoVerifiedDelegateChain(delegateKey, permissions, certificates[0].Certificate.RawData, notBefore, notAfter,
                captureRevocationTargets ? BuildRevocationTargets(certificates, owner.EncodeSubjectPublicKeyInfo()) : null);
        }
        finally
        {
            foreach (ParsedCertificate certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    private IReadOnlyList<FdoDelegateRevocationTarget> BuildRevocationTargets(
        IReadOnlyList<ParsedCertificate> certificates, ReadOnlyMemory<byte> ownerKey)
    {
        var targets = new FdoDelegateRevocationTarget[certificates.Count];
        for (int i = 0; i < targets.Length; i++)
        {
            X509Certificate2? issuer = i + 1 == targets.Length ? null : certificates[i + 1].Certificate;
            targets[i] = new FdoDelegateRevocationTarget(
                certificates[i].Certificate.RawData, issuer is null ? ownerKey : EncodeKey(issuer),
                issuer is null ? (ReadOnlyMemory<byte>?)null : new ReadOnlyMemory<byte>(issuer.RawData));
        }

        return Array.AsReadOnly(targets);
    }

    private void VerifyHop(ParsedCertificate subject, ParsedCertificate issuer)
    {
        if (!subject.Issuer.Span.SequenceEqual(issuer.Subject.Span))
        {
            throw Fail(FdoDelegateChainFailure.IssuerNameMismatch,
                "A Delegate certificate issuer name does not match the next certificate in the chain.");
        }

        if (subject.FindExtension(AuthorityKeyIdentifierOid) is { } authority)
        {
            byte[]? keyIdentifier = ReadAuthorityKeyIdentifier(authority.RawData);
            if (keyIdentifier is not null && issuer.FindExtension(SubjectKeyIdentifierOid) is { } subjectKey)
            {
                byte[] issuerIdentifier = Decode(() =>
                {
                    var reader = new AsnReader(subjectKey.RawData, AsnEncodingRules.DER);
                    byte[] identifier = reader.ReadOctetString();
                    reader.ThrowIfNotEmpty();
                    return identifier;
                });
                if (!keyIdentifier.AsSpan().SequenceEqual(issuerIdentifier))
                {
                    throw Fail(FdoDelegateChainFailure.KeyIdentifierMismatch,
                        "A Delegate certificate authority key identifier does not match its issuer.");
                }
            }
        }

        ReadOnlyMemory<byte> issuerKey = EncodeKey(issuer.Certificate);
        using FdoPublicKeyCodec.DecodedKey key = _keys.Decode(issuerKey);
        if (!key.VerifyCertificateSignature(subject.SignedData.Span, subject.Signature, subject.SignatureAlgorithm))
        {
            throw Fail(FdoDelegateChainFailure.HopSignature,
                "A Delegate certificate was not signed by the next certificate in the chain.");
        }
    }

    private static byte[]? ReadAuthorityKeyIdentifier(ReadOnlyMemory<byte> value)
    {
        byte[]? keyIdentifier = null;
        bool otherFields = Decode(() =>
        {
            var reader = new AsnReader(value, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            if (sequence.HasData && sequence.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                keyIdentifier = sequence.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
            }

            return sequence.HasData;
        });

        // An issuer name and serial would identify the issuer through a second
        // path; this verifier relies only on the exact supplied order.
        if (otherFields)
        {
            throw Fail(FdoDelegateChainFailure.UnsupportedPathFeature,
                "A Delegate certificate authority key identifier names its issuer, which is not supported.");
        }

        return keyIdentifier;
    }

    private static (FdoDelegatePermissions Permissions, DateTimeOffset NotBefore, DateTimeOffset NotAfter) CheckCertificates(
        List<ParsedCertificate> certificates, DateTimeOffset verificationTime)
    {
        FdoDelegatePermissions effective = FdoDelegatePermissions.Redirect |
            FdoDelegatePermissions.OnboardNewCredentials | FdoDelegatePermissions.OnboardReuseCredentials |
            FdoDelegatePermissions.OnboardDisable;
        DateTimeOffset notBefore = DateTimeOffset.MinValue;
        DateTimeOffset notAfter = DateTimeOffset.MaxValue;
        for (int i = 0; i < certificates.Count; i++)
        {
            ParsedCertificate certificate = certificates[i];
            if (verificationTime < certificate.NotBefore || verificationTime > certificate.NotAfter)
            {
                throw Fail(FdoDelegateChainFailure.Validity,
                    "A Delegate certificate is not valid at the verification time.");
            }

            if (certificate.NotBefore > notBefore)
            {
                notBefore = certificate.NotBefore;
            }

            if (certificate.NotAfter < notAfter)
            {
                notAfter = certificate.NotAfter;
            }

            for (int j = 0; j < i; j++)
            {
                if (certificates[j].Subject.Span.SequenceEqual(certificate.Subject.Span))
                {
                    throw Fail(FdoDelegateChainFailure.DuplicateSubject,
                        "Delegate certificates must have unique subject names.");
                }
            }

            effective &= CheckExtensions(certificate, isLeaf: i == 0, caCertificatesBelow: Math.Max(0, i - 1));
        }

        return (effective, notBefore, notAfter);
    }

    private static FdoDelegatePermissions CheckExtensions(
        ParsedCertificate certificate, bool isLeaf, int caCertificatesBelow)
    {
        foreach (X509Extension extension in certificate.Extensions)
        {
            string oid = extension.Oid!.Value!;
            if (oid is NameConstraintsOid or PolicyMappingsOid or PolicyConstraintsOid or InhibitAnyPolicyOid
                or NameOwnerMatchOid or NameOwnerMatchConstraintOid)
            {
                throw Fail(FdoDelegateChainFailure.UnsupportedPathFeature,
                    "A Delegate certificate uses a path-affecting extension that is not supported.");
            }

            if (extension.Critical && oid is not (BasicConstraintsOid or KeyUsageOid or ExtendedKeyUsageOid
                or SubjectKeyIdentifierOid or AuthorityKeyIdentifierOid))
            {
                throw Fail(FdoDelegateChainFailure.UnknownCriticalExtension,
                    "A Delegate certificate has an unrecognized critical extension.");
            }
        }

        (bool Ca, int? PathLength) basicConstraints = certificate.FindExtension(BasicConstraintsOid) is { } bc
            ? Decode(() =>
            {
                var decoded = new X509BasicConstraintsExtension(bc, bc.Critical);
                return (decoded.CertificateAuthority,
                    decoded.HasPathLengthConstraint ? decoded.PathLengthConstraint : (int?)null);
            })
            : (false, null);
        if (isLeaf)
        {
            if (basicConstraints.Ca)
            {
                throw Fail(FdoDelegateChainFailure.CaConstraints, "The Delegate leaf certificate must not be a CA certificate.");
            }
        }
        else if (!basicConstraints.Ca || basicConstraints.PathLength < caCertificatesBelow)
        {
            throw Fail(FdoDelegateChainFailure.CaConstraints, "A Delegate issuing certificate violates its CA constraints.");
        }

        if (certificate.FindExtension(KeyUsageOid) is { } ku)
        {
            X509KeyUsageFlags usage = Decode(() => new X509KeyUsageExtension(ku, ku.Critical).KeyUsages);
            X509KeyUsageFlags required = isLeaf ? X509KeyUsageFlags.DigitalSignature : X509KeyUsageFlags.KeyCertSign;
            if ((usage & required) == 0)
            {
                throw Fail(FdoDelegateChainFailure.KeyUsage, "A Delegate certificate key usage does not permit its role.");
            }
        }

        // Missing EKU, anyExtendedKeyUsage or generic usages grant no FDO operation.
        FdoDelegatePermissions permissions = FdoDelegatePermissions.None;
        if (certificate.FindExtension(ExtendedKeyUsageOid) is { } eku)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (Oid usageOid in Decode(() => new X509EnhancedKeyUsageExtension(eku, eku.Critical).EnhancedKeyUsages))
            {
                string value = usageOid.Value ?? string.Empty;
                if (!seen.Add(value))
                {
                    throw Fail(FdoDelegateChainFailure.InconsistentSignedFields,
                        "A Delegate certificate repeats an extended key usage.");
                }

                permissions |= value switch
                {
                    RedirectOid => FdoDelegatePermissions.Redirect,
                    OnboardNewCredentialsOid => FdoDelegatePermissions.OnboardNewCredentials,
                    OnboardReuseCredentialsOid => FdoDelegatePermissions.OnboardReuseCredentials,
                    OnboardDisableOid => FdoDelegatePermissions.OnboardDisable,
                    NameOwnerMatchOid or NameOwnerMatchConstraintOid => throw Fail(
                        FdoDelegateChainFailure.UnsupportedPathFeature,
                        "A Delegate certificate uses Name-Owner Match, which is not supported."),
                    _ => FdoDelegatePermissions.None,
                };
            }
        }

        return permissions;
    }

    private ReadOnlyMemory<byte> EncodeKey(X509Certificate2 certificate)
    {
        try
        {
            using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa is not null)
            {
                return _keys.Encode(ecdsa);
            }

            using RSA? rsa = certificate.GetRSAPublicKey();
            if (rsa is not null)
            {
                return _keys.EncodeRsa(rsa);
            }
        }
        catch (Exception exception) when (exception is NotSupportedException or CryptographicException
            and not FdoDelegateChainException)
        {
            throw Fail(FdoDelegateChainFailure.UnsupportedKey,
                "A Delegate certificate key is not a supported FDO key type.", exception);
        }

        throw Fail(FdoDelegateChainFailure.UnsupportedKey, "A Delegate certificate key is not a supported FDO key type.");
    }

    private static T Decode<T>(Func<T> decode)
    {
        try
        {
            return decode();
        }
        catch (Exception exception) when (exception is AsnContentException or CryptographicException
            and not FdoDelegateChainException)
        {
            throw Fail(FdoDelegateChainFailure.MalformedCertificate,
                "A Delegate certificate extension is not valid DER.", exception);
        }
    }

    private static FdoDelegateChainException Fail(
        FdoDelegateChainFailure reason, string message, Exception? inner = null) => new(reason, message, inner);

    /// <summary>
    /// One certificate decoded from its exact DER bytes. Path decisions use these
    /// fields rather than the platform's view, and the platform's names must agree.
    /// </summary>
    private sealed class ParsedCertificate : IDisposable
    {
        private ParsedCertificate(X509Certificate2 certificate)
        {
            Certificate = certificate;
        }

        public X509Certificate2 Certificate { get; }

        public ReadOnlyMemory<byte> SignedData { get; private set; }

        public byte[] Signature { get; private set; } = Array.Empty<byte>();

        public string SignatureAlgorithm { get; private set; } = string.Empty;

        public ReadOnlyMemory<byte> Issuer { get; private set; }

        public ReadOnlyMemory<byte> Subject { get; private set; }

        public DateTimeOffset NotBefore { get; private set; }

        public DateTimeOffset NotAfter { get; private set; }

        public List<X509Extension> Extensions { get; } = new();

        public static ParsedCertificate Parse(ReadOnlyMemory<byte> encoded)
        {
            X509Certificate2 platform;
            try
            {
                platform = FdoDerEncoding.LoadCertificate(encoded);
            }
            catch (CryptographicException exception)
            {
                throw Fail(FdoDelegateChainFailure.MalformedCertificate,
                    "The Delegate certificate is not a DER X.509 certificate.", exception);
            }

            var parsed = new ParsedCertificate(platform);
            try
            {
                parsed.Read(encoded);
                if (!platform.IssuerName.RawData.AsSpan().SequenceEqual(parsed.Issuer.Span) ||
                    !platform.SubjectName.RawData.AsSpan().SequenceEqual(parsed.Subject.Span))
                {
                    throw Fail(FdoDelegateChainFailure.InconsistentSignedFields,
                        "The Delegate certificate names are inconsistent.");
                }

                return parsed;
            }
            catch (AsnContentException exception)
            {
                parsed.Dispose();
                throw Fail(FdoDelegateChainFailure.MalformedCertificate,
                    "The Delegate certificate is not a DER X.509 certificate.", exception);
            }
            catch
            {
                parsed.Dispose();
                throw;
            }
        }

        public X509Extension? FindExtension(string oid) =>
            Extensions.Find(extension => string.Equals(extension.Oid!.Value, oid, StringComparison.Ordinal));

        public void Dispose() => Certificate.Dispose();

        private void Read(ReadOnlyMemory<byte> encoded)
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);
            AsnReader certificate = reader.ReadSequence();
            SignedData = certificate.ReadEncodedValue();
            ReadOnlyMemory<byte> outerAlgorithm = certificate.ReadEncodedValue();
            Signature = certificate.ReadBitString(out int unusedBits);
            certificate.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();

            AsnReader tbs = new AsnReader(SignedData, AsnEncodingRules.DER).ReadSequence();
            if (!tbs.PeekTag().HasSameClassAndValue(VersionTag))
            {
                throw Fail(FdoDelegateChainFailure.InconsistentSignedFields, "A Delegate certificate must be version 3.");
            }

            AsnReader version = tbs.ReadSequence(VersionTag);
            if (!version.TryReadInt32(out int value) || value != 2)
            {
                throw Fail(FdoDelegateChainFailure.InconsistentSignedFields, "A Delegate certificate must be version 3.");
            }

            version.ThrowIfNotEmpty();
            _ = tbs.ReadIntegerBytes();
            ReadOnlyMemory<byte> innerAlgorithm = tbs.ReadEncodedValue();
            if (unusedBits != 0 || !innerAlgorithm.Span.SequenceEqual(outerAlgorithm.Span))
            {
                throw Fail(FdoDelegateChainFailure.InconsistentSignedFields,
                    "The Delegate certificate signature algorithm is inconsistent.");
            }

            SignatureAlgorithm = ReadSignatureAlgorithm(outerAlgorithm);
            Issuer = tbs.ReadEncodedValue();
            AsnReader validity = tbs.ReadSequence();
            NotBefore = ReadTime(validity);
            NotAfter = ReadTime(validity);
            validity.ThrowIfNotEmpty();
            Subject = tbs.ReadEncodedValue();
            _ = tbs.ReadSequence();
            if (tbs.HasData && (tbs.PeekTag().HasSameClassAndValue(IssuerUniqueIdTag) ||
                tbs.PeekTag().HasSameClassAndValue(SubjectUniqueIdTag)))
            {
                throw Fail(FdoDelegateChainFailure.InconsistentSignedFields,
                    "A Delegate certificate uses unique identifiers, which are not supported.");
            }

            if (tbs.HasData)
            {
                AsnReader wrapper = tbs.ReadSequence(ExtensionsTag);
                AsnReader extensions = wrapper.ReadSequence();
                wrapper.ThrowIfNotEmpty();
                var oids = new HashSet<string>(StringComparer.Ordinal);
                while (extensions.HasData)
                {
                    AsnReader extension = extensions.ReadSequence();
                    string oid = extension.ReadObjectIdentifier();
                    bool critical = false;
                    if (extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                    {
                        critical = extension.ReadBoolean();
                        if (!critical)
                        {
                            // DER omits the default; an explicit FALSE is a second encoding.
                            throw Fail(FdoDelegateChainFailure.InconsistentSignedFields,
                                "A Delegate certificate extension encodes the default criticality.");
                        }
                    }

                    byte[] extensionValue = extension.ReadOctetString();
                    extension.ThrowIfNotEmpty();
                    if (!oids.Add(oid))
                    {
                        throw Fail(FdoDelegateChainFailure.InconsistentSignedFields,
                            "A Delegate certificate repeats an extension.");
                    }

                    Extensions.Add(new X509Extension(oid, extensionValue, critical));
                }
            }

            tbs.ThrowIfNotEmpty();
        }

        private static string ReadSignatureAlgorithm(ReadOnlyMemory<byte> encoded)
        {
            AsnReader algorithm = new AsnReader(encoded, AsnEncodingRules.DER).ReadSequence();
            string oid = algorithm.ReadObjectIdentifier();
            switch (oid)
            {
                case EcdsaSha256Oid or EcdsaSha384Oid:
                    break;
                case RsaSha256Oid or RsaSha384Oid:
                    algorithm.ReadNull();
                    break;
                default:
                    throw Fail(FdoDelegateChainFailure.UnsupportedSignatureAlgorithm,
                        "The Delegate certificate signature algorithm is not supported.");
            }

            algorithm.ThrowIfNotEmpty();
            return oid;
        }

        private static DateTimeOffset ReadTime(AsnReader validity) =>
            validity.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime)
                ? validity.ReadUtcTime()
                : validity.ReadGeneralizedTime();
    }
}
