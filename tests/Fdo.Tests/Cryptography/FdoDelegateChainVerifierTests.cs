// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Serialization;

namespace Fdo.Tests.Cryptography;

public sealed class FdoDelegateChainVerifierTests
{
    private static readonly string[] AllPermissions =
    {
        FdoDelegateChainVerifier.RedirectOid,
        FdoDelegateChainVerifier.OnboardNewCredentialsOid,
        FdoDelegateChainVerifier.OnboardReuseCredentialsOid,
        FdoDelegateChainVerifier.OnboardDisableOid,
    };

    private const FdoDelegatePermissions Every = FdoDelegatePermissions.Redirect |
        FdoDelegatePermissions.OnboardNewCredentials | FdoDelegatePermissions.OnboardReuseCredentials |
        FdoDelegatePermissions.OnboardDisable;

    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    [Test]
    [Arguments("P256", 1)]
    [Arguments("P256", 2)]
    [Arguments("P256", 3)]
    [Arguments("P384", 2)]
    [Arguments("RSA2048", 1)]
    [Arguments("RSA3072", 2)]
    public async Task VerifiesTheExactPathToANonSelfSignedOwnerSignedAnchor(string ownerType, int depth)
    {
        using var fixture = new ChainFixture(ownerType);
        byte[][] chain = fixture.Build(Specs(depth));

        await Assert.That(IsSelfIssued(chain[^1])).IsFalse();

        FdoVerifiedDelegateChain verified = Verifier().Verify(Memories(chain), fixture.OwnerKey, Now);

        await Assert.That(verified.Permissions).IsEqualTo(Every);
        await Assert.That(verified.LeafCertificate.Span.SequenceEqual(chain[0])).IsTrue();
        await Assert.That(verified.DelegateKey.Span.SequenceEqual(
            new FdoPublicKeyCodec().Encode(fixture.LeafKey).Span)).IsTrue();
    }

    [Test]
    [Arguments(1)]
    [Arguments(3)]
    public async Task OfflineStatusBindsEveryCertificateToItsActualIssuer(int depth)
    {
        using var fixture = new ChainFixture("P256");
        byte[][] chain = fixture.Build(Specs(depth));
        FdoVerifiedDelegateChain verified = Verifier().Verify(Memories(chain), fixture.OwnerKey, Now, true);
        var source = new OfflineStatusFixture(TimeProvider.System) { Transform = statuses => statuses.Reverse().ToArray() };
        verified.RequireOfflineStatus(source.Policy, Now);

        IReadOnlyList<FdoDelegateRevocationTarget> path = source.Path!;
        await Assert.That(path.Count).IsEqualTo(depth);
        for (int i = 0; i < path.Count; i++)
        {
            await Assert.That(path[i].Certificate.Span.SequenceEqual(chain[i])).IsTrue();
            if (i + 1 == path.Count)
            {
                await Assert.That(path[i].IssuerCertificate).IsNull();
                await Assert.That(path[i].IssuerPublicKey.Span.SequenceEqual(fixture.OwnerKey.Span)).IsTrue();
            }
            else
            {
                await Assert.That(path[i].IssuerCertificate!.Value.Span.SequenceEqual(chain[i + 1])).IsTrue();
                using X509Certificate2 certificate = FdoDerEncoding.LoadCertificate(chain[i + 1]);
                using ECDsa issuer = certificate.GetECDsaPublicKey()!;
                await Assert.That(path[i].IssuerPublicKey.Span.SequenceEqual(new FdoPublicKeyCodec().Encode(issuer).Span)).IsTrue();
            }
        }
    }

    [Test]
    [Arguments("missing")]
    [Arguments("duplicated")]
    [Arguments("certificate")]
    [Arguments("issuer")]
    [Arguments("revoked")]
    [Arguments("unknown")]
    [Arguments("authority")]
    [Arguments("future")]
    [Arguments("expired")]
    [Arguments("stale")]
    [Arguments("lifetime")]
    [Arguments("interval")]
    public async Task OfflineStatusRejectsUnboundUnavailableOrInvalidEvidence(string failure)
    {
        using var fixture = new ChainFixture("P256");
        byte[][] chain = fixture.Build(Specs(2));
        FdoVerifiedDelegateChain verified = Verifier().Verify(Memories(chain), fixture.OwnerKey, Now, true);
        var source = new OfflineStatusFixture(TimeProvider.System)
        {
            Transform = statuses =>
            {
                if (failure == "missing")
                {
                    return [statuses[0]];
                }

                FdoDelegateOfflineStatus ownerIssued = statuses[^1];
                statuses[^1] = failure switch
                {
                    "duplicated" => statuses[0] with { Status = FdoDelegateCertificateStatus.Revoked },
                    "certificate" => ownerIssued with { CertificateSha256 = statuses[0].CertificateSha256 },
                    "issuer" => ownerIssued with { IssuerKeySha256 = statuses[0].IssuerKeySha256 },
                    "revoked" => ownerIssued with { Status = FdoDelegateCertificateStatus.Revoked },
                    "unknown" => ownerIssued with { Status = FdoDelegateCertificateStatus.Unknown },
                    "authority" => ownerIssued with { Status = FdoDelegateCertificateStatus.NoAuthority },
                    "future" => ownerIssued with { ThisUpdate = Now.AddMinutes(1) },
                    "expired" => ownerIssued with { NextUpdate = Now },
                    "stale" => ownerIssued with { ThisUpdate = Now.AddMinutes(-125) },
                    "lifetime" => ownerIssued with { NextUpdate = Now.AddHours(5) },
                    "interval" => ownerIssued with { NextUpdate = ownerIssued.ThisUpdate.AddSeconds(-1) },
                    _ => throw new ArgumentOutOfRangeException(nameof(failure)),
                };
                return statuses;
            },
        };
        await Assert.That(failure == "authority"
            ? Throws<NotSupportedException>(() => verified.RequireOfflineStatus(source.Policy, Now))
            : Throws<CryptographicException>(() => verified.RequireOfflineStatus(source.Policy, Now))).IsTrue();
        await Assert.That(source.Calls).IsEqualTo(1);
        verified.RequireOfflineStatus(null, Now);
        await Assert.That(source.Calls).IsEqualTo(1);
    }

    [Test]
    public async Task AcceptsConsistentKeyIdentifiersAndNonCriticalUnknownExtensions()
    {
        using var fixture = new ChainFixture("P256");
        Spec[] specs = Specs(3);
        specs[1] = specs[1] with
        {
            Extra = new[] { SubjectKeyIdentifier(0xAA, 0xBB), Raw("2.5.29.32", false, 0x30, 0x00) },
        };
        specs[2] = specs[2] with
        {
            Extra = new[] { AuthorityKeyIdentifier(0xAA, 0xBB), Raw("1.3.6.1.4.1.45724.99.2", false, 0x05, 0x00) },
        };
        byte[][] chain = fixture.Build(specs);

        FdoVerifiedDelegateChain verified = Verifier().Verify(Memories(chain), fixture.OwnerKey, Now);

        await Assert.That(verified.Permissions).IsEqualTo(Every);
    }

    [Test]
    public async Task ReSignedUnchangedCertificatesStillVerify()
    {
        // Proves the re-signing helper, so mutation cases fail only on their mutation.
        using var fixture = new ChainFixture("P256");
        Spec[] specs = Specs(3);
        specs[2] = specs[2] with { MutateTbs = tbs => tbs };
        specs[1] = specs[1] with { MutateTbs = tbs => tbs };
        byte[][] chain = fixture.Build(specs);

        FdoVerifiedDelegateChain verified = Verifier().Verify(Memories(chain), fixture.OwnerKey, Now);

        await Assert.That(verified.Permissions).IsEqualTo(Every);
    }

    [Test]
    public async Task PermissionsAreTheIntersectionAcrossEveryCertificate()
    {
        using var fixture = new ChainFixture("P256");
        Spec[] specs = Specs(3);
        specs[0] = specs[0] with { Ekus = new[] { AllPermissions[0], AllPermissions[1], AllPermissions[3] } };
        specs[1] = specs[1] with { Ekus = new[] { AllPermissions[0], AllPermissions[3] } };
        specs[2] = specs[2] with { Ekus = new[] { AllPermissions[0], AllPermissions[1] } };
        byte[][] chain = fixture.Build(specs);

        FdoVerifiedDelegateChain verified = Verifier().Verify(Memories(chain), fixture.OwnerKey, Now);
        verified.Require(FdoDelegatePermissions.Redirect);

        await Assert.That(verified.Permissions).IsEqualTo(FdoDelegatePermissions.Redirect);
        await Assert.That(NotPermitted(verified, FdoDelegatePermissions.OnboardNewCredentials)).IsTrue();
        await Assert.That(NotPermitted(verified, FdoDelegatePermissions.OnboardReuseCredentials)).IsTrue();
        await Assert.That(NotPermitted(verified, FdoDelegatePermissions.OnboardDisable)).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => verified.Require(FdoDelegatePermissions.None)))
            .IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => verified.Require(
            FdoDelegatePermissions.Redirect | FdoDelegatePermissions.OnboardDisable))).IsTrue();
    }

    [Test]
    [Arguments(0, "none")]
    [Arguments(1, "none")]
    [Arguments(2, "none")]
    [Arguments(0, "removed")]
    [Arguments(2, "any")]
    [Arguments(2, "generic")]
    [Arguments(0, "generic")]
    public async Task MissingFdoUsageOnAnyCertificateGrantsNoOperation(int index, string usage)
    {
        using var fixture = new ChainFixture("P256");
        Spec[] specs = Specs(3);
        specs[index] = specs[index] with
        {
            Ekus = usage switch
            {
                "any" => new[] { "2.5.29.37.0" },
                "generic" => new[] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" },
                "removed" => Array.Empty<string>(),
                _ => null,
            },
        };
        byte[][] chain = fixture.Build(specs);

        FdoVerifiedDelegateChain verified = Verifier().Verify(Memories(chain), fixture.OwnerKey, Now);

        await Assert.That(verified.Permissions).IsEqualTo(FdoDelegatePermissions.None);
        foreach (FdoDelegatePermissions permission in new[]
        {
            FdoDelegatePermissions.Redirect, FdoDelegatePermissions.OnboardNewCredentials,
            FdoDelegatePermissions.OnboardReuseCredentials, FdoDelegatePermissions.OnboardDisable,
        })
        {
            await Assert.That(NotPermitted(verified, permission)).IsTrue();
        }
    }

    [Test]
    public async Task DistinguishesAnUnpermittedChainFromAnInvalidChain()
    {
        using var fixture = new ChainFixture("P256");
        Spec[] specs = Specs(2);
        specs[1] = specs[1] with { Ekus = new[] { FdoDelegateChainVerifier.RedirectOid } };
        byte[][] chain = fixture.Build(specs);
        byte[][] tampered = chain.Select(certificate => (byte[])certificate.Clone()).ToArray();
        tampered[0][^1] ^= 1;
        FdoVerifiedDelegateChain verified = Verifier().Verify(Memories(chain), fixture.OwnerKey, Now);

        Exception? unpermitted = Capture(() => verified.Require(FdoDelegatePermissions.OnboardReuseCredentials));

        await Assert.That(unpermitted is FdoDelegateNotPermittedException
        {
            Required:
            FdoDelegatePermissions.OnboardReuseCredentials
        }).IsTrue();
        await Assert.That(Reason(() => Verifier().Verify(Memories(tampered), fixture.OwnerKey, Now)))
            .IsEqualTo(FdoDelegateChainFailure.HopSignature);
    }

    [Test]
    [Arguments("leaf-ca", nameof(FdoDelegateChainFailure.CaConstraints))]
    [Arguments("issuer-not-ca", nameof(FdoDelegateChainFailure.CaConstraints))]
    [Arguments("anchor-not-ca", nameof(FdoDelegateChainFailure.CaConstraints))]
    [Arguments("path-length", nameof(FdoDelegateChainFailure.CaConstraints))]
    [Arguments("anchor-critical", nameof(FdoDelegateChainFailure.UnknownCriticalExtension))]
    [Arguments("leaf-critical", nameof(FdoDelegateChainFailure.UnknownCriticalExtension))]
    [Arguments("critical-policies", nameof(FdoDelegateChainFailure.UnknownCriticalExtension))]
    [Arguments("duplicate-subject", nameof(FdoDelegateChainFailure.DuplicateSubject))]
    [Arguments("leaf-key-usage", nameof(FdoDelegateChainFailure.KeyUsage))]
    [Arguments("issuer-key-usage", nameof(FdoDelegateChainFailure.KeyUsage))]
    [Arguments("anchor-expired", nameof(FdoDelegateChainFailure.Validity))]
    [Arguments("leaf-not-yet-valid", nameof(FdoDelegateChainFailure.Validity))]
    public async Task RejectsCertificateConstraintViolationsIncludingOnTheAnchor(
        string violation, string expectedReason)
    {
        using var fixture = new ChainFixture("P256");
        Spec[] specs = Specs(3);
        switch (violation)
        {
            case "leaf-ca":
                specs[2] = specs[2] with { Ca = true, KeyUsage = X509KeyUsageFlags.DigitalSignature };
                break;
            case "issuer-not-ca":
                specs[1] = specs[1] with { Ca = false };
                break;
            case "anchor-not-ca":
                specs[0] = specs[0] with { Ca = false };
                break;
            case "path-length":
                specs[0] = specs[0] with { PathLength = 0 };
                break;
            case "anchor-critical":
                specs[0] = specs[0] with { UnknownCritical = true };
                break;
            case "leaf-critical":
                specs[2] = specs[2] with { UnknownCritical = true };
                break;
            case "critical-policies":
                specs[1] = specs[1] with
                {
                    Extra = [Raw("2.5.29.32", true, 0x30, 0x08, 0x30, 0x06, 0x06, 0x04, 0x2A, 0x03, 0x04, 0x05)]
                };
                break;
            case "duplicate-subject":
                specs[1] = specs[1] with { Name = specs[0].Name };
                break;
            case "leaf-key-usage":
                specs[2] = specs[2] with { KeyUsage = X509KeyUsageFlags.KeyEncipherment };
                break;
            case "issuer-key-usage":
                specs[1] = specs[1] with { KeyUsage = X509KeyUsageFlags.DigitalSignature };
                break;
            case "anchor-expired":
                specs[0] = specs[0] with { NotAfter = Now.AddMinutes(-1) };
                break;
            case "leaf-not-yet-valid":
                specs[2] = specs[2] with { NotBefore = Now.AddMinutes(1) };
                break;
        }

        byte[][] chain = fixture.Build(specs);

        await Assert.That(Reason(() => Verifier().Verify(Memories(chain), fixture.OwnerKey, Now)))
            .IsEqualTo(Enum.Parse<FdoDelegateChainFailure>(expectedReason));
    }

    [Test]
    [Arguments("name-constraints")]
    [Arguments("policy-mappings")]
    [Arguments("policy-constraints")]
    [Arguments("inhibit-any-policy")]
    [Arguments("name-owner-match")]
    [Arguments("name-owner-match-constraint")]
    [Arguments("name-owner-match-usage")]
    [Arguments("authority-issuer-and-serial")]
    public async Task RejectsUnsupportedPathFeaturesEvenWhenNotCritical(string feature)
    {
        using var fixture = new ChainFixture("P256");
        Spec[] specs = Specs(3);
        X509Extension? extension = feature switch
        {
            "name-constraints" => Raw("2.5.29.30", false, 0x30, 0x00),
            "policy-mappings" => Raw("2.5.29.33", false, 0x30, 0x00),
            "policy-constraints" => Raw("2.5.29.36", false, 0x30, 0x00),
            "inhibit-any-policy" => Raw("2.5.29.54", false, 0x02, 0x01, 0x00),
            "name-owner-match" => Raw(FdoDelegateChainVerifier.NameOwnerMatchOid, false, 0x30, 0x00),
            "name-owner-match-constraint" => Raw(
                FdoDelegateChainVerifier.NameOwnerMatchConstraintOid, false, 0x30, 0x00),
            _ => null,
        };
        if (extension is not null)
        {
            // The anchor is checked like any other certificate.
            specs[0] = specs[0] with { Extra = new[] { extension } };
        }
        else if (feature == "name-owner-match-usage")
        {
            specs[0] = specs[0] with
            {
                Ekus = AllPermissions.Append(FdoDelegateChainVerifier.NameOwnerMatchOid).ToArray(),
            };
        }
        else
        {
            // keyIdentifier [0] AA BB plus authorityCertSerialNumber [2] 05.
            specs[1] = specs[1] with { Extra = new[] { SubjectKeyIdentifier(0xAA, 0xBB) } };
            specs[2] = specs[2] with
            {
                Extra = new[] { Raw("2.5.29.35", false, 0x30, 0x07, 0x80, 0x02, 0xAA, 0xBB, 0x82, 0x01, 0x05) },
            };
        }

        byte[][] chain = fixture.Build(specs);

        await Assert.That(Reason(() => Verifier().Verify(Memories(chain), fixture.OwnerKey, Now)))
            .IsEqualTo(FdoDelegateChainFailure.UnsupportedPathFeature);
    }

    [Test]
    [Arguments("issuer-name", nameof(FdoDelegateChainFailure.IssuerNameMismatch))]
    [Arguments("key-identifier", nameof(FdoDelegateChainFailure.KeyIdentifierMismatch))]
    [Arguments("wrong-signer", nameof(FdoDelegateChainFailure.HopSignature))]
    [Arguments("sha512", nameof(FdoDelegateChainFailure.UnsupportedSignatureAlgorithm))]
    [Arguments("p521-leaf", nameof(FdoDelegateChainFailure.UnsupportedKey))]
    [Arguments("p521-issuer", nameof(FdoDelegateChainFailure.UnsupportedKey))]
    [Arguments("duplicate-extension", nameof(FdoDelegateChainFailure.InconsistentSignedFields))]
    [Arguments("duplicate-usage", nameof(FdoDelegateChainFailure.InconsistentSignedFields))]
    [Arguments("unique-identifier", nameof(FdoDelegateChainFailure.InconsistentSignedFields))]
    [Arguments("inner-algorithm", nameof(FdoDelegateChainFailure.InconsistentSignedFields))]
    [Arguments("trailing-byte", nameof(FdoDelegateChainFailure.MalformedCertificate))]
    public async Task RejectsEachPathDefectWithItsSpecificReason(string defect, string expectedReason)
    {
        using var fixture = new ChainFixture("P256");
        Spec[] specs = Specs(3);
        switch (defect)
        {
            case "issuer-name":
                // Signed by the right key under a different issuer name.
                specs[2] = specs[2] with { IssuerName = "CN=Another CA" };
                break;
            case "key-identifier":
                specs[1] = specs[1] with { Extra = new[] { SubjectKeyIdentifier(0xAA, 0xBB) } };
                specs[2] = specs[2] with { Extra = new[] { AuthorityKeyIdentifier(0xAA, 0xBC) } };
                break;
            case "wrong-signer":
                specs[2] = specs[2] with { WrongSigner = true };
                break;
            case "sha512":
                specs[2] = specs[2] with { HashOverride = HashAlgorithmName.SHA512 };
                break;
            case "p521-leaf":
                specs[2] = specs[2] with { Curve = ECCurve.NamedCurves.nistP521 };
                break;
            case "p521-issuer":
                specs[1] = specs[1] with { Curve = ECCurve.NamedCurves.nistP521 };
                specs[2] = specs[2] with { HashOverride = HashAlgorithmName.SHA384 };
                break;
            case "duplicate-extension":
                specs[2] = specs[2] with { MutateTbs = DuplicateFirstExtension };
                break;
            case "duplicate-usage":
                specs[1] = specs[1] with { Ekus = AllPermissions.Append(AllPermissions[0]).ToArray() };
                break;
            case "unique-identifier":
                // issuerUniqueID [1] BIT STRING after subjectPublicKeyInfo.
                specs[2] = specs[2] with { MutateTbs = tbs => InsertElement(tbs, 7, 0x81, 0x02, 0x00, 0x01) };
                break;
            case "inner-algorithm":
                // The TBS names ecdsa-with-SHA384 while the outer AlgorithmIdentifier stays SHA-256.
                specs[2] = specs[2] with
                {
                    MutateTbs = tbs => ReplaceElement(
                        tbs, 2, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03),
                };
                break;
        }

        byte[][] chain = fixture.Build(specs);
        if (defect == "trailing-byte")
        {
            chain[1] = chain[1].Append((byte)0).ToArray();
        }

        await Assert.That(Reason(() => Verifier().Verify(Memories(chain), fixture.OwnerKey, Now)))
            .IsEqualTo(Enum.Parse<FdoDelegateChainFailure>(expectedReason));
    }

    [Test]
    public async Task UsesTheVerificationTimeForEveryCertificate()
    {
        using var fixture = new ChainFixture("P256");
        byte[][] chain = fixture.Build(Specs(2));

        _ = Verifier().Verify(Memories(chain), fixture.OwnerKey, Now);
        await Assert.That(Reason(() => Verifier().Verify(Memories(chain), fixture.OwnerKey, Now.AddDays(2))))
            .IsEqualTo(FdoDelegateChainFailure.Validity);
        await Assert.That(Reason(() => Verifier().Verify(Memories(chain), fixture.OwnerKey, Now.AddDays(-2))))
            .IsEqualTo(FdoDelegateChainFailure.Validity);
    }

    [Test]
    public async Task RejectsAChainTheOwnerDidNotSignOrThatIsNotInExactOrder()
    {
        using var fixture = new ChainFixture("P256");
        using var other = new ChainFixture("P256");
        byte[][] chain = fixture.Build(Specs(3));

        await Assert.That(Reason(() => Verifier().Verify(Memories(chain), other.OwnerKey, Now)))
            .IsEqualTo(FdoDelegateChainFailure.OwnerSignature);
        await Assert.That(Reason(() => Verifier().Verify(Memories(chain.Reverse().ToArray()), fixture.OwnerKey, Now)))
            .IsEqualTo(FdoDelegateChainFailure.OwnerSignature);
        await Assert.That(Reason(() =>
            Verifier().Verify(Memories(new[] { chain[0], chain[2], chain[1] }), fixture.OwnerKey, Now)))
            .IsEqualTo(FdoDelegateChainFailure.OwnerSignature);
        await Assert.That(Reason(() =>
            Verifier().Verify(Memories(new[] { chain[0], chain[2] }), fixture.OwnerKey, Now)))
            .IsEqualTo(FdoDelegateChainFailure.IssuerNameMismatch);
    }

    [Test]
    public async Task GrantsNoAmbientOrSelfIssuedTrust()
    {
        using var fixture = new ChainFixture("P256");
        byte[][] chain = fixture.Build(Specs(2));
        using ECDsa selfKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Self Root", selfKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(Oids(AllPermissions), false));
        using X509Certificate2 selfSigned = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));

        // The leaf alone: its Owner-signed issuer is omitted, so nothing anchors it.
        await Assert.That(Reason(() => Verifier().Verify(Memories(new[] { chain[0] }), fixture.OwnerKey, Now)))
            .IsEqualTo(FdoDelegateChainFailure.OwnerSignature);
        // A self-signed root carrying every FDO permission is not Owner-signed.
        await Assert.That(Reason(() =>
            Verifier().Verify(Memories(new[] { selfSigned.RawData }), fixture.OwnerKey, Now)))
            .IsEqualTo(FdoDelegateChainFailure.OwnerSignature);
    }

    [Test]
    public async Task EnforcesChainBoundsAndRejectsUnsupportedRevocationModes()
    {
        using var fixture = new ChainFixture("P256");
        byte[][] chain = fixture.Build(Specs(3));
        int largest = chain.Max(certificate => certificate.Length);
        int total = chain.Sum(certificate => certificate.Length);

        _ = new FdoDelegateChainVerifier(X509RevocationMode.NoCheck, 3, largest, total)
            .Verify(Memories(chain), fixture.OwnerKey, Now);
        await Assert.That(Reason(() => new FdoDelegateChainVerifier(X509RevocationMode.NoCheck, 2, largest, total)
            .Verify(Memories(chain), fixture.OwnerKey, Now))).IsEqualTo(FdoDelegateChainFailure.ChainBounds);
        await Assert.That(Reason(() => new FdoDelegateChainVerifier(X509RevocationMode.NoCheck, 3, largest - 1, total)
            .Verify(Memories(chain), fixture.OwnerKey, Now))).IsEqualTo(FdoDelegateChainFailure.ChainBounds);
        await Assert.That(Reason(() => new FdoDelegateChainVerifier(X509RevocationMode.NoCheck, 3, largest, total - 1)
            .Verify(Memories(chain), fixture.OwnerKey, Now))).IsEqualTo(FdoDelegateChainFailure.ChainBounds);
        await Assert.That(Reason(() => Verifier().Verify(Array.Empty<ReadOnlyMemory<byte>>(), fixture.OwnerKey, Now)))
            .IsEqualTo(FdoDelegateChainFailure.ChainBounds);
        await Assert.That(Throws<NotSupportedException>(() =>
            _ = new FdoDelegateChainVerifier(X509RevocationMode.Online))).IsTrue();
        await Assert.That(Throws<NotSupportedException>(() =>
            _ = new FdoDelegateChainVerifier(X509RevocationMode.Offline))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            _ = new FdoDelegateChainVerifier((X509RevocationMode)7))).IsTrue();
    }

    private static FdoDelegateChainVerifier Verifier() => new(X509RevocationMode.NoCheck);

    private static Spec[] Specs(int depth)
    {
        var specs = new Spec[depth];
        for (int i = 0; i < depth; i++)
        {
            bool leaf = i == depth - 1;
            specs[i] = new Spec(
                leaf ? "CN=Delegate Leaf" : $"CN=Delegate CA {i}",
                Ca: !leaf,
                PathLength: null,
                KeyUsage: leaf ? X509KeyUsageFlags.DigitalSignature : X509KeyUsageFlags.KeyCertSign,
                Ekus: AllPermissions,
                UnknownCritical: false,
                NotBefore: Now.AddDays(-1),
                NotAfter: Now.AddDays(1));
        }

        return specs;
    }

    private static X509Extension Raw(string oid, bool critical, params byte[] value) => new(oid, value, critical);

    private static X509Extension SubjectKeyIdentifier(params byte[] identifier) =>
        Raw("2.5.29.14", false, new byte[] { 0x04, (byte)identifier.Length }.Concat(identifier).ToArray());

    private static X509Extension AuthorityKeyIdentifier(params byte[] identifier) =>
        Raw("2.5.29.35", false, new byte[] { 0x30, (byte)(identifier.Length + 2), 0x80, (byte)identifier.Length }
            .Concat(identifier).ToArray());

    private static List<byte[]> Elements(byte[] tbs)
    {
        AsnReader reader = new AsnReader(tbs, AsnEncodingRules.DER).ReadSequence();
        var elements = new List<byte[]>();
        while (reader.HasData)
        {
            elements.Add(reader.ReadEncodedValue().ToArray());
        }

        return elements;
    }

    private static byte[] Sequence(IEnumerable<byte[]> elements)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach (byte[] element in elements)
            {
                writer.WriteEncodedValue(element);
            }
        }

        return writer.Encode();
    }

    private static byte[] InsertElement(byte[] tbs, int index, params byte[] element)
    {
        List<byte[]> elements = Elements(tbs);
        elements.Insert(index, element);
        return Sequence(elements);
    }

    private static byte[] ReplaceElement(byte[] tbs, int index, params byte[] element)
    {
        List<byte[]> elements = Elements(tbs);
        elements[index] = element;
        return Sequence(elements);
    }

    private static byte[] DuplicateFirstExtension(byte[] tbs)
    {
        var tag = new Asn1Tag(TagClass.ContextSpecific, 3, true);
        List<byte[]> elements = Elements(tbs);
        AsnReader extensions = new AsnReader(elements[^1], AsnEncodingRules.DER).ReadSequence(tag).ReadSequence();
        var values = new List<byte[]>();
        while (extensions.HasData)
        {
            values.Add(extensions.ReadEncodedValue().ToArray());
        }

        values.Add(values[0]);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence(tag))
        using (writer.PushSequence())
        {
            values.ForEach(value => writer.WriteEncodedValue(value));
        }

        elements[^1] = writer.Encode();
        return Sequence(elements);
    }

    private static bool IsSelfIssued(byte[] encoded)
    {
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(encoded);
        return certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
    }

    private static ReadOnlyMemory<byte>[] Memories(byte[][] chain) =>
        chain.Select(certificate => new ReadOnlyMemory<byte>(certificate)).ToArray();

    private static OidCollection Oids(IEnumerable<string> values)
    {
        var oids = new OidCollection();
        foreach (string value in values)
        {
            oids.Add(new Oid(value));
        }

        return oids;
    }

    private static bool NotPermitted(FdoVerifiedDelegateChain chain, FdoDelegatePermissions permission) =>
        Capture(() => chain.Require(permission)) is FdoDelegateNotPermittedException exception &&
        exception.Required == permission;

    private static FdoDelegateChainFailure? Reason(Action action) =>
        (Capture(action) as FdoDelegateChainException)?.Reason;

    private static Exception? Capture(Action action)
    {
        try
        {
            action();
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    private static bool Throws<TException>(Action action)
        where TException : Exception => Capture(action) is TException;

    /// <summary>A certificate description; specs are ordered from the Owner-signed certificate to the leaf.</summary>
    /// <param name="Name">The certificate subject's common name.</param>
    /// <param name="Ca">Whether the certificate is a CA.</param>
    /// <param name="PathLength">The optional CA path length constraint.</param>
    /// <param name="KeyUsage">The optional key usage flags.</param>
    /// <param name="Ekus">The optional extended key usage OIDs.</param>
    /// <param name="UnknownCritical">Whether to include an unknown critical extension.</param>
    /// <param name="NotBefore">The start of the certificate validity period.</param>
    /// <param name="NotAfter">The end of the certificate validity period.</param>
    private sealed record Spec(
        string Name,
        bool Ca,
        int? PathLength,
        X509KeyUsageFlags? KeyUsage,
        string[]? Ekus,
        bool UnknownCritical,
        DateTimeOffset NotBefore,
        DateTimeOffset NotAfter)
    {
        public X509Extension[]? Extra { get; init; }

        /// <summary>An issuer name that differs from the actual signer's subject name.</summary>
        public string? IssuerName { get; init; }

        /// <summary>Signs with an unrelated key under the correct issuer name.</summary>
        public bool WrongSigner { get; init; }

        public HashAlgorithmName? HashOverride { get; init; }

        public ECCurve? Curve { get; init; }

        /// <summary>Rewrites the TBSCertificate, which is then signed again by the same issuer key.</summary>
        public Func<byte[], byte[]>? MutateTbs { get; init; }
    }

    private sealed class ChainFixture : IDisposable
    {
        private readonly AsymmetricAlgorithm _owner;
        private readonly List<ECDsa> _keys = [];

        public ChainFixture(string ownerType)
        {
            _owner = ownerType switch
            {
                "P256" => ECDsa.Create(ECCurve.NamedCurves.nistP256),
                "P384" => ECDsa.Create(ECCurve.NamedCurves.nistP384),
                "RSA2048" => RSA.Create(2048),
                "RSA3072" => RSA.Create(3072),
                _ => throw new ArgumentOutOfRangeException(nameof(ownerType)),
            };
            var codec = new FdoPublicKeyCodec();
            OwnerKey = _owner is ECDsa ecdsa ? codec.Encode(ecdsa) : codec.EncodeRsa((RSA)_owner);
        }

        public ReadOnlyMemory<byte> OwnerKey { get; }

        public ECDsa LeafKey => _keys[^1];

        /// <summary>Returns the chain leaf first, as carried in an X5CHAIN.</summary>
        /// <param name="specs">The certificates to issue, starting with the Owner-signed certificate.</param>
        public byte[][] Build(IReadOnlyList<Spec> specs)
        {
            var encoded = new byte[specs.Count][];
            AsymmetricAlgorithm issuerKey = _owner;
            var issuerName = new X500DistinguishedName("CN=FDO Owner");
            for (int i = 0; i < specs.Count; i++)
            {
                Spec spec = specs[i];
                ECDsa key = ECDsa.Create(spec.Curve ?? ECCurve.NamedCurves.nistP256);
                _keys.Add(key);
                var subject = new X500DistinguishedName(spec.Name);
                HashAlgorithmName hash = spec.HashOverride ?? Hash(issuerKey);
                var request = new CertificateRequest(subject, key, hash);
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                    spec.Ca, spec.PathLength.HasValue, spec.PathLength ?? 0, true));
                if (spec.KeyUsage is { } usage)
                {
                    request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
                }

                if (spec.Ekus is not null)
                {
                    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(Oids(spec.Ekus), false));
                }

                if (spec.UnknownCritical)
                {
                    request.CertificateExtensions.Add(
                        new X509Extension("1.3.6.1.4.1.45724.99.1", new byte[] { 0x05, 0x00 }, true));
                }

                foreach (X509Extension extension in spec.Extra ?? Array.Empty<X509Extension>())
                {
                    request.CertificateExtensions.Add(extension);
                }

                using ECDsa? wrongKey = spec.WrongSigner ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : null;
                AsymmetricAlgorithm signer = wrongKey ?? issuerKey;
                X500DistinguishedName statedIssuer = spec.IssuerName is { } name
                    ? new X500DistinguishedName(name) : issuerName;
                byte[] serial = RandomNumberGenerator.GetBytes(8);
                serial[0] &= 0x7F;
                using X509Certificate2 certificate = request.Create(
                    statedIssuer, Generator(signer), spec.NotBefore, spec.NotAfter, serial);
                encoded[specs.Count - 1 - i] = spec.MutateTbs is { } mutate
                    ? Resign(certificate.RawData, mutate, signer, hash)
                    : certificate.RawData;
                issuerKey = key;
                issuerName = subject;
            }

            return encoded;
        }

        public void Dispose()
        {
            _owner.Dispose();
            _keys.ForEach(key => key.Dispose());
        }

        private static byte[] Resign(
            byte[] certificate, Func<byte[], byte[]> mutate, AsymmetricAlgorithm signer, HashAlgorithmName hash)
        {
            AsnReader reader = new AsnReader(certificate, AsnEncodingRules.DER).ReadSequence();
            byte[] tbs = mutate(reader.ReadEncodedValue().ToArray());
            ReadOnlyMemory<byte> algorithm = reader.ReadEncodedValue();
            byte[] signature = signer switch
            {
                ECDsa ecdsa => ecdsa.SignData(tbs, hash, DSASignatureFormat.Rfc3279DerSequence),
                RSA rsa => rsa.SignData(tbs, hash, RSASignaturePadding.Pkcs1),
                _ => throw new ArgumentOutOfRangeException(nameof(signer)),
            };
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                writer.WriteEncodedValue(tbs);
                writer.WriteEncodedValue(algorithm.Span);
                writer.WriteBitString(signature);
            }

            return writer.Encode();
        }

        private static HashAlgorithmName Hash(AsymmetricAlgorithm key) => key.KeySize is 384 or 3072
            ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;

        private static X509SignatureGenerator Generator(AsymmetricAlgorithm key) => key switch
        {
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            _ => throw new ArgumentOutOfRangeException(nameof(key)),
        };
    }
}
