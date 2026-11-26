using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fdo.Serialization;

namespace Fdo.Cryptography;

/// <summary>
/// Establishes manufacturer and Device certificate trust for the supplied
/// voucher and Device proof. A host must also authorize the Device for the
/// requested enrollment.
/// </summary>
internal interface IFdoOwnerDeviceTrustPolicy
{
    void Validate(FdoOwnerDeviceTrustEvidence evidence);
}

internal sealed record FdoOwnerDeviceTrustEvidence(
    ReadOnlyMemory<byte> Guid,
    ReadOnlyMemory<byte> ManufacturerKey,
    IReadOnlyList<ReadOnlyMemory<byte>> DeviceCertificates);

/// <summary>
/// Pins a manufacturer public key and one certificate trust anchor. The host
/// selects revocation behavior explicitly; NoCheck does not check revocation.
/// This policy does not authorize a Device for enrollment.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoPinnedDeviceTrustPolicy : IFdoOwnerDeviceTrustPolicy
{
    private readonly FdoPublicKeyCodec _keys = new();
    private readonly ReadOnlyMemory<byte> _manufacturerKey;
    private readonly byte[] _trustAnchor;
    private readonly X509RevocationMode _revocationMode;

    public FdoPinnedDeviceTrustPolicy(
        ReadOnlyMemory<byte> manufacturerKey,
        ReadOnlyMemory<byte> trustAnchor,
        X509RevocationMode revocationMode)
    {
        if (revocationMode is not (X509RevocationMode.NoCheck or X509RevocationMode.Offline or X509RevocationMode.Online))
        {
            throw new ArgumentOutOfRangeException(nameof(revocationMode));
        }

        using FdoPublicKeyCodec.DecodedKey decoded = _keys.Decode(manufacturerKey);
        using X509Certificate2 certificate = FdoDerEncoding.LoadCertificate(trustAnchor);
        _manufacturerKey = decoded.Encoded.ToArray();
        _trustAnchor = certificate.RawData;
        _revocationMode = revocationMode;
    }

    public void Validate(FdoOwnerDeviceTrustEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(evidence.DeviceCertificates);
        if (evidence.DeviceCertificates.Count == 0)
        {
            throw new CryptographicException("A Device certificate chain is required.");
        }

        using FdoPublicKeyCodec.DecodedKey trusted = _keys.Decode(_manufacturerKey);
        using FdoPublicKeyCodec.DecodedKey received = _keys.Decode(evidence.ManufacturerKey);
        if (!trusted.HasSamePublicKey(received))
        {
            throw new CryptographicException("The voucher manufacturer key is not trusted.");
        }

        var certificates = new List<X509Certificate2>(evidence.DeviceCertificates.Count);
        try
        {
            foreach (ReadOnlyMemory<byte> encoded in evidence.DeviceCertificates)
            {
                certificates.Add(FdoDerEncoding.LoadCertificate(encoded));
            }

            using X509Certificate2 anchor = FdoDerEncoding.LoadCertificate(_trustAnchor);
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(anchor);
            chain.ChainPolicy.RevocationMode = _revocationMode;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            for (int i = 1; i < certificates.Count; i++)
            {
                chain.ChainPolicy.ExtraStore.Add(certificates[i]);
            }

            if (!chain.Build(certificates[0]))
            {
                throw new CryptographicException("The Device certificate path did not validate against the configured trust anchor.");
            }

            int pathLength = chain.ChainElements.Count;
            if (pathLength == 0 ||
                (pathLength != certificates.Count && pathLength != certificates.Count + 1) ||
                !chain.ChainElements[pathLength - 1].Certificate.RawData.AsSpan().SequenceEqual(_trustAnchor))
            {
                throw new CryptographicException("The Device certificate path does not match the supplied chain and trust anchor.");
            }

            for (int i = 0; i < certificates.Count; i++)
            {
                if (!chain.ChainElements[i].Certificate.RawData.AsSpan().SequenceEqual(certificates[i].RawData))
                {
                    throw new CryptographicException("The Device certificate path does not match the supplied chain order.");
                }
            }
        }
        finally
        {
            foreach (X509Certificate2 certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }
}
