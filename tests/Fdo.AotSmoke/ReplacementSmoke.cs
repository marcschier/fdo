// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Cryptography;
using Fdo.Enrollment;
using Fdo.Initialization;
using Fdo.Serialization;

namespace Fdo.Tests.Transport;

internal static partial class Program
{
    private sealed class ReplacementSmoke :
        IFdoOwnerReplacementHandler, IFdoDeviceReplacementHandler, IFdoDeviceDelegateAcceptance,
        IFdoDelegateOfflineStatusSource, IFdoDeviceInitializeHmacSecret, IDisposable
    {
        private readonly ECDsa _replacementOwner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly byte[] _replacementSecret = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _previousGuid;
        private readonly byte[] _canonicalOwnerKey;
        private FdoDeviceReplacementProposal? _reserved;
        private FdoDeviceReplacementCredential? _staged;
        private FdoOwnerReplacementCommit? _committed;
        private byte[] _activeGuid;
        private bool _accepted;
        private int _statusCalls;

        public ReplacementSmoke(ECDsa owner, ReadOnlyMemory<byte> previousGuid, ReadOnlyMemory<byte> rendezvousInfo)
        {
            _previousGuid = previousGuid.ToArray();
            _activeGuid = previousGuid.ToArray();
            _canonicalOwnerKey = new FdoPublicKeyCodec().Encode(owner).ToArray();
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var ownerRequest = new CertificateRequest("CN=FDO smoke Owner", owner, HashAlgorithmName.SHA256);
            ownerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            using X509Certificate2 ownerCertificate = ownerRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(1));
            OwnerCertificate = ownerCertificate.RawData;

            var delegateRequest = new CertificateRequest("CN=FDO smoke Delegate", DelegateKey, HashAlgorithmName.SHA256);
            delegateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            delegateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            delegateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                [new Oid("1.3.6.1.4.1.45724.3.1.2")], false));
            using X509Certificate2 certificate = delegateRequest.Create(ownerRequest.SubjectName,
                X509SignatureGenerator.CreateForECDsa(owner), now.AddMinutes(-5), now.AddDays(1),
                RandomNumberGenerator.GetBytes(16));
            DelegateChain = Array.AsReadOnly(new ReadOnlyMemory<byte>[] { certificate.RawData });
            OfflinePolicy = new FdoDelegateOfflineRevocationPolicy(this, TimeSpan.FromMinutes(10), TimeSpan.FromHours(1));
            OwnerOptions = new FdoOwnerReplacementOptions
            {
                Owner2SigningKey = _replacementOwner,
                EncodedRendezvousInfo = rendezvousInfo.ToArray(),
                Handler = this,
            };
        }

        public ECDsa DelegateKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public ReadOnlyMemory<byte> OwnerCertificate { get; }
        public ReadOnlyCollection<ReadOnlyMemory<byte>> DelegateChain { get; }
        public FdoDelegateOfflineRevocationPolicy OfflinePolicy { get; }
        public FdoOwnerReplacementOptions OwnerOptions { get; }
        public FdoDeviceSession? DeviceSession { get; set; }
        public FdoDeviceHmacAlgorithm Algorithm => FdoDeviceHmacAlgorithm.HmacSha256;
        public int KeySizeInBytes => _replacementSecret.Length;

        public IReadOnlyList<FdoDelegateOfflineStatus> GetStatuses(IReadOnlyList<FdoDelegateRevocationTarget> path)
        {
            Require(path.Count == 1 && path[0].IssuerCertificate is null &&
                path[0].Certificate.Span.SequenceEqual(DelegateChain[0].Span) &&
                path[0].IssuerPublicKey.Span.SequenceEqual(_canonicalOwnerKey),
                "The offline status request did not match the explicitly trusted fixture issuer and certificate.");
            _statusCalls++;
            DateTimeOffset now = DateTimeOffset.UtcNow;
            return [new(path[0].CertificateSha256, path[0].IssuerKeySha256,
                FdoDelegateCertificateStatus.Good, now.AddMinutes(-1), now.AddMinutes(5))];
        }

        public ValueTask<bool> AcceptAsync(FdoDelegateEvidence evidence, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(!_accepted && _statusCalls == 3 && evidence.MayOnboardNewCredentials &&
                !evidence.MayOnboardReuseCredentials && !evidence.MayRedirect &&
                evidence.LeafCertificate.Span.SequenceEqual(DelegateChain[0].Span),
                "The Device did not verify the configured Delegate and its offline status before acceptance.");
            _accepted = true;
            return ValueTask.FromResult(true);
        }

        public ValueTask<IFdoDeviceInitializeHmacSecret> ReserveSecretAsync(
            FdoDeviceReplacementProposal proposal, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(_accepted && _reserved is null && proposal.PreviousDeviceGuid.Span.SequenceEqual(_previousGuid) &&
                !proposal.ReplacementDeviceGuid.Span.SequenceEqual(_previousGuid) &&
                proposal.EncodedOwnerPublicKey.Span.SequenceEqual(new FdoPublicKeyCodec().Encode(_replacementOwner).Span),
                "The replacement reservation did not match the authenticated Owner2 or Device.");
            _reserved = proposal;
            return ValueTask.FromResult<IFdoDeviceInitializeHmacSecret>(this);
        }

        public ValueTask StageAsync(FdoDeviceReplacementCredential credential, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(ReferenceEquals(credential.Proposal, _reserved) && _staged is null &&
                ReferenceEquals(credential.VoucherHmacSecret, this) && _activeGuid.AsSpan().SequenceEqual(_previousGuid),
                "Replacement staging changed the active credential or did not use the reserved secret.");
            _staged = credential;
            return ValueTask.CompletedTask;
        }

        public ValueTask<ReadOnlyMemory<byte>> ComputeAsync(
            ReadOnlyMemory<byte> encodedHeaderContents, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(HMACSHA256.HashData(_replacementSecret, encodedHeaderContents.Span));
        }

        public ValueTask CommitAsync(FdoOwnerReplacementCommit replacement, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            FdoDeviceReplacementProposal staged = _staged?.Proposal ??
                throw new InvalidOperationException("The Device did not stage a replacement before the Owner committed.");
            Require(_committed is null && _activeGuid.AsSpan().SequenceEqual(_previousGuid) &&
                replacement.PreviousDeviceGuid.Span.SequenceEqual(_previousGuid) &&
                replacement.ReplacementDeviceGuid.Span.SequenceEqual(staged.ReplacementDeviceGuid.Span) &&
                replacement.EncodedVoucherHeaderTag.Span.SequenceEqual(staged.EncodedVoucherHeaderTag.Span),
                "The Owner commit did not match the staged credential.");
            var header = new CborReader(replacement.EncodedVoucherHeaderTag);
            var hmac = new CborReader(replacement.EncodedVoucherHeaderHmac);
            hmac.ReadStartArray();
            hmac.ReadInt32();
            Require(CryptographicOperations.FixedTimeEquals(hmac.ReadByteString(),
                HMACSHA256.HashData(_replacementSecret, header.ReadByteString())),
                "The Owner did not retain the HMAC for the new Device secret.");
            _committed = replacement;
            return ValueTask.CompletedTask;
        }

        public ValueTask ActivateAsync(FdoDeviceReplacementCredential credential, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(DeviceSession?.DoneAckAuthenticated == true && _committed is not null &&
                ReferenceEquals(credential, _staged) && _activeGuid.AsSpan().SequenceEqual(_previousGuid),
                "The Device activated without the authenticated acknowledgment or changed the old credential early.");
            _activeGuid = credential.Proposal.ReplacementDeviceGuid.ToArray();
            return ValueTask.CompletedTask;
        }

        public void RequireCompleted() =>
            Require(_committed is not null && _activeGuid.AsSpan().SequenceEqual(_committed.ReplacementDeviceGuid.Span) &&
                !_activeGuid.AsSpan().SequenceEqual(_previousGuid), "The authenticated replacement was not activated.");

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_replacementSecret);
            DelegateKey.Dispose();
            _replacementOwner.Dispose();
        }
    }
}
