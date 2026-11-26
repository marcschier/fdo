// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Formats.Cbor;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Enrollment;
using Fdo.Initialization;
using Fdo.Rendezvous;
using Fdo.Transport.Http;

namespace Fdo.PeerProbe;

internal static class Program
{
    private const ushort MaxMessageSize = 16384;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 1 || !Uri.TryCreate(args[0], UriKind.Absolute, out Uri? address) ||
            address.Scheme != Uri.UriSchemeHttp || address.Host != "127.0.0.1" ||
            address.UserInfo.Length != 0 || address.PathAndQuery != "/" || address.Fragment.Length != 0)
        {
            Console.Error.WriteLine("Usage: Fdo.PeerProbe http://127.0.0.1:<port>/");
            return 2;
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(35));
        using ECDsa attestationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa enrollmentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var host = new DeviceHost(address);
        var attestationRequest = new CertificateRequest(
            "CN=FDO peer fixture", attestationKey, HashAlgorithmName.SHA256);
        var enrollmentRequest = new CertificateRequest(
            "CN=FDO peer enrollment", enrollmentKey, HashAlgorithmName.SHA256);
        var di = new FdoDeviceInitializeSession(new FdoDeviceInitializeOptions
        {
            AttestationKey = attestationKey,
            Handler = host,
            EncodedDeviceMfgInfo = EncodeManufacturingInfo(attestationRequest.CreateSigningRequest()),
            MaxMessageSize = MaxMessageSize,
            UseVoucherHeaderHmac = true
        });

        string phase = "DI";
        try
        {
            FdoDeviceInitializeCredential credential = await FdoHttp.RunDeviceInitializeAsync(
                di, address, MaxMessageSize, timeout.Token).ConfigureAwait(false);
            Console.WriteLine("phase=DI outcome=complete");
            phase = "TO1";
            var lookup = new FdoDeviceRendezvousSession(new FdoDeviceRendezvousOptions
            {
                DeviceGuid = credential.DeviceGuid,
                AttestationKey = attestationKey,
                MaxMessageSize = MaxMessageSize,
                UseProvisionalPairedProfile = true
            });
            FdoDeviceRendezvousResult result = await FdoHttp.RunDeviceRendezvousAsync(
                lookup, address, MaxMessageSize, timeout.Token).ConfigureAwait(false);
            FdoRendezvousAddress candidate = result.CandidateAddress;
            if (candidate.Protocol != FdoRendezvousTransportProtocol.Http ||
                candidate.IpAddress is not ReadOnlyMemory<byte> ip ||
                !new IPAddress(ip.Span).Equals(IPAddress.Loopback) || candidate.Port != address.Port)
            {
                throw new InvalidOperationException("The redirect does not match the authorized loopback peer.");
            }

            Console.WriteLine("phase=TO1 outcome=complete");
            phase = "TO2";
            using var device = new FdoDeviceSession(new FdoDeviceSessionOptions
            {
                DeviceGuid = credential.DeviceGuid,
                EncodedManufacturerKeyHash = credential.EncodedManufacturerKeyHash,
                VoucherHmacAlgorithm = credential.VoucherHmacAlgorithm,
                VoucherHmacSecretHandle = credential.VoucherHmacSecret,
                AttestationKey = attestationKey,
                CertificateSigningRequest = enrollmentRequest.CreateSigningRequest(),
                KeyExchangeSuite = FdoPairedKeyExchangeSuite.Ecdh256,
                CipherSuite = FdoPairedCipherSuite.A256Gcm,
                AllowRendezvousBypass = false,
                RendezvousResult = result,
                AllowCredentialReuse = true,
                UseProvisionalPairedProfile = true,
                MaxMessageSize = MaxMessageSize,
                MaxOwnerServiceInfoSize = 4096,
                Metadata = new FdoDeviceMetadata("linux", "x64", "1", "fdo-peer", ":", "elf"),
                EnrollmentHandler = host
            });
            await FdoHttp.RunDeviceAsync(device, address, MaxMessageSize, timeout.Token).ConfigureAwait(false);
            if (!device.DoneAckAuthenticated || !host.EnrollmentInstalled)
            {
                throw new InvalidOperationException("The enrolled credential was not installed.");
            }

            Console.WriteLine("phase=TO2 outcome=complete");
            return 0;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            Console.Error.WriteLine($"phase={phase} outcome=rejected reason={exception.GetType().Name}");
            Console.Error.WriteLine(
                $"di-staged={di.CredentialStaged} di-set-hmac={di.SetHmacSendStarted} di-done={di.DoneReceived}");
            return 1;
        }
    }

    private static byte[] EncodeManufacturingInfo(ReadOnlySpan<byte> csr)
    {
        // Go's non-normative custom.DeviceMfgInfo expects the P-256/SPKI fixture and a DER CSR.
        var writer = new CborWriter();
        writer.WriteStartArray(5);
        writer.WriteInt32(10);
        writer.WriteInt32(1);
        writer.WriteTextString("fdo-peer-1");
        writer.WriteTextString("fdo-peer");
        writer.WriteByteString(csr);
        writer.WriteEndArray();
        return writer.Encode();
    }

    private sealed class DeviceHost(Uri address) :
        IFdoDeviceInitializeHandler,
        IFdoDeviceInitializeHmacSecret,
        IFdoDeviceEnrollmentHandler,
        IDisposable
    {
        private readonly byte[] _hmac = RandomNumberGenerator.GetBytes(32);
        private FdoDeviceInitializeCredential? _staged;
        private FdoDeviceEnrollment? _validated;

        public FdoDeviceHmacAlgorithm Algorithm => FdoDeviceHmacAlgorithm.HmacSha256;

        public int KeySizeInBytes => _hmac.Length;

        public bool EnrollmentInstalled { get; private set; }

        public ValueTask<IFdoDeviceInitializeHmacSecret> AuthorizeAndReserveAsync(
            Guid runId, IFdoDeviceInitializeTransport transport, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (transport is not IFdoHttpPeer peer || peer.BaseAddress != address)
            {
                throw new InvalidOperationException("Only the isolated peer may act as the manufacturing station.");
            }

            return ValueTask.FromResult<IFdoDeviceInitializeHmacSecret>(this);
        }

        public ValueTask StageAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!FdoRendezvousInfo.Parse(credential.EncodedRendezvousInfo, FdoRendezvousProtocol.DeviceLookup)
                    .Any(candidate => candidate.BaseAddress == address))
            {
                throw new InvalidOperationException("The credential does not advertise the loopback Rendezvous peer.");
            }

            _staged = credential;
            return ValueTask.CompletedTask;
        }

        public ValueTask InstallAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!ReferenceEquals(_staged, credential))
            {
                throw new InvalidOperationException("The staged credential does not match.");
            }

            return ValueTask.CompletedTask;
        }

        public ValueTask<ReadOnlyMemory<byte>> ComputeAsync(
            ReadOnlyMemory<byte> encodedHeaderContents, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(HMACSHA256.HashData(_hmac, encodedHeaderContents.Span));
        }

        public ValueTask ValidateCertificateAsync(FdoDeviceEnrollment enrollment, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(enrollment.Certificate.Span);
            CertificateRequest request = CertificateRequest.LoadSigningRequest(
                enrollment.CertificateSigningRequest.ToArray(), HashAlgorithmName.SHA256);
            if (!certificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan()
                    .SequenceEqual(request.PublicKey.ExportSubjectPublicKeyInfo()))
            {
                throw new CryptographicException("The synthetic enrollment key does not match the CSR.");
            }

            _validated = enrollment;
            return ValueTask.CompletedTask;
        }

        public ValueTask InstallAsync(FdoDeviceEnrollment enrollment, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!ReferenceEquals(_validated, enrollment))
            {
                throw new InvalidOperationException("The synthetic enrollment was not validated.");
            }

            EnrollmentInstalled = true;
            return ValueTask.CompletedTask;
        }

        public void Dispose() => CryptographicOperations.ZeroMemory(_hmac);
    }
}
