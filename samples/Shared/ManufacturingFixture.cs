// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Enrollment;
using Fdo.Initialization;
using Fdo.Ownership;
using Fdo.Transport.Http;

namespace Fdo.Samples;

internal sealed class ManufacturingFixture :
    IFdoDeviceInitializeHandler,
    IFdoManufacturerInitializeHandler,
    IFdoDeviceInitializeHmacSecret,
    IDisposable
{
    private const string DeviceInfo = "fdo-sample";
    private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 _root;
    private readonly X509Certificate2 _deviceCertificate;
    private readonly ECDsa _manufacturerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly byte[] _hmacKey = RandomNumberGenerator.GetBytes(32);
    private IFdoDeviceInitializeTransport? _station;
    private Uri? _stationAddress;
    private FdoManufacturerInitializeProposal? _proposal;
    private FdoDeviceInitializeCredential? _staged;
    private FdoDeviceInitializeCredential? _installed;
    private FdoManufacturerInitializeVoucher? _voucher;
    private bool _reserved;

    public ManufacturingFixture()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var ca = new CertificateRequest("CN=FDO sample CA", _rootKey, HashAlgorithmName.SHA256);
        ca.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        ca.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        _root = ca.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));

        var device = new CertificateRequest("CN=FDO sample Device", _deviceKey, HashAlgorithmName.SHA256);
        device.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        device.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        _deviceCertificate = device.Create(
            _root, now.AddMinutes(-4), now.AddMinutes(55), RandomNumberGenerator.GetBytes(16));
    }

    public const ushort MaxMessageSize = 16384;

    public FdoDeviceHmacAlgorithm Algorithm => FdoDeviceHmacAlgorithm.HmacSha256;

    public int KeySizeInBytes => _hmacKey.Length;

    public FdoManufacturerInitializeSession CreateManufacturer() => new(new FdoManufacturerInitializeOptions
    {
        Handler = this,
        MaxMessageSize = MaxMessageSize,
        UseVoucherHeaderHmac = true
    });

    public ValueTask<FdoDeviceInitializeCredential> InitializeAsync(
        IFdoDeviceInitializeTransport authorizedStation,
        CancellationToken cancellationToken)
    {
        _station = authorizedStation;
        return CreateDevice().RunAsync(authorizedStation, cancellationToken);
    }

    public ValueTask<FdoDeviceInitializeCredential> InitializeAsync(
        Uri authorizedStation,
        CancellationToken cancellationToken)
    {
        _stationAddress = authorizedStation;
        return FdoHttp.RunDeviceInitializeAsync(CreateDevice(), authorizedStation, MaxMessageSize, cancellationToken);
    }

    public void Transfer(FdoDeviceInitializeCredential credential)
    {
        if (!ReferenceEquals(_installed, credential) || _voucher is null)
        {
            throw new InvalidOperationException("The Device credential or manufacturer voucher is missing.");
        }

        using ECDsa owner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa authorizedOwner = ECDsa.Create(owner.ExportParameters(includePrivateParameters: false));
        FdoTransferredOwnershipVoucher transferred =
            FdoOwnershipVoucherTransfer.Extend(_voucher.EncodedVoucher, _manufacturerKey, authorizedOwner);
        if (transferred.EncodedVoucherEntries.Count != 1)
        {
            throw new InvalidOperationException("The transfer did not append an Owner entry.");
        }
    }

    public ValueTask<IFdoDeviceInitializeHmacSecret> AuthorizeAndReserveAsync(
        Guid runId,
        IFdoDeviceInitializeTransport transport,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        bool authorized = ReferenceEquals(transport, _station) ||
            (_stationAddress is not null && transport is IFdoHttpPeer peer && peer.BaseAddress == _stationAddress);
        if (_reserved || !authorized)
        {
            throw new InvalidOperationException("The station was not authorized or the Device is reserved.");
        }

        _reserved = true;
        return ValueTask.FromResult<IFdoDeviceInitializeHmacSecret>(this);
    }

    public ValueTask StageAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_reserved || _staged is not null || credential.DeviceInfo != DeviceInfo)
        {
            throw new InvalidOperationException("The Device proposal is not the authorized sample fixture.");
        }

        _staged = credential;
        return ValueTask.CompletedTask;
    }

    public ValueTask InstallAsync(FdoDeviceInitializeCredential credential, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ReferenceEquals(_staged, credential) || _installed is not null)
        {
            throw new InvalidOperationException("The staged credential does not match.");
        }

        _installed = credential;
        return ValueTask.CompletedTask;
    }

    public ValueTask<FdoManufacturerInitializeProposal> AuthorizeAndPrepareAsync(
        FdoManufacturerInitializeRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_proposal is not null || !_reserved || request.EncodedDeviceMfgInfo is not null)
        {
            throw new InvalidOperationException("No new preauthorized sample Device is reserved.");
        }

        _proposal = FdoManufacturerInitializeProposal.Create(
            DeviceInfo, _manufacturerKey, [_deviceCertificate.RawData, _root.RawData]);
        return ValueTask.FromResult(_proposal);
    }

    public ValueTask PersistVoucherAsync(FdoManufacturerInitializeVoucher voucher, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_proposal is null || _voucher is not null ||
            !_proposal.EncodedVoucherHeaderTag.Span.SequenceEqual(voucher.EncodedVoucherHeaderTag.Span))
        {
            throw new InvalidOperationException("The voucher does not match the authorized proposal.");
        }

        _voucher = voucher;
        return ValueTask.CompletedTask;
    }

    public ValueTask<ReadOnlyMemory<byte>> ComputeAsync(
        ReadOnlyMemory<byte> encodedHeaderContents,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<ReadOnlyMemory<byte>>(HMACSHA256.HashData(_hmacKey, encodedHeaderContents.Span));
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_hmacKey);
        _deviceCertificate.Dispose();
        _root.Dispose();
        _deviceKey.Dispose();
        _manufacturerKey.Dispose();
        _rootKey.Dispose();
    }

    private FdoDeviceInitializeSession CreateDevice() => new(new FdoDeviceInitializeOptions
    {
        AttestationKey = _deviceKey,
        Handler = this,
        MaxMessageSize = MaxMessageSize,
        UseVoucherHeaderHmac = true
    });
}
