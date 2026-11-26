// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Enrollment;

/// <summary>
/// Applies Device certificate policy and installs an authenticated enrollment.
/// </summary>
/// <remarks>
/// Validation occurs before Done20 and must not install the certificate or
/// distributed trust material.
/// Installation occurs only after the Device authenticates DoneAck20. The host
/// owns the enrollment key and durable storage. For server-generated keys,
/// the separate server-key handler performs installation instead. If
/// installation throws or is canceled, its durable outcome may be unknown
/// and must be reconciled.
/// </remarks>
public interface IFdoDeviceEnrollmentHandler
{
    /// <summary>
    /// Checks the certificate's trust, validity, intended use, and local
    /// authorization policy. Reject it by throwing an exception.
    /// </summary>
    ValueTask ValidateCertificateAsync(
        FdoDeviceEnrollment enrollment,
        CancellationToken cancellationToken);

    /// <summary>
    /// Durably installs the enrollment after authenticated DoneAck20.
    /// </summary>
    ValueTask InstallAsync(FdoDeviceEnrollment enrollment, CancellationToken cancellationToken);
}

/// <summary>
/// Detached evidence for one Device enrollment. The local run identifier is
/// independent of the Owner's identifier; the Device GUID is the 16-byte FDO
/// wire value rather than a .NET GUID byte-order conversion.
/// </summary>
public sealed class FdoDeviceEnrollment
{
    private readonly byte[] _deviceGuid;
    private readonly byte[] _certificateSigningRequest;
    private readonly byte[] _certificate;

    internal FdoDeviceEnrollment(
        Guid runId,
        ReadOnlyMemory<byte> deviceGuid,
        ReadOnlyMemory<byte> certificateSigningRequest,
        ReadOnlyMemory<byte> certificate,
        FdoCaCertificates? caCertificates = null,
        bool isReenrollment = false,
        FdoCsrAttributes? csrAttributes = null,
        bool isServerKeyGeneration = false)
    {
        RunId = runId;
        _deviceGuid = deviceGuid.ToArray();
        _certificateSigningRequest = certificateSigningRequest.ToArray();
        _certificate = certificate.ToArray();
        CaCertificates = caCertificates;
        IsReenrollment = isReenrollment;
        CsrAttributes = csrAttributes;
        IsServerKeyGeneration = isServerKeyGeneration;
    }

    /// <summary>A locally generated identifier for this Device run.</summary>
    public Guid RunId { get; }

    /// <summary>The 16-byte FDO Device GUID.</summary>
    public ReadOnlyMemory<byte> DeviceGuid => (byte[])_deviceGuid.Clone();

    /// <summary>
    /// The exact DER PKCS#10 request. For server-generated keys, its public
    /// key and signature are ignored and do not prove possession.
    /// </summary>
    public ReadOnlyMemory<byte> CertificateSigningRequest => (byte[])_certificateSigningRequest.Clone();

    /// <summary>The exact DER certificate issued for this enrollment.</summary>
    public ReadOnlyMemory<byte> Certificate => (byte[])_certificate.Clone();

    /// <summary>
    /// Detached CA certificates and CRLs, or null when distribution was not
    /// requested. The host must authenticate and authorize them before use.
    /// </summary>
    public FdoCaCertificates? CaCertificates { get; }

    /// <summary>Whether the Device requested simple re-enrollment.</summary>
    public bool IsReenrollment { get; }

    /// <summary>Authenticated Owner attributes, or null when discovery was not requested.</summary>
    public FdoCsrAttributes? CsrAttributes { get; }

    /// <summary>Whether the Owner generated the enrollment private key.</summary>
    public bool IsServerKeyGeneration { get; }
}
