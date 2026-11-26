// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Enrollment;

/// <summary>
/// Authorizes and issues a certificate for client-key enrollment, then commits
/// an enrollment after the Owner verifies the Device's Done20 message.
/// </summary>
/// <remarks>
/// The host is responsible for certificate policy and durable storage. It must
/// reconcile an issuance when the run does not reach a confirmed commit. If
/// <see cref="CommitAsync"/> throws or is canceled, its durable outcome may be
/// unknown. A successful commit does not establish that the Device received
/// DoneAck20.
/// </remarks>
public interface IFdoOwnerEnrollmentHandler
{
    /// <summary>
    /// Authorizes the authenticated Device and returns the issued DER
    /// certificate. Reject the request by throwing an exception.
    /// </summary>
    ValueTask<ReadOnlyMemory<byte>> AuthorizeAndIssueAsync(
        FdoEnrollmentRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Durably commits the issued enrollment before DoneAck20 is produced,
    /// including enrollments issued by the server-key handler.
    /// </summary>
    ValueTask CommitAsync(FdoEnrollmentCommit enrollment, CancellationToken cancellationToken);
}

/// <summary>
/// Detached evidence for one authenticated enrollment request. The Device
/// GUID is the 16-byte FDO wire value, not a .NET GUID byte-order conversion.
/// </summary>
public sealed class FdoEnrollmentRequest
{
    private readonly byte[] _deviceGuid;
    private readonly byte[] _deviceAttestationCertificate;
    private readonly byte[] _certificateSigningRequest;

    internal FdoEnrollmentRequest(
        Guid runId,
        ReadOnlyMemory<byte> deviceGuid,
        ReadOnlyMemory<byte> deviceAttestationCertificate,
        ReadOnlyMemory<byte> certificateSigningRequest,
        bool isReenrollment = false,
        FdoReenrollmentDetails? reenrollment = null,
        FdoCsrAttributes? csrAttributes = null,
        bool isServerKeyGeneration = false)
    {
        RunId = runId;
        _deviceGuid = deviceGuid.ToArray();
        _deviceAttestationCertificate = deviceAttestationCertificate.ToArray();
        _certificateSigningRequest = certificateSigningRequest.ToArray();
        IsReenrollment = isReenrollment;
        Reenrollment = reenrollment;
        CsrAttributes = csrAttributes;
        IsServerKeyGeneration = isServerKeyGeneration;
    }

    /// <summary>A locally generated identifier for this Owner run.</summary>
    public Guid RunId { get; }

    /// <summary>The authenticated 16-byte FDO Device GUID.</summary>
    public ReadOnlyMemory<byte> DeviceGuid => (byte[])_deviceGuid.Clone();

    /// <summary>The DER Device attestation certificate verified for this run.</summary>
    public ReadOnlyMemory<byte> DeviceAttestationCertificate => (byte[])_deviceAttestationCertificate.Clone();

    /// <summary>
    /// The exact DER PKCS#10 request received over the protected channel. For
    /// server-generated keys, its public key and signature are ignored and do
    /// not prove possession.
    /// </summary>
    public ReadOnlyMemory<byte> CertificateSigningRequest => (byte[])_certificateSigningRequest.Clone();

    /// <summary>Whether the Device requested simple re-enrollment.</summary>
    public bool IsReenrollment { get; }

    /// <summary>
    /// Checked prior-certificate evidence, or null for initial enrollment and
    /// while the host is resolving the prior certificate.
    /// </summary>
    public FdoReenrollmentDetails? Reenrollment { get; }

    /// <summary>
    /// Attribute information sent earlier in this run, or null when none was
    /// sent. It does not establish that the CSR contains those attributes.
    /// </summary>
    public FdoCsrAttributes? CsrAttributes { get; }

    /// <summary>Whether this request asks the Owner to generate the private key.</summary>
    public bool IsServerKeyGeneration { get; }
}

/// <summary>
/// Detached request and issued certificate bound to the authenticated Done20
/// for one Owner run. The Device's receipt of DoneAck20 is a separate event.
/// </summary>
public sealed class FdoEnrollmentCommit
{
    private readonly byte[] _certificate;

    internal FdoEnrollmentCommit(FdoEnrollmentRequest request, ReadOnlyMemory<byte> certificate)
    {
        Request = request;
        _certificate = certificate.ToArray();
    }

    /// <summary>The authenticated request being committed.</summary>
    public FdoEnrollmentRequest Request { get; }

    /// <summary>The exact DER certificate issued for the request.</summary>
    public ReadOnlyMemory<byte> Certificate => (byte[])_certificate.Clone();
}
