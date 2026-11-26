using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Enrollment;

/// <summary>Resolves the current credential and approves requested identity changes.</summary>
/// <remarks>
/// The host must resolve the actual current certificate for the authenticated
/// Device and enrollment scope. The CSR's identity alone is not sufficient to
/// select or authorize that certificate. A matching identity or public key does
/// not prove possession of the prior private key.
/// </remarks>
public interface IFdoOwnerReenrollmentHandler
{
    /// <summary>
    /// Returns the current DER certificate. During this callback,
    /// <see cref="FdoEnrollmentRequest.IsReenrollment"/> is true and
    /// <see cref="FdoEnrollmentRequest.Reenrollment"/> is null.
    /// Reject an unauthorized or unresolved request by throwing an exception.
    /// </summary>
    ValueTask<ReadOnlyMemory<byte>> GetPriorCertificateAsync(
        FdoEnrollmentRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    /// Approves the signed identity change after the library checks the CSR
    /// against the current certificate. Reject it by throwing an exception.
    /// </summary>
    ValueTask ApproveIdentityChangeAsync(
        FdoEnrollmentRequest request,
        CancellationToken cancellationToken);
}

/// <summary>The relation between the prior certificate key and the new CSR key.</summary>
public enum FdoReenrollmentKind
{
    /// <summary>The SubjectPublicKeyInfo values match.</summary>
    Renewal,

    /// <summary>The SubjectPublicKeyInfo values differ.</summary>
    Rekey,
}

/// <summary>Detached evidence checked against the host-selected prior certificate.</summary>
public sealed class FdoReenrollmentDetails
{
    private readonly byte[] _priorCertificate;

    internal FdoReenrollmentDetails(
        FdoReenrollmentKind kind,
        ReadOnlyMemory<byte> priorCertificate,
        FdoReenrollmentIdentityChange? identityChange)
    {
        Kind = kind;
        _priorCertificate = priorCertificate.ToArray();
        IdentityChange = identityChange;
    }

    /// <summary>Whether this request renews or rekeys the selected certificate.</summary>
    public FdoReenrollmentKind Kind { get; }

    /// <summary>The exact DER certificate selected by the host.</summary>
    public ReadOnlyMemory<byte> PriorCertificate => (byte[])_priorCertificate.Clone();

    /// <summary>The signed requested identity change, or null when absent.</summary>
    public FdoReenrollmentIdentityChange? IdentityChange { get; }
}

/// <summary>Detached RFC 6402 ChangeSubjectName evidence from the signed CSR.</summary>
public sealed class FdoReenrollmentIdentityChange
{
    private readonly byte[] _encodedValue;
    private readonly byte[] _subjectName;
    private readonly byte[]? _subjectAlternativeNames;

    internal FdoReenrollmentIdentityChange(
        ReadOnlyMemory<byte> encodedValue,
        ReadOnlyMemory<byte> subjectName,
        byte[]? subjectAlternativeNames)
    {
        _encodedValue = encodedValue.ToArray();
        _subjectName = subjectName.ToArray();
        _subjectAlternativeNames = subjectAlternativeNames is null
            ? null : (byte[])subjectAlternativeNames.Clone();
    }

    /// <summary>The exact DER ChangeSubjectName attribute value.</summary>
    public ReadOnlyMemory<byte> EncodedValue => (byte[])_encodedValue.Clone();

    /// <summary>
    /// The requested DER X.500 Name. An omitted subject requests an empty name.
    /// </summary>
    public ReadOnlyMemory<byte> SubjectName => (byte[])_subjectName.Clone();

    /// <summary>
    /// The requested DER GeneralNames value, or null when the change requests
    /// removal of the subject alternative name extension.
    /// </summary>
    public ReadOnlyMemory<byte>? SubjectAlternativeNames =>
        _subjectAlternativeNames is null
            ? (ReadOnlyMemory<byte>?)null
            : new ReadOnlyMemory<byte>((byte[])_subjectAlternativeNames.Clone());
}
