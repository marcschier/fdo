using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Enrollment;

/// <summary>Supplies CSR attribute information for an authenticated Device.</summary>
/// <remarks>
/// Reject an unauthorized request by throwing an exception. Returning
/// attributes does not authorize or guarantee subsequent certificate issuance.
/// </remarks>
public interface IFdoOwnerCsrAttributesHandler
{
    /// <summary>Returns the attribute information for this request.</summary>
    ValueTask<FdoCsrAttributes> GetCsrAttributesAsync(
        FdoCsrAttributesRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Detached identity for one authenticated CSR attributes request.</summary>
public sealed class FdoCsrAttributesRequest
{
    private readonly byte[] _deviceGuid;
    private readonly byte[] _deviceAttestationCertificate;

    internal FdoCsrAttributesRequest(
        Guid runId,
        ReadOnlyMemory<byte> deviceGuid,
        ReadOnlyMemory<byte> deviceAttestationCertificate)
    {
        RunId = runId;
        _deviceGuid = deviceGuid.ToArray();
        _deviceAttestationCertificate = deviceAttestationCertificate.ToArray();
    }

    /// <summary>A locally generated identifier for this Owner run.</summary>
    public Guid RunId { get; }

    /// <summary>The authenticated 16-byte FDO Device GUID.</summary>
    public ReadOnlyMemory<byte> DeviceGuid => (byte[])_deviceGuid.Clone();

    /// <summary>The DER Device attestation certificate verified for this run.</summary>
    public ReadOnlyMemory<byte> DeviceAttestationCertificate => (byte[])_deviceAttestationCertificate.Clone();
}
