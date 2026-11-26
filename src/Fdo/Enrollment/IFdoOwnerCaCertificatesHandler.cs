// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Enrollment;

/// <summary>Supplies CA distribution material for an authenticated Device.</summary>
/// <remarks>
/// The returned certificates and CRLs are candidates, not automatically
/// trusted material. Reject an unauthorized request by throwing an exception.
/// </remarks>
public interface IFdoOwnerCaCertificatesHandler
{
    /// <summary>Returns the material for one activated <c>fdo.csr</c> request.</summary>
    /// <param name="request">The request data for this exchange.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask<FdoCaCertificates> GetCaCertificatesAsync(
        FdoCaCertificatesRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Detached identity and format for one authenticated CA request.</summary>
public sealed class FdoCaCertificatesRequest
{
    private readonly byte[] _deviceGuid;
    private readonly byte[] _deviceAttestationCertificate;

    internal FdoCaCertificatesRequest(
        Guid runId,
        ReadOnlyMemory<byte> deviceGuid,
        ReadOnlyMemory<byte> deviceAttestationCertificate,
        ulong format)
    {
        RunId = runId;
        _deviceGuid = deviceGuid.ToArray();
        _deviceAttestationCertificate = deviceAttestationCertificate.ToArray();
        Format = format;
    }

    /// <summary>A locally generated identifier for this Owner run.</summary>
    public Guid RunId { get; }

    /// <summary>The authenticated 16-byte FDO Device GUID.</summary>
    public ReadOnlyMemory<byte> DeviceGuid => (byte[])_deviceGuid.Clone();

    /// <summary>The DER Device attestation certificate verified for this run.</summary>
    public ReadOnlyMemory<byte> DeviceAttestationCertificate => (byte[])_deviceAttestationCertificate.Clone();

    /// <summary>The requested <c>fdo.csr</c> certificate format.</summary>
    public ulong Format { get; }
}
