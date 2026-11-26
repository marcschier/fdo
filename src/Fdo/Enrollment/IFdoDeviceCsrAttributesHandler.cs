// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Enrollment;

/// <summary>Creates or selects a CSR after receiving Owner attributes.</summary>
/// <remarks>
/// The host interprets attributes it recognizes, ignores unknown identifiers or
/// attributes and owns the CSR policy and any client-generated enrollment
/// key. Reject discovery by throwing an exception. Returning a CSR does not
/// authorize its issuance.
/// </remarks>
public interface IFdoDeviceCsrAttributesHandler
{
    /// <summary>
    /// Returns a DER PKCS#10 request. Client-key enrollment requires a valid
    /// signature; server-side key generation ignores its key and signature.
    /// </summary>
    /// <param name="request">The request data for this exchange.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask<ReadOnlyMemory<byte>> CreateCertificateSigningRequestAsync(
        FdoDeviceCsrAttributesRequest request,
        CancellationToken cancellationToken);
}

/// <summary>Detached evidence received before the Device prepares its CSR.</summary>
public sealed class FdoDeviceCsrAttributesRequest
{
    private readonly byte[] _deviceGuid;

    internal FdoDeviceCsrAttributesRequest(
        Guid runId,
        ReadOnlyMemory<byte> deviceGuid,
        FdoCsrAttributes attributes,
        FdoCaCertificates? caCertificates,
        bool isReenrollment,
        bool isServerKeyGeneration)
    {
        RunId = runId;
        _deviceGuid = deviceGuid.ToArray();
        Attributes = attributes;
        CaCertificates = caCertificates;
        IsReenrollment = isReenrollment;
        IsServerKeyGeneration = isServerKeyGeneration;
    }

    /// <summary>A locally generated identifier for this Device run.</summary>
    public Guid RunId { get; }

    /// <summary>The 16-byte FDO Device GUID.</summary>
    public ReadOnlyMemory<byte> DeviceGuid => (byte[])_deviceGuid.Clone();

    /// <summary>CSR attribute information received from the authenticated Owner.</summary>
    public FdoCsrAttributes Attributes { get; }

    /// <summary>Distributed CA material, or null when it was not requested.</summary>
    public FdoCaCertificates? CaCertificates { get; }

    /// <summary>Whether the Device intends to request simple re-enrollment.</summary>
    public bool IsReenrollment { get; }

    /// <summary>Whether the Device intends to request a server-generated key.</summary>
    public bool IsServerKeyGeneration { get; }
}
