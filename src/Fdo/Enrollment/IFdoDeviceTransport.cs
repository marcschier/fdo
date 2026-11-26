using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Enrollment;

/// <summary>Exchanges encoded FDO request and response bodies for one Device run.</summary>
/// <remarks>
/// The host binds every request to the same Owner session and bounds each
/// response while reading it. It must not retry or redirect a request after
/// delivery is uncertain. A transport failure ends the Device run. The
/// Device session does not close or dispose the transport.
/// </remarks>
public interface IFdoDeviceTransport
{
    /// <summary>Sends one request and returns the Owner's response.</summary>
    ValueTask<FdoOwnerResponse> SendAsync(
        ushort protocolVersion,
        FdoTo2MessageType messageType,
        ReadOnlyMemory<byte> encodedBody,
        CancellationToken cancellationToken);
}
