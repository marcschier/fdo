using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Enrollment;

/// <summary>Installs a server-generated credential after authenticated DoneAck20.</summary>
/// <remarks>
/// The private key is available only for the duration of the callback. Import
/// it before returning, protect any copies, and do not log it. A throwing or
/// canceled callback can have an unknown durable outcome.
/// </remarks>
public interface IFdoDeviceServerKeygenHandler
{
    /// <summary>Durably installs the enrollment and DER PKCS#8 private key.</summary>
    ValueTask InstallAsync(
        FdoDeviceEnrollment enrollment,
        ReadOnlyMemory<byte> privateKeyPkcs8,
        CancellationToken cancellationToken);
}
