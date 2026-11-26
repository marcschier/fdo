// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Enrollment;

/// <summary>
/// Optional Device transport capability for one protected FDO Error after key exchange.
/// </summary>
/// <remarks>
/// The Device session seals the body on the live TO2 channel before calling
/// this method, and calls it at most once per run. The transport sends the
/// sealed body to the same Owner session and must not retry, redirect, or
/// fall back to an unprotected body. A successful return means the Owner
/// accepted the terminal Error.
/// </remarks>
public interface IFdoDeviceErrorTransport
{
    /// <summary>Sends one sealed FDO Error to the Owner session.</summary>
    /// <param name="protocolVersion">The numeric FDO protocol version.</param>
    /// <param name="encodedBody">The FDO body bytes, excluding transport framing.</param>
    /// <param name="cancellationToken">A token that cancels the operation.</param>
    ValueTask SendErrorAsync(
        ushort protocolVersion,
        ReadOnlyMemory<byte> encodedBody,
        CancellationToken cancellationToken);
}
