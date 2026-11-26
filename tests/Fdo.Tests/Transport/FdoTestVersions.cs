// Copyright (c) marcschier. Licensed under the MIT License.

using Fdo.Transport;

namespace Fdo.Tests.Transport;

internal static class FdoTestVersions
{
    /// <summary>
    /// This invented version exercises HTTP mechanics without claiming FDO support.
    /// </summary>
    public static FdoProtocolVersion SyntheticHttp { get; } = new(650, 99);
}
