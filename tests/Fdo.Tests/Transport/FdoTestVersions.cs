using Fdo.Transport;

namespace Fdo.Tests.Transport;

internal static class FdoTestVersions
{
    // This invented version exercises HTTP mechanics without claiming FDO support.
    public static FdoProtocolVersion SyntheticHttp { get; } = new(650, 99);
}
