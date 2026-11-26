using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

internal static class FdoSecretBuffer
{
    public static void ClearOwned(ReadOnlyMemory<byte> value)
    {
        if (!MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment) || segment.Array is null)
        {
            throw new InvalidOperationException("The secret is not backed by owned memory.");
        }

        CryptographicOperations.ZeroMemory(segment.Array.AsSpan(segment.Offset, segment.Count));
    }
}
