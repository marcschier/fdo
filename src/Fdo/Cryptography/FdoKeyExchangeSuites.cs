using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Fdo.Cryptography;

internal enum FdoKeyExchangeSuite
{
    Ecdh256,
    Ecdh384,
    DhkexId14,
    DhkexId15,
    Asymkex2048,
    Asymkex3072,
}

internal interface IFdoPairedKeyExchange : IDisposable
{
    byte[] ExportParameter();
    byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerParameter, out byte[] contextRand);
}

internal static class FdoKeyExchangeSuites
{
    public static bool IsDh(FdoKeyExchangeSuite suite) =>
        suite is FdoKeyExchangeSuite.DhkexId14 or FdoKeyExchangeSuite.DhkexId15;

    public static bool IsAsym(FdoKeyExchangeSuite suite) =>
        suite is FdoKeyExchangeSuite.Asymkex2048 or FdoKeyExchangeSuite.Asymkex3072;

    public static string GetName(FdoKeyExchangeSuite suite) => suite switch
    {
        FdoKeyExchangeSuite.Ecdh256 => "ECDH256",
        FdoKeyExchangeSuite.Ecdh384 => "ECDH384",
        FdoKeyExchangeSuite.DhkexId14 => "DHKEXid14",
        FdoKeyExchangeSuite.DhkexId15 => "DHKEXid15",
        FdoKeyExchangeSuite.Asymkex2048 => "ASYMKEX2048",
        FdoKeyExchangeSuite.Asymkex3072 => "ASYMKEX3072",
        _ => throw new ArgumentOutOfRangeException(nameof(suite)),
    };

    public static FdoKeyExchangeSuite ParseName(string name) => name switch
    {
        "ECDH256" => FdoKeyExchangeSuite.Ecdh256,
        "ECDH384" => FdoKeyExchangeSuite.Ecdh384,
        "DHKEXid14" => FdoKeyExchangeSuite.DhkexId14,
        "DHKEXid15" => FdoKeyExchangeSuite.DhkexId15,
        "ASYMKEX2048" => FdoKeyExchangeSuite.Asymkex2048,
        "ASYMKEX3072" => FdoKeyExchangeSuite.Asymkex3072,
        _ => throw new NotSupportedException("The paired key-exchange suite is not supported."),
    };

    public static void RequireParameterShape(
        FdoKeyExchangeSuite suite, bool isOwner, ReadOnlySpan<byte> parameter)
    {
        if (suite is FdoKeyExchangeSuite.Ecdh256 or FdoKeyExchangeSuite.Ecdh384)
        {
            int coordinateLength = suite == FdoKeyExchangeSuite.Ecdh256 ? 32 : 48;
            int randomLength = suite == FdoKeyExchangeSuite.Ecdh256 ? 16 : 48;
            int secondLengthOffset = 2 + coordinateLength;
            int randomLengthOffset = secondLengthOffset + 2 + coordinateLength;
            if (parameter.Length != randomLengthOffset + 2 + randomLength ||
                BinaryPrimitives.ReadUInt16BigEndian(parameter) != coordinateLength ||
                BinaryPrimitives.ReadUInt16BigEndian(parameter[secondLengthOffset..]) != coordinateLength ||
                BinaryPrimitives.ReadUInt16BigEndian(parameter[randomLengthOffset..]) != randomLength)
            {
                throw new CryptographicException("The ECDH parameter has an invalid field length.");
            }

            return;
        }

        int expectedLength = suite switch
        {
            FdoKeyExchangeSuite.DhkexId14 => 256,
            FdoKeyExchangeSuite.DhkexId15 => 384,
            FdoKeyExchangeSuite.Asymkex2048 => isOwner ? 32 : 256,
            FdoKeyExchangeSuite.Asymkex3072 => isOwner ? 96 : 384,
            _ => throw new ArgumentOutOfRangeException(nameof(suite)),
        };
        if (parameter.Length != expectedLength)
        {
            throw new CryptographicException("The key-exchange parameter has an invalid length.");
        }
    }
}
