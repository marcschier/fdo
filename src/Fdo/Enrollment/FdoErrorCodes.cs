// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Security.Cryptography;
using Fdo.Cryptography;

namespace Fdo.Enrollment;

/// <summary>Maps a local TO2 failure to the generic FDO Error codes this library sends.</summary>
internal static class FdoErrorCodes
{
    public const ushort MessageBodyError = 100;
    public const ushort InvalidMessageError = 101;
    public const ushort CredentialReuseError = 102;
    public const ushort DelegateNotPermitted = 104;
    public const ushort InternalServerError = 500;

    public static ushort Classify(Exception exception) => exception switch
    {
        FdoCredentialReuseDeniedException => CredentialReuseError,
        FdoDelegateNotPermittedException => DelegateNotPermitted,
        CborContentException => MessageBodyError,
        CryptographicException or NotSupportedException => InvalidMessageError,
        _ => InternalServerError,
    };

    public static ulong NewCorrelationId()
    {
        Span<byte> value = stackalloc byte[sizeof(ulong)];
        RandomNumberGenerator.Fill(value);
        return BinaryPrimitives.ReadUInt64LittleEndian(value);
    }
}

/// <summary>The Device refused the Owner's credential-reuse disposition.</summary>
[SuppressMessage("Roslynator", "RCS1194", Justification = "This exception always reports the same rejection reason.")]
internal sealed class FdoCredentialReuseDeniedException : InvalidOperationException
{
    public FdoCredentialReuseDeniedException()
        : base("Credential reuse was not explicitly enabled.")
    {
    }
}
