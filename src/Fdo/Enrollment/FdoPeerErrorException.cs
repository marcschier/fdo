// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Globalization;

namespace Fdo.Enrollment;

/// <summary>
/// The Owner ended the TO2 run with an FDO Error that the Device authenticated
/// on the live protected channel. The peer's description text is not retained.
/// </summary>
public sealed class FdoPeerErrorException : Exception
{
    /// <summary>Creates the exception for an authenticated peer Error.</summary>
    public FdoPeerErrorException(ushort errorCode, FdoTo2MessageType previousMessageType)
        : base(string.Create(
            CultureInfo.InvariantCulture,
            $"The FDO peer ended the run with Error {errorCode} after message {(byte)previousMessageType}."))
    {
        ErrorCode = errorCode;
        PreviousMessageType = previousMessageType;
    }

    /// <summary>The FDO Error code sent by the peer.</summary>
    public ushort ErrorCode { get; }

    /// <summary>The Device request that the peer's Error names.</summary>
    public FdoTo2MessageType PreviousMessageType { get; }
}
