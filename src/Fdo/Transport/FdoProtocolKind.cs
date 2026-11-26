// Copyright (c) marcschier. Licensed under the MIT License.

namespace Fdo.Transport;

/// <summary>
/// The FDO sub-protocol that one transport session carries. FDO 2.0 §4.3
/// scopes an HTTP authorization token to a single sub-protocol run.
/// </summary>
internal enum FdoProtocolKind
{
    /// <summary>
    /// Device Initialize (DI), message types 10 to 13.
    /// </summary>
    DeviceInitialize = 0,

    /// <summary>
    /// Transfer Ownership 0 (TO0), message types 20 to 23.
    /// </summary>
    TransferOwnership0 = 1,

    /// <summary>
    /// Transfer Ownership 1 (TO1), message types 30 to 33.
    /// </summary>
    TransferOwnership1 = 2,

    /// <summary>
    /// Transfer Ownership 2 (TO2) version 2.0, message types 80 to 91.
    /// </summary>
    TransferOwnership2 = 3,
}
