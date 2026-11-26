namespace Fdo.Transport;

/// <summary>
/// FDO 2.0 message type numbers (§5) and the direction each one travels
/// within its sub-protocol.
/// </summary>
internal static class FdoMessageTypes
{
    /// <summary>Error, type 255 (§5.1.1).</summary>
    public const ushort Error = 255;

    /// <summary>DI.AppStart, type 10.</summary>
    public const ushort DIAppStart = 10;

    /// <summary>DI.SetCredentials, type 11.</summary>
    public const ushort DISetCredentials = 11;

    /// <summary>DI.SetHMAC, type 12.</summary>
    public const ushort DISetHmac = 12;

    /// <summary>DI.Done, type 13.</summary>
    public const ushort DIDone = 13;

    /// <summary>TO0.Hello, type 20.</summary>
    public const ushort TO0Hello = 20;

    /// <summary>TO0.HelloAck, type 21.</summary>
    public const ushort TO0HelloAck = 21;

    /// <summary>TO0.OwnerSign, type 22.</summary>
    public const ushort TO0OwnerSign = 22;

    /// <summary>TO0.AcceptOwner, type 23.</summary>
    public const ushort TO0AcceptOwner = 23;

    /// <summary>TO1.HelloRV, type 30.</summary>
    public const ushort TO1HelloRV = 30;

    /// <summary>TO1.HelloRVAck, type 31.</summary>
    public const ushort TO1HelloRVAck = 31;

    /// <summary>TO1.ProveToRV, type 32. TO1.RVMore also uses type 32 (§5.4.5).</summary>
    public const ushort TO1ProveToRV = 32;

    /// <summary>TO1.RVRedirect, type 33.</summary>
    public const ushort TO1RVRedirect = 33;

    /// <summary>TO2.HelloDeviceProbe, type 80.</summary>
    public const ushort TO2HelloDeviceProbe = 80;

    /// <summary>TO2.HelloDeviceAck20, type 81.</summary>
    public const ushort TO2HelloDeviceAck20 = 81;

    /// <summary>TO2.ProveDevice20, type 82.</summary>
    public const ushort TO2ProveDevice20 = 82;

    /// <summary>TO2.ProveOVHdr20, type 83.</summary>
    public const ushort TO2ProveOVHdr20 = 83;

    /// <summary>TO2.GetOVNextEntry20, type 84.</summary>
    public const ushort TO2GetOVNextEntry20 = 84;

    /// <summary>TO2.OVNextEntry20, type 85.</summary>
    public const ushort TO2OVNextEntry20 = 85;

    /// <summary>TO2.DeviceServiceInfoRdy20, type 86.</summary>
    public const ushort TO2DeviceServiceInfoRdy20 = 86;

    /// <summary>TO2.SetupDevice20, type 87.</summary>
    public const ushort TO2SetupDevice20 = 87;

    /// <summary>TO2.DeviceSvcInfo20, type 88.</summary>
    public const ushort TO2DeviceSvcInfo20 = 88;

    /// <summary>TO2.OwnerSvcInfo20, type 89.</summary>
    public const ushort TO2OwnerSvcInfo20 = 89;

    /// <summary>TO2.Done20, type 90. Its HTTP suffix was selected by the user.</summary>
    public const ushort TO2Done20 = 90;

    /// <summary>TO2.DoneAck20, type 91.</summary>
    public const ushort TO2DoneAck20 = 91;

    /// <summary>
    /// Returns whether <paramref name="messageType"/> is a request of
    /// <paramref name="protocol"/>. The Error message is excluded because
    /// it has its own send path.
    /// </summary>
    public static bool IsRequest(FdoProtocolKind protocol, ushort messageType) => protocol switch
    {
        FdoProtocolKind.DeviceInitialize => messageType is DIAppStart or DISetHmac,
        FdoProtocolKind.TransferOwnership0 => messageType is TO0Hello or TO0OwnerSign,
        FdoProtocolKind.TransferOwnership1 => messageType is TO1HelloRV or TO1ProveToRV,
        FdoProtocolKind.TransferOwnership2 => messageType is TO2HelloDeviceProbe
            or TO2ProveDevice20
            or TO2GetOVNextEntry20
            or TO2DeviceServiceInfoRdy20
            or TO2DeviceSvcInfo20
            or TO2Done20,
        _ => false,
    };

    /// <summary>
    /// Identifies requests that require unavailable TO2 session protection.
    /// ServiceInfo request bodies also have unresolved ReplacementHMac semantics.
    /// </summary>
    public static bool RequiresUnavailableTo2Protection(FdoProtocolKind protocol, ushort messageType) =>
        protocol == FdoProtocolKind.TransferOwnership2 &&
        messageType is TO2DeviceServiceInfoRdy20 or TO2DeviceSvcInfo20 or TO2Done20;

    /// <summary>
    /// Returns whether the HTTP server of <paramref name="protocol"/> sends
    /// <paramref name="messageType"/> as a successful response. The Error
    /// message is excluded because §5.1.1 carries it with HTTP status 500.
    /// </summary>
    public static bool IsResponse(FdoProtocolKind protocol, ushort messageType) => protocol switch
    {
        FdoProtocolKind.DeviceInitialize => messageType is DISetCredentials or DIDone,
        FdoProtocolKind.TransferOwnership0 => messageType is TO0HelloAck or TO0AcceptOwner,
        FdoProtocolKind.TransferOwnership1 => messageType is TO1HelloRVAck or TO1RVRedirect,
        FdoProtocolKind.TransferOwnership2 => messageType is TO2HelloDeviceAck20
            or TO2ProveOVHdr20
            or TO2OVNextEntry20
            or TO2SetupDevice20
            or TO2OwnerSvcInfo20
            or TO2DoneAck20,
        _ => false,
    };
}
