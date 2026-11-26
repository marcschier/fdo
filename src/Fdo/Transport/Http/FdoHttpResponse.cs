using System;
using Fdo.Serialization;

namespace Fdo.Transport.Http;

/// <summary>
/// How the server answered an FDO HTTP request.
/// </summary>
internal enum FdoHttpResponseKind
{
    /// <summary>
    /// HTTP 200 carrying the next protocol message.
    /// </summary>
    Message,

    /// <summary>
    /// HTTP 500 carrying an FDO Error message (§5.1.1). The session is terminated.
    /// </summary>
    Error,

    /// <summary>
    /// HTTP 302 or 307 in answer to TO1.HelloRV (§5.4.1). The session is
    /// terminated and the host decides whether to start another TO1 run.
    /// </summary>
    Redirect,
}

/// <summary>
/// A validated FDO HTTP response. Message bodies retain their original encoding;
/// their protocol-specific fields are not decoded by this layer.
/// </summary>
internal sealed class FdoHttpResponse
{
    private FdoHttpResponse(
        FdoHttpResponseKind kind,
        ushort messageType,
        ReadOnlyMemory<byte> body,
        Uri? redirectLocation,
        FdoCborCodec.StreamMessage? streamMessage = null)
    {
        Kind = kind;
        MessageType = messageType;
        Body = body;
        RedirectLocation = redirectLocation;
        StreamMessage = streamMessage;
    }

    /// <summary>
    /// The response kind.
    /// </summary>
    public FdoHttpResponseKind Kind { get; }

    /// <summary>
    /// The FDO message type. 255 for <see cref="FdoHttpResponseKind.Error"/>;
    /// 0 for <see cref="FdoHttpResponseKind.Redirect"/>.
    /// </summary>
    public ushort MessageType { get; }

    /// <summary>
    /// The CBOR message body. Empty for <see cref="FdoHttpResponseKind.Redirect"/>.
    /// </summary>
    public ReadOnlyMemory<byte> Body { get; }

    /// <summary>
    /// The absolute redirect target for <see cref="FdoHttpResponseKind.Redirect"/>.
    /// </summary>
    public Uri? RedirectLocation { get; }

    /// <summary>The reconstructed StreamMsg; absent for an HTTP redirect.</summary>
    public FdoCborCodec.StreamMessage? StreamMessage { get; }

    internal static FdoHttpResponse Message(FdoCborCodec.StreamMessage message) =>
        new(FdoHttpResponseKind.Message, message.MessageType, message.Body, null, message);

    internal static FdoHttpResponse Error(FdoCborCodec.StreamMessage message) =>
        new(FdoHttpResponseKind.Error, FdoMessageTypes.Error, message.Body, null, message);

    internal static FdoHttpResponse Redirect(Uri location) =>
        new(FdoHttpResponseKind.Redirect, 0, ReadOnlyMemory<byte>.Empty, location);
}
