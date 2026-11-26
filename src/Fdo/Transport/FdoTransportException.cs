using System;
using System.Net;

namespace Fdo.Transport;

/// <summary>
/// The category of an FDO transport failure.
/// </summary>
public enum FdoTransportFailure
{
    /// <summary>
    /// The request did not complete because of a connection failure or timeout.
    /// The sending role determines whether its session can continue.
    /// </summary>
    Network,

    /// <summary>
    /// The server returned an HTTP status that FDO 2.0 §4.3 and §5.1.1 do not
    /// permit for this request.
    /// </summary>
    UnexpectedStatus,

    /// <summary>
    /// The response violated the FDO HTTP binding: missing or invalid
    /// Message-Type, a message type outside the session's sub-protocol, an
    /// empty or invalid CBOR body, or a redirect that the HTTP stack followed.
    /// </summary>
    InvalidResponse,

    /// <summary>
    /// The server did not allocate a token on the first response, changed it
    /// later in the session, or received an invalid request token.
    /// </summary>
    Authorization,

    /// <summary>
    /// The response body exceeded the session's configured limit.
    /// </summary>
    ResponseTooLarge,

    /// <summary>The HTTP request metadata or body framing is invalid.</summary>
    InvalidRequest,

    /// <summary>The request body exceeded the configured limit.</summary>
    RequestTooLarge,

    /// <summary>The Rendezvous Server redirected the initial TO1 request.</summary>
    RendezvousRedirect,
}

/// <summary>
/// Raised when an FDO HTTP exchange fails below the message layer.
/// </summary>
public sealed class FdoTransportException : Exception
{
    /// <summary>
    /// Creates a transport exception.
    /// </summary>
    public FdoTransportException(
        FdoTransportFailure failure,
        string message,
        HttpStatusCode? statusCode = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Failure = failure;
        StatusCode = statusCode;
    }

    internal FdoTransportException(HttpStatusCode statusCode, Uri redirectLocation)
        : this(
            FdoTransportFailure.RendezvousRedirect,
            "The Rendezvous Server returned a redirect. The host must authorize any new TO1 run.",
            statusCode)
    {
        RedirectLocation = redirectLocation;
    }

    /// <summary>
    /// The failure category.
    /// </summary>
    public FdoTransportFailure Failure { get; }

    /// <summary>
    /// The HTTP status code, when the server responded.
    /// </summary>
    public HttpStatusCode? StatusCode { get; }

    /// <summary>
    /// The untrusted absolute redirect target, when a paired TO1 Hello request
    /// received a redirect. It can be a full request URI rather than a base
    /// address, and it may contain sensitive server-supplied data.
    /// </summary>
    public Uri? RedirectLocation { get; }
}
