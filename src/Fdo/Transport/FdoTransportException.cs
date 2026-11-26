// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
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
    Network = 0,

    /// <summary>
    /// The server returned an HTTP status that FDO 2.0 §4.3 and §5.1.1 do not
    /// permit for this request.
    /// </summary>
    UnexpectedStatus = 1,

    /// <summary>
    /// The response violated the FDO HTTP binding: missing or invalid
    /// Message-Type, a message type outside the session's sub-protocol, an
    /// empty or invalid CBOR body, or a redirect that the HTTP stack followed.
    /// </summary>
    InvalidResponse = 2,

    /// <summary>
    /// The server did not allocate a token on the first response, changed it
    /// later in the session, or received an invalid request token.
    /// </summary>
    Authorization = 3,

    /// <summary>
    /// The response body exceeded the session's configured limit.
    /// </summary>
    ResponseTooLarge = 4,

    /// <summary>The HTTP request metadata or body framing is invalid.</summary>
    InvalidRequest = 5,

    /// <summary>The request body exceeded the configured limit.</summary>
    RequestTooLarge = 6,

    /// <summary>The Rendezvous Server redirected the initial TO1 request.</summary>
    RendezvousRedirect = 7,
}

/// <summary>
/// Raised when an FDO HTTP exchange fails below the message layer.
/// </summary>
[SuppressMessage("Roslynator", "RCS1194", Justification = "A transport failure classification is required.")]
public sealed class FdoTransportException : Exception
{
    /// <summary>
    /// Creates a transport exception.
    /// </summary>
    /// <param name="failure">The transport failure classification.</param>
    /// <param name="message">The diagnostic text for the failure.</param>
    /// <param name="statusCode">The HTTP status code.</param>
    /// <param name="innerException">The underlying exception, if one is available.</param>
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
