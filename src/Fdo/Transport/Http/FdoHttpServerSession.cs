using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Enrollment;
using Fdo.Initialization;
using Fdo.Rendezvous;

namespace Fdo.Transport.Http;

/// <summary>One HTTP request presented by the server host.</summary>
/// <remarks>
/// The host must reject invalid HTTP framing and supply a body stream limited
/// to this request. The target is the unmodified origin-form request target.
/// Header values must preserve duplicates so the binding can reject them.
/// </remarks>
public sealed class FdoHttpServerRequest
{
    private IPAddress? _observedSource;

    /// <summary>The HTTP method.</summary>
    public required string Method { get; init; }

    /// <summary>The raw path and query received in the HTTP request target.</summary>
    public required string Target { get; init; }

    /// <summary>All Authorization header values, or an empty list.</summary>
    public IReadOnlyList<string> AuthorizationValues { get; init; } = Array.Empty<string>();

    /// <summary>All Content-Type header values, or an empty list.</summary>
    public IReadOnlyList<string> ContentTypeValues { get; init; } = Array.Empty<string>();

    /// <summary>The request body stream, which remains owned by the host.</summary>
    public required Stream Body { get; init; }

    /// <summary>The validated Content-Length, or null when the length is unknown.</summary>
    public long? ContentLength { get; init; }

    /// <summary>
    /// The observed submitter address for this request, required for delegated
    /// TO0 OwnerSign. The host resolves it through any trusted proxy path.
    /// This binding does not read forwarded headers.
    /// </summary>
    public IPAddress? ObservedSource
    {
        get => CopyAddress(_observedSource);
        init => _observedSource = CopyAddress(value);
    }

    private static IPAddress? CopyAddress(IPAddress? address) => address is null ? null :
        address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? new IPAddress(address.GetAddressBytes(), address.ScopeId)
            : new IPAddress(address.GetAddressBytes());
}

/// <summary>A detached HTTP response for one paired FDO request.</summary>
/// <remarks>
/// The host sends <see cref="StatusCode"/>, <see cref="Authorization"/> as
/// Authorization and, when the body is not empty, <see cref="MessageType"/>
/// as Message-Type and the body as application/cbor. The authorization value
/// is a bearer secret. Status 500 carries a protected TO2 Error or an
/// authenticated TO0 permission rejection; status 200
/// with an empty body accepts a terminal FDO Error. Both end the binding, so
/// the host sends them once and does not confirm handoff.
/// </remarks>
public sealed class FdoHttpServerResponse
{
    private readonly byte[] _encodedBody;

    internal FdoHttpServerResponse(
        ushort messageType, string authorization, ReadOnlyMemory<byte> encodedBody, int statusCode = 200)
    {
        MessageType = messageType;
        Authorization = authorization;
        StatusCode = statusCode;
        _encodedBody = encodedBody.ToArray();
    }

    /// <summary>The HTTP status code: 200, or 500 for an FDO Error body.</summary>
    public int StatusCode { get; }

    /// <summary>Whether this response ended the binding and must not be confirmed.</summary>
    public bool IsTerminal => MessageType == FdoMessageTypes.Error;

    /// <summary>The numeric FDO response type.</summary>
    public ushort MessageType { get; }

    /// <summary>The session's bearer authorization value.</summary>
    public string Authorization { get; }

    /// <summary>The exact encoded FDO response body.</summary>
    public ReadOnlyMemory<byte> EncodedBody => (byte[])_encodedBody.Clone();
}

/// <summary>Binds one paired server role session to HTTP requests.</summary>
/// <remarks>
/// The host creates one binding for each initial request, routes later
/// requests by the issued bearer value, and serializes processing with
/// response handoff. It registers the token before sending the first response
/// and removes it when the run ends. It must protect tokens from disclosure,
/// authenticate or authorize peers where required, limit concurrent sessions
/// and lifetimes, and reject malformed HTTP framing. The binding owns the
/// supplied role session. Dispose it if response handoff fails or is uncertain.
/// Confirmation records a host handoff, not peer receipt.
/// </remarks>
[UnsupportedOSPlatform("browser")]
public sealed class FdoHttpServerSession : IDisposable
{
    private readonly FdoProtocolKind _protocol;
    private readonly string _routePrefix;
    private readonly int _maxRequestBytes;
    private readonly Func<ushort, ReadOnlyMemory<byte>, IPAddress?, CancellationToken, ValueTask<ServerMessage>> _process;
    private readonly Action _confirm;
    private readonly Action _disposeRole;
    private readonly FdoRendezvousServerSession? _rendezvous;
    private string? _authorization;
    private ushort _pendingResponseType;
    private int _busy;
    private bool _awaitingHandoff;
    private bool _complete;
    private bool _disposed;

    private FdoHttpServerSession(
        FdoProtocolKind protocol,
        string pathPrefix,
        int maxRequestBytes,
        Func<ushort, ReadOnlyMemory<byte>, IPAddress?, CancellationToken, ValueTask<ServerMessage>> process,
        Action confirm,
        Action disposeRole,
        FdoRendezvousServerSession? rendezvous = null)
    {
        ArgumentNullException.ThrowIfNull(pathPrefix);
        if (maxRequestBytes is <= 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(maxRequestBytes));
        }

        if (pathPrefix == "/")
        {
            pathPrefix = string.Empty;
        }

        if (pathPrefix.Length > 1024 ||
            (pathPrefix.Length != 0 &&
             (!pathPrefix.StartsWith("/", StringComparison.Ordinal) ||
              pathPrefix.EndsWith("/", StringComparison.Ordinal) ||
              pathPrefix.Contains("//", StringComparison.Ordinal) ||
              pathPrefix.IndexOfAny(['?', '#', '\\', '\r', '\n']) >= 0)))
        {
            throw new ArgumentException("The HTTP path prefix must be an absolute path without a trailing slash or query.", nameof(pathPrefix));
        }

        _protocol = protocol;
        _routePrefix = pathPrefix + "/fdo/200/msg/";
        _maxRequestBytes = maxRequestBytes;
        _process = process;
        _confirm = confirm;
        _disposeRole = disposeRole;
        _rendezvous = rendezvous;
    }

    /// <summary>Creates a binding that owns one Owner TO2 session.</summary>
    public static FdoHttpServerSession ForOwner(
        FdoOwnerSession owner, int maxRequestBytes = ushort.MaxValue, string pathPrefix = "")
    {
        ArgumentNullException.ThrowIfNull(owner);
        return new FdoHttpServerSession(
            FdoProtocolKind.TransferOwnership2, pathPrefix, maxRequestBytes,
            async (type, body, _, cancellationToken) =>
            {
                FdoOwnerResponse response = await owner.ProcessAsync(
                    200, (FdoTo2MessageType)type, body, cancellationToken).ConfigureAwait(false);
                return new ServerMessage(response.ProtocolVersion, (ushort)response.MessageType, response.EncodedBody);
            },
            owner.ConfirmResponseSent, owner.Dispose);
    }

    /// <summary>Creates a binding that owns one manufacturer DI session.</summary>
    public static FdoHttpServerSession ForManufacturer(
        FdoManufacturerInitializeSession manufacturer, int maxRequestBytes = ushort.MaxValue, string pathPrefix = "")
    {
        ArgumentNullException.ThrowIfNull(manufacturer);
        return new FdoHttpServerSession(
            FdoProtocolKind.DeviceInitialize, pathPrefix, maxRequestBytes,
            async (type, body, _, cancellationToken) =>
            {
                FdoDeviceInitializeResponse response = await manufacturer.ProcessAsync(
                    200, (FdoDeviceInitializeMessageType)type, body, cancellationToken).ConfigureAwait(false);
                return new ServerMessage(response.ProtocolVersion, (ushort)response.MessageType, response.EncodedBody);
            },
            manufacturer.ConfirmResponseSent, manufacturer.Dispose);
    }

    /// <summary>Creates a binding that owns one TO0 or TO1 Rendezvous Server session.</summary>
    public static FdoHttpServerSession ForRendezvous(
        FdoRendezvousServerSession server, int maxRequestBytes = ushort.MaxValue, string pathPrefix = "")
    {
        ArgumentNullException.ThrowIfNull(server);
        FdoProtocolKind protocol = server.Protocol == FdoRendezvousProtocol.OwnerRegistration
            ? FdoProtocolKind.TransferOwnership0 : FdoProtocolKind.TransferOwnership1;
        return new FdoHttpServerSession(
            protocol, pathPrefix, maxRequestBytes,
            async (type, body, observedSource, cancellationToken) =>
            {
                FdoRendezvousResponse response = await server.ProcessAsync(
                    200, (FdoRendezvousMessageType)type, body, observedSource, cancellationToken).ConfigureAwait(false);
                return new ServerMessage(response.ProtocolVersion, (ushort)response.MessageType, response.EncodedBody);
            },
            server.ConfirmResponseSent, server.Dispose, server);
    }

    /// <summary>Whether the final response handoff has been confirmed.</summary>
    public bool IsComplete => Volatile.Read(ref _complete);

    /// <summary>
    /// Processes a request and returns its response without confirming handoff.
    /// A failure after a request is admitted ends this binding.
    /// </summary>
    public async ValueTask<FdoHttpServerResponse> ProcessAsync(
        FdoHttpServerRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The HTTP server session is already processing a request.");
        }

        bool admitted = false;
        bool completed = false;
        try
        {
            RequireUsable(allowCompleted: _rendezvous?.CanRepeatLastRedirectPage == true);
            if (_awaitingHandoff)
            {
                throw new InvalidOperationException("Confirm the previous response handoff before another request.");
            }

            ushort messageType = ValidateRequest(request);
            ValidateAuthorization(request.AuthorizationValues);
            admitted = true;
            cancellationToken.ThrowIfCancellationRequested();
            ReadOnlyMemory<byte> body = await ReadBodyAsync(request, cancellationToken).ConfigureAwait(false);
            ServerMessage response = await _process(messageType, body, request.ObservedSource, cancellationToken)
                .ConfigureAwait(false);
            if (response.Type == FdoMessageTypes.Error &&
                (_protocol == FdoProtocolKind.TransferOwnership2 ||
                 (_protocol == FdoProtocolKind.TransferOwnership0 && messageType == FdoMessageTypes.TO0OwnerSign)))
            {
                FdoHttpServerResponse terminal = CreateTerminalResponse(messageType, response);
                completed = true;
                DisposeCore();
                return terminal;
            }

            cancellationToken.ThrowIfCancellationRequested();
            if (response.Version != 200 || !FdoMessageTypes.IsResponse(_protocol, response.Type) ||
                response.Body.IsEmpty || response.Body.Length > ushort.MaxValue)
            {
                throw new InvalidOperationException("The paired role returned an invalid FDO response.");
            }

            _authorization ??= "Bearer " + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var result = new FdoHttpServerResponse(response.Type, _authorization, response.Body);
            _pendingResponseType = response.Type;
            _awaitingHandoff = true;
            completed = true;
            return result;
        }
        finally
        {
            try
            {
                if (admitted && !completed)
                {
                    DisposeCore();
                }
            }
            finally
            {
                Volatile.Write(ref _busy, 0);
            }
        }
    }

    /// <summary>Records a successful response handoff, not peer receipt.</summary>
    public void ConfirmResponseSent()
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The HTTP server session is already processing a request.");
        }

        try
        {
            RequireUsable(allowCompleted: _awaitingHandoff);
            if (!_awaitingHandoff)
            {
                throw new InvalidOperationException("No HTTP response is awaiting handoff.");
            }

            bool confirmed = false;
            try
            {
                _confirm();
                confirmed = true;
            }
            finally
            {
                if (!confirmed)
                {
                    DisposeCore();
                }
            }

            _awaitingHandoff = false;
            if (_pendingResponseType is FdoMessageTypes.DIDone or FdoMessageTypes.TO0AcceptOwner or FdoMessageTypes.TO2DoneAck20 ||
                (_pendingResponseType == FdoMessageTypes.TO1RVRedirect && _rendezvous?.FinalResponseHandoffConfirmed == true))
            {
                Volatile.Write(ref _complete, true);
            }
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    /// <summary>Ends the binding and its role without changing host storage.</summary>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _busy, 1, 0) != 0)
        {
            throw new InvalidOperationException("The HTTP server session is already processing a request.");
        }

        try
        {
            DisposeCore();
        }
        finally
        {
            Volatile.Write(ref _busy, 0);
        }
    }

    private FdoHttpServerResponse CreateTerminalResponse(ushort requestType, ServerMessage response)
    {
        // A TO2 Error POST gets an empty 200. A role-generated Error response
        // to an authenticated request carries the Error body with status 500.
        string authorization = _authorization
            ?? throw new InvalidOperationException("The paired role returned an FDO Error before a session existed.");
        if (response.Version != 200)
        {
            throw new InvalidOperationException("The paired role returned an invalid FDO Error.");
        }

        if (requestType == FdoMessageTypes.Error)
        {
            if (!response.Body.IsEmpty)
            {
                throw new InvalidOperationException("The paired role answered an FDO Error with a body.");
            }

            return new FdoHttpServerResponse(FdoMessageTypes.Error, authorization, ReadOnlyMemory<byte>.Empty, 200);
        }

        if (response.Body.IsEmpty || response.Body.Length > ushort.MaxValue)
        {
            throw new InvalidOperationException("The paired role returned an invalid FDO Error.");
        }

        return new FdoHttpServerResponse(FdoMessageTypes.Error, authorization, response.Body, 500);
    }

    private ushort ValidateRequest(FdoHttpServerRequest request)
    {
        ArgumentNullException.ThrowIfNull(request.Method);
        ArgumentNullException.ThrowIfNull(request.Target);
        ArgumentNullException.ThrowIfNull(request.AuthorizationValues);
        ArgumentNullException.ThrowIfNull(request.ContentTypeValues);
        ArgumentNullException.ThrowIfNull(request.Body);
        if (!string.Equals(request.Method, "POST", StringComparison.Ordinal) ||
            !request.Target.StartsWith(_routePrefix, StringComparison.Ordinal))
        {
            throw InvalidRequest("The HTTP method or FDO route is invalid.");
        }

        ReadOnlySpan<char> suffix = request.Target.AsSpan(_routePrefix.Length);
        if (suffix.Length is < 1 or > 5 ||
            !ushort.TryParse(suffix, NumberStyles.None, CultureInfo.InvariantCulture, out ushort type) ||
            !suffix.SequenceEqual(type.ToString(CultureInfo.InvariantCulture)) ||
            !(FdoMessageTypes.IsRequest(_protocol, type) ||
              (type == FdoMessageTypes.Error && _protocol == FdoProtocolKind.TransferOwnership2 &&
               _authorization is not null)))
        {
            throw InvalidRequest("The HTTP route has an invalid FDO version or request type.");
        }

        if (request.ContentTypeValues.Count != 1 ||
            !MediaTypeHeaderValue.TryParse(request.ContentTypeValues[0], out MediaTypeHeaderValue? contentType) ||
            !string.Equals(contentType.MediaType, FdoHttpClientSession.CborMediaType, StringComparison.OrdinalIgnoreCase))
        {
            throw InvalidRequest("The HTTP request must have one application/cbor Content-Type.");
        }

        if (!request.Body.CanRead)
        {
            throw InvalidRequest("The HTTP request body stream is not readable.");
        }

        return type;
    }

    private void ValidateAuthorization(IReadOnlyList<string> values)
    {
        if (_authorization is null)
        {
            if (values.Count == 0)
            {
                return;
            }
        }
        else if (values.Count == 1 && values[0] is string supplied &&
            supplied.Length == _authorization.Length &&
            CryptographicOperations.FixedTimeEquals(
                MemoryMarshal.AsBytes(supplied.AsSpan()),
                MemoryMarshal.AsBytes(_authorization.AsSpan())))
        {
            return;
        }

        throw new FdoTransportException(
            FdoTransportFailure.Authorization, "The HTTP request has missing, repeated, or incorrect authorization.");
    }

    private async ValueTask<ReadOnlyMemory<byte>> ReadBodyAsync(
        FdoHttpServerRequest request, CancellationToken cancellationToken)
    {
        long? length = request.ContentLength;
        if (length < 0)
        {
            throw InvalidRequest("The HTTP request has a negative Content-Length.");
        }

        if (length > _maxRequestBytes)
        {
            throw TooLarge();
        }

        int capacity = length is long declared ? (int)declared : _maxRequestBytes + 1;
        byte[] buffer = new byte[capacity];
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await request.Body.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        if (total > _maxRequestBytes)
        {
            throw TooLarge();
        }

        if (total == 0 || (length is long expected && total != expected))
        {
            throw InvalidRequest("The HTTP request body is empty or shorter than Content-Length.");
        }

        return buffer.AsMemory(0, total);
    }

    private void RequireUsable(bool allowCompleted)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_complete && !allowCompleted)
        {
            throw new InvalidOperationException("The HTTP server session has completed.");
        }
    }

    private void DisposeCore()
    {
        if (!_disposed)
        {
            _disposed = true;
            _authorization = null;
            _disposeRole();
        }
    }

    private static FdoTransportException InvalidRequest(string message) =>
        new(FdoTransportFailure.InvalidRequest, message);

    private FdoTransportException TooLarge() =>
        new(FdoTransportFailure.RequestTooLarge,
            string.Create(CultureInfo.InvariantCulture, $"The request body exceeds the {_maxRequestBytes}-byte limit."));

    private readonly record struct ServerMessage(ushort Version, ushort Type, ReadOnlyMemory<byte> Body);
}
