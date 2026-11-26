// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Enrollment;
using Fdo.Initialization;
using Fdo.Rendezvous;
using Fdo.Serialization;

namespace Fdo.Transport.Http;

/// <summary>
/// The HTTP client side of one FDO sub-protocol run (DI, TO0, TO1 or TO2).
/// </summary>
/// <remarks>
/// <para>
/// The numeric path <c>{base}/fdo/{protver}/msg/{msgtype}</c> is a provisional
/// FDO 2.0 interpretation. It is not retried with another version or route.
/// The generic sender rejects requests requiring TO2 protection and all
/// FDO 2.0 Error sends before transmission. Only the paired TO2 Device
/// transport sends an FDO 2.0 Error: it posts one Error sealed on the live
/// channel to <c>msg/255</c> with the active token and requires an empty
/// HTTP 200. A protected Owner Error arrives with HTTP 500 and ends the run.
/// The server allocates an
/// authorization token on the first response; the session sends it in the
/// <c>Authorization</c> header of every later request and rejects a changed
/// token. A token never crosses sessions, so each sub-protocol run needs a
/// new instance.
/// </para>
/// <para>
/// The session handles one exchange at a time. After an FDO Error is sent or
/// received, or a TO1 redirect is received, the session is terminated and
/// rejects further sends. The paired role transport also terminates after
/// any failed exchange; a generic send leaves its state unchanged on a
/// network failure.
/// </para>
/// <para>
/// The caller owns <see cref="FdoHttpClient"/>, which disables automatic
/// redirects before sending. Injected delegating handlers must not implement
/// their own redirect or cross-address replay logic. Checking the final URI
/// detects a contract violation; it cannot prevent a replay that already occurred.
/// </para>
/// </remarks>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoHttpClientSession
{
    /// <summary>
    /// The content type of every FDO request (§4.3).
    /// </summary>
    public const string CborMediaType = "application/cbor";

    /// <summary>
    /// The response header that carries the numeric message type (§4.3).
    /// </summary>
    public const string MessageTypeHeader = "Message-Type";

    /// <summary>
    /// The header that carries the session token (§4.3).
    /// </summary>
    public const string AuthorizationHeader = "Authorization";

    /// <summary>
    /// The default response limit: the largest value that the uint16
    /// <c>maxDeviceMessageSize</c> field of TO2.HelloDeviceProbe can announce.
    /// </summary>
    public const int DefaultMaxResponseBytes = ushort.MaxValue;

    private const int InitialReadBufferBytes = 4096;

    private readonly FdoHttpClient _httpClient;
    private readonly FdoCborCodec _codec;
    private readonly Uri _baseAddress;
    private string? _authorization;
    private int _busy;
    private volatile bool _terminated;

    /// <summary>
    /// Creates a session for one sub-protocol run.
    /// </summary>
    /// <param name="httpClient">The caller-owned client with redirects disabled.</param>
    /// <param name="baseAddress">
    /// The absolute http or https address of the server, without query or
    /// fragment. A path, if present, prefixes the FDO path.
    /// </param>
    /// <param name="protocol">The sub-protocol this session carries.</param>
    /// <param name="version">The protocol version used in the provisional numeric path.</param>
    /// <param name="maxResponseBytes">The largest accepted response body.</param>
    public FdoHttpClientSession(
        FdoHttpClient httpClient,
        Uri baseAddress,
        FdoProtocolKind protocol,
        FdoProtocolVersion version,
        int maxResponseBytes = DefaultMaxResponseBytes)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(baseAddress);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxResponseBytes);

        if (!baseAddress.IsAbsoluteUri || !IsHttpScheme(baseAddress))
        {
            throw new ArgumentException("The base address must be an absolute http or https URI.", nameof(baseAddress));
        }

        if (baseAddress.Query.Length != 0 || baseAddress.Fragment.Length != 0)
        {
            throw new ArgumentException("The base address must not have a query or fragment.", nameof(baseAddress));
        }

        if (!Enum.IsDefined(protocol))
        {
            throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "Unknown FDO sub-protocol.");
        }

        if (version.Value == 0)
        {
            throw new ArgumentException("The protocol version must be initialized.", nameof(version));
        }

        _httpClient = httpClient;
        _codec = new FdoCborCodec(maxEncodedBytes: maxResponseBytes);
        _baseAddress = baseAddress;
        Protocol = protocol;
        Version = version;
        MaxResponseBytes = maxResponseBytes;
    }

    /// <summary>
    /// The sub-protocol this session carries.
    /// </summary>
    public FdoProtocolKind Protocol { get; }

    /// <summary>
    /// The protocol version used in the provisional numeric path.
    /// </summary>
    public FdoProtocolVersion Version { get; }

    /// <summary>
    /// The largest accepted response body in bytes.
    /// </summary>
    public int MaxResponseBytes { get; }

    /// <summary>
    /// Whether the server has allocated a token for this session.
    /// </summary>
    public bool HasAuthorizationToken => _authorization is not null;

    /// <summary>
    /// Whether the session has ended through an Error message or a redirect.
    /// </summary>
    public bool IsTerminated => _terminated;

    internal IFdoDeviceTransport CreateDeviceTransport()
    {
        if (Protocol != FdoProtocolKind.TransferOwnership2)
        {
            throw new InvalidOperationException("The HTTP session is not a TO2 session.");
        }

        return new DeviceTransport(this);
    }

    internal IFdoDeviceInitializeTransport CreateInitializeTransport()
    {
        if (Protocol != FdoProtocolKind.DeviceInitialize)
        {
            throw new InvalidOperationException("The HTTP session is not a DI session.");
        }

        return new InitializeTransport(this);
    }

    internal IFdoRendezvousTransport CreateRendezvousTransport()
    {
        if (Protocol is not (FdoProtocolKind.TransferOwnership0 or FdoProtocolKind.TransferOwnership1))
        {
            throw new InvalidOperationException("The HTTP session is not a rendezvous session.");
        }

        return new RendezvousTransport(this);
    }

    /// <summary>
    /// Constructs the provisional numeric URI for <paramref name="messageType"/>.
    /// Constructing a URI does not authorize an outbound request.
    /// </summary>
    public Uri GetMessageUri(ushort messageType)
    {
        var builder = new UriBuilder(_baseAddress)
        {
            Path = string.Concat(
                _baseAddress.AbsolutePath.TrimEnd('/'),
                "/fdo/",
                Version.Value.ToString(CultureInfo.InvariantCulture),
                "/msg/",
                messageType.ToString(CultureInfo.InvariantCulture)),
            Query = string.Empty,
            Fragment = string.Empty,
        };
        return builder.Uri;
    }

    /// <summary>
    /// Sends one protocol message and validates the server's answer.
    /// </summary>
    /// <param name="messageType">A request message type of this session's sub-protocol.</param>
    /// <param name="body">The CBOR message body.</param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>The validated response.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="messageType"/> is not a request of this sub-protocol.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The request requires unavailable TO2 session protection.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// The session is terminated or another exchange is in progress.
    /// </exception>
    /// <exception cref="FdoTransportException">The exchange failed.</exception>
    public Task<FdoHttpResponse> SendAsync(
        ushort messageType,
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken = default) =>
        SendMessageAsync(messageType, body, paired: false, cancellationToken);

    private Task<FdoHttpResponse> SendPairedAsync(
        ushort messageType,
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken) =>
        SendMessageAsync(messageType, body, paired: true, cancellationToken);

    private async Task<FdoHttpResponse> SendMessageAsync(
        ushort messageType,
        ReadOnlyMemory<byte> body,
        bool paired,
        CancellationToken cancellationToken)
    {
        if (!FdoMessageTypes.IsRequest(Protocol, messageType))
        {
            throw new ArgumentOutOfRangeException(
                nameof(messageType),
                messageType,
                "The message type is not a request of this FDO sub-protocol.");
        }

        if (!paired && FdoMessageTypes.RequiresUnavailableTo2Protection(Protocol, messageType))
        {
            throw new NotSupportedException($"FDO message type {messageType} requires unavailable TO2 session protection.");
        }

        if (body.IsEmpty)
        {
            throw new ArgumentException("An FDO message body must not be empty.", nameof(body));
        }

        if (paired && (Version != FdoProtocolVersion.V20 || body.Length > ushort.MaxValue))
        {
            throw new ArgumentException("A paired FDO 2.0 body must fit in uint16.", nameof(body));
        }

        body = ValidateOutboundBody(body, nameof(body));
        EnterExchange();
        bool completed = false;
        try
        {
            Uri requestUri = GetMessageUri(messageType);
            using HttpRequestMessage request = CreateRequest(requestUri, body, paired);
            using HttpResponseMessage response = await SendCoreAsync(request, cancellationToken).ConfigureAwait(false);
            EnsureNotRedirectedAutomatically(response, requestUri);
            FdoHttpResponse result = await ReadResponseAsync(
                messageType, requestUri, response, paired, cancellationToken).ConfigureAwait(false);
            if (paired && result.RedirectLocation is Uri redirectLocation)
            {
                throw new FdoTransportException(response.StatusCode, redirectLocation);
            }

            if (paired && result.Kind != FdoHttpResponseKind.Message)
            {
                if (result.Kind == FdoHttpResponseKind.Error &&
                    Protocol == FdoProtocolKind.TransferOwnership2 && _authorization is not null)
                {
                    // The Device role authenticates this Error on its live
                    // channel. The HTTP session has ended either way.
                    return result;
                }

                throw new FdoTransportException(
                    FdoTransportFailure.UnexpectedStatus,
                    "The paired HTTP role does not process FDO Error messages.",
                    response.StatusCode);
            }

            completed = true;
            return result;
        }
        catch (IOException ex) when (paired)
        {
            throw new FdoTransportException(
                FdoTransportFailure.Network, "The FDO HTTP response could not be read.", innerException: ex);
        }
        catch (OperationCanceledException ex) when (paired && !cancellationToken.IsCancellationRequested)
        {
            throw new FdoTransportException(
                FdoTransportFailure.Network, "The FDO HTTP response timed out.", innerException: ex);
        }
        finally
        {
            if (paired && !completed)
            {
                _terminated = true;
            }

            ExitExchange();
        }
    }

    /// <summary>
    /// Reports a problem found in a server response by sending an FDO Error
    /// message (§5.1.1) and terminates the session. The server answers with
    /// an empty body, which is not read.
    /// </summary>
    /// <param name="errorMessage">The CBOR ErrorMessage body.</param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <exception cref="NotSupportedException">FDO 2.0 Error sending is not implemented.</exception>
    /// <exception cref="InvalidOperationException">
    /// The session is terminated or another exchange is in progress. §5.1.1
    /// forbids an Error in answer to an Error.
    /// </exception>
    /// <exception cref="FdoTransportException">The server rejected the request.</exception>
    public async Task SendErrorAsync(ReadOnlyMemory<byte> errorMessage, CancellationToken cancellationToken = default)
    {
        if (Version == FdoProtocolVersion.V20)
        {
            throw new NotSupportedException("FDO 2.0 Error handling and phase-specific protection are not implemented.");
        }

        if (errorMessage.IsEmpty)
        {
            throw new ArgumentException("An FDO Error message body must not be empty.", nameof(errorMessage));
        }

        errorMessage = ValidateOutboundBody(errorMessage, nameof(errorMessage));
        EnterExchange();
        try
        {
            Uri requestUri = GetMessageUri(FdoMessageTypes.Error);
            using HttpRequestMessage request = CreateRequest(requestUri, errorMessage);
            using HttpResponseMessage response = await SendCoreAsync(request, cancellationToken).ConfigureAwait(false);
            EnsureNotRedirectedAutomatically(response, requestUri);
            if (!response.IsSuccessStatusCode)
            {
                throw new FdoTransportException(
                    FdoTransportFailure.UnexpectedStatus,
                    "The server rejected the FDO Error message.",
                    response.StatusCode);
            }
        }
        finally
        {
            _terminated = true;
            ExitExchange();
        }
    }

    private static bool IsHttpScheme(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps;

    private async Task SendPairedErrorAsync(ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        // Sends one sealed TO2 Error in the active session and ends it. The
        // Owner accepts it with an empty HTTP 200; nothing is retried.
        if (Protocol != FdoProtocolKind.TransferOwnership2 || Version != FdoProtocolVersion.V20)
        {
            throw new InvalidOperationException("Only a paired FDO 2.0 TO2 session sends a protected Error.");
        }

        if (body.IsEmpty || body.Length > ushort.MaxValue)
        {
            throw new ArgumentException("A paired FDO 2.0 Error body must be nonempty and fit in uint16.", nameof(body));
        }

        EnterExchange();
        try
        {
            if (_authorization is null)
            {
                throw new InvalidOperationException("A protected FDO Error requires an active session.");
            }

            Uri requestUri = GetMessageUri(FdoMessageTypes.Error);
            using HttpRequestMessage request = CreateRequest(requestUri, body, paired: true);
            using HttpResponseMessage response = await SendCoreAsync(request, cancellationToken).ConfigureAwait(false);
            EnsureNotRedirectedAutomatically(response, requestUri);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new FdoTransportException(
                    FdoTransportFailure.UnexpectedStatus,
                    "The server rejected the FDO Error message.",
                    response.StatusCode);
            }

            if (!(await ReadBodyAsync(response, cancellationToken).ConfigureAwait(false)).IsEmpty)
            {
                throw new FdoTransportException(
                    FdoTransportFailure.InvalidResponse,
                    "The server answered an FDO Error with a body.",
                    response.StatusCode);
            }
        }
        finally
        {
            _terminated = true;
            ExitExchange();
        }
    }

    private static ReadOnlyMemory<byte> ValidateOutboundBody(ReadOnlyMemory<byte> body, string parameterName)
    {
        try
        {
            return new FdoCborCodec(maxEncodedBytes: body.Length).ValidateAndCopy(body);
        }
        catch (CborContentException ex)
        {
            throw new ArgumentException("The message body must be length-first deterministic CBOR within the nesting and item limits.", parameterName, ex);
        }
    }

    private void EnterExchange()
    {
        if (Interlocked.Exchange(ref _busy, 1) != 0)
        {
            throw new InvalidOperationException("An FDO exchange is already in progress on this session.");
        }

        if (_terminated)
        {
            Volatile.Write(ref _busy, 0);
            throw new InvalidOperationException("The FDO session has terminated.");
        }
    }

    private void ExitExchange() => Volatile.Write(ref _busy, 0);

    private HttpRequestMessage CreateRequest(Uri requestUri, ReadOnlyMemory<byte> body, bool paired = false)
    {
        HttpContent content = paired ? new SingleUseContent(body) : new ReadOnlyMemoryContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(CborMediaType);

        var request = new HttpRequestMessage(HttpMethod.Post, requestUri) { Content = content };
        if (paired)
        {
            // HTTP/1.1 with content and no Expect/Continue avoids the runtime's
            // retry path for an EOF after an ambiguously delivered request.
            request.Version = HttpVersion.Version11;
            request.VersionPolicy = HttpVersionPolicy.RequestVersionExact;
            request.Headers.ExpectContinue = false;
        }

        if (_authorization is not null)
        {
            request.Headers.TryAddWithoutValidation(AuthorizationHeader, _authorization);
        }

        return request;
    }

    private async Task<HttpResponseMessage> SendCoreAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            return await _httpClient
                .SendAsync(request, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new FdoTransportException(FdoTransportFailure.Network, "The FDO HTTP request failed.", innerException: ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new FdoTransportException(FdoTransportFailure.Network, "The FDO HTTP request timed out.", innerException: ex);
        }
    }

    private static void EnsureNotRedirectedAutomatically(HttpResponseMessage response, Uri requestUri)
    {
        Uri? finalUri = response.RequestMessage?.RequestUri;
        if (finalUri is not null && finalUri != requestUri)
        {
            throw new FdoTransportException(
                FdoTransportFailure.InvalidResponse,
                "The HTTP handler followed a redirect. FDO requires automatic redirects to be disabled.",
                response.StatusCode);
        }
    }

    private async Task<FdoHttpResponse> ReadResponseAsync(
        ushort requestType,
        Uri requestUri,
        HttpResponseMessage response,
        bool paired,
        CancellationToken cancellationToken)
    {
        switch (response.StatusCode)
        {
            case HttpStatusCode.OK:
                return await ReadMessageAsync(response, paired, cancellationToken).ConfigureAwait(false);

            case HttpStatusCode.InternalServerError:
                return await ReadErrorAsync(response, cancellationToken).ConfigureAwait(false);

            case HttpStatusCode.Found:
            case HttpStatusCode.TemporaryRedirect:
                return ReadRedirect(requestType, requestUri, response);

            default:
                throw new FdoTransportException(
                    FdoTransportFailure.UnexpectedStatus,
                    "The server returned an HTTP status that the FDO binding does not permit.",
                    response.StatusCode);
        }
    }

    private async Task<FdoHttpResponse> ReadMessageAsync(
        HttpResponseMessage response, bool paired, CancellationToken cancellationToken)
    {
        if (paired &&
            (!response.Content.Headers.TryGetValues("Content-Type", out IEnumerable<string>? contentTypes) ||
             contentTypes.Count() != 1 ||
             !string.Equals(response.Content.Headers.ContentType?.MediaType, CborMediaType, StringComparison.OrdinalIgnoreCase)))
        {
            throw new FdoTransportException(
                FdoTransportFailure.InvalidResponse,
                "The paired response must have one application/cbor Content-Type.",
                response.StatusCode);
        }

        // Adopt the token before validating the message, so that an Error
        // reporting a bad first response reaches the server's protocol context.
        string? token = ReadAuthorization(response);
        if (_authorization is null)
        {
            _authorization = token ?? throw new FdoTransportException(
                FdoTransportFailure.Authorization,
                "The server did not allocate an authorization token on the first response.",
                response.StatusCode);
        }
        else if (token is not null && !string.Equals(token, _authorization, StringComparison.Ordinal))
        {
            throw new FdoTransportException(
                FdoTransportFailure.Authorization,
                "The server changed the authorization token within the session.",
                response.StatusCode);
        }

        ushort? messageType = ReadMessageType(response);
        if (messageType is not ushort type)
        {
            throw new FdoTransportException(
                FdoTransportFailure.InvalidResponse,
                "The response has no Message-Type header.",
                response.StatusCode);
        }

        if (!FdoMessageTypes.IsResponse(Protocol, type))
        {
            throw new FdoTransportException(
                FdoTransportFailure.InvalidResponse,
                "The response message type is not a response of this FDO sub-protocol.",
                response.StatusCode);
        }

        ReadOnlyMemory<byte> body = await ReadBodyAsync(response, cancellationToken).ConfigureAwait(false);
        if (body.IsEmpty)
        {
            throw new FdoTransportException(
                FdoTransportFailure.InvalidResponse,
                "The response has an empty message body.",
                response.StatusCode);
        }

        return FdoHttpResponse.Message(CreateStreamMessage(type, body, response.StatusCode));
    }

    private async Task<FdoHttpResponse> ReadErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        // An Error terminates the run whether or not its body is usable.
        _terminated = true;

        ushort? messageType = ReadMessageType(response);
        if (messageType is ushort type && type != FdoMessageTypes.Error)
        {
            throw new FdoTransportException(
                FdoTransportFailure.InvalidResponse,
                "An HTTP 500 response carried a message type other than Error.",
                response.StatusCode);
        }

        ReadOnlyMemory<byte> body = await ReadBodyAsync(response, cancellationToken).ConfigureAwait(false);
        if (body.IsEmpty)
        {
            throw new FdoTransportException(
                FdoTransportFailure.UnexpectedStatus,
                "The server returned HTTP 500 without an FDO Error message.",
                response.StatusCode);
        }

        return FdoHttpResponse.Error(CreateStreamMessage(FdoMessageTypes.Error, body, response.StatusCode));
    }

    private FdoCborCodec.StreamMessage CreateStreamMessage(ushort messageType, ReadOnlyMemory<byte> body, HttpStatusCode status)
    {
        try
        {
            return _codec.CreateStreamMessage(messageType, Version, _authorization, body);
        }
        catch (CborContentException ex)
        {
            throw new FdoTransportException(
                FdoTransportFailure.InvalidResponse,
                "The response body is not bounded length-first deterministic CBOR.",
                status,
                ex);
        }
    }

    private FdoHttpResponse ReadRedirect(ushort requestType, Uri requestUri, HttpResponseMessage response)
    {
        if (Protocol != FdoProtocolKind.TransferOwnership1
            || requestType != FdoMessageTypes.TO1HelloRV
            || _authorization is not null)
        {
            throw new FdoTransportException(
                FdoTransportFailure.UnexpectedStatus,
                "FDO permits an HTTP redirect only in answer to TO1.HelloRV.",
                response.StatusCode);
        }

        if (!response.Headers.TryGetValues("Location", out IEnumerable<string>? values)
            || values.Count() != 1
            || response.Headers.Location is not Uri location)
        {
            throw new FdoTransportException(
                FdoTransportFailure.InvalidResponse,
                "The redirect must have one valid Location header.",
                response.StatusCode);
        }

        if (!location.IsAbsoluteUri)
        {
            location = new Uri(requestUri, location);
        }

        if (!IsHttpScheme(location))
        {
            throw new FdoTransportException(
                FdoTransportFailure.InvalidResponse,
                "The redirect target is not an http or https URI.",
                response.StatusCode);
        }

        _terminated = true;
        return FdoHttpResponse.Redirect(location);
    }

    private static ushort? ReadMessageType(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(MessageTypeHeader, out IEnumerable<string>? values))
        {
            return null;
        }

        string[] all = values.ToArray();
        if (all.Length != 1
            || !ushort.TryParse(all[0].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out ushort type))
        {
            throw new FdoTransportException(
                FdoTransportFailure.InvalidResponse,
                "The Message-Type header is not a single unsigned 16-bit decimal number.",
                response.StatusCode);
        }

        return type;
    }

    private static string? ReadAuthorization(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues(AuthorizationHeader, out IEnumerable<string>? values))
        {
            return null;
        }

        string[] all = values.ToArray();
        if (all.Length != 1 || string.IsNullOrWhiteSpace(all[0]))
        {
            throw new FdoTransportException(
                FdoTransportFailure.Authorization,
                "The response carries an empty or repeated Authorization header.",
                response.StatusCode);
        }

        return all[0];
    }

    private async Task<ReadOnlyMemory<byte>> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        long? declaredLength = response.Content.Headers.ContentLength;
        if (declaredLength > MaxResponseBytes)
        {
            throw TooLarge(response);
        }

        Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            int initial = declaredLength is long length
                ? (int)length
                : Math.Min(MaxResponseBytes, InitialReadBufferBytes);
            byte[] buffer = new byte[initial];
            int total = 0;

            while (true)
            {
                if (total == buffer.Length)
                {
                    if (total >= MaxResponseBytes)
                    {
                        byte[] probe = new byte[1];
                        if (await stream.ReadAsync(probe, cancellationToken).ConfigureAwait(false) != 0)
                        {
                            throw TooLarge(response);
                        }

                        break;
                    }

                    int grown = (int)Math.Min(MaxResponseBytes, Math.Max(buffer.Length * 2L, InitialReadBufferBytes));
                    Array.Resize(ref buffer, grown);
                }

                int read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            return buffer.AsMemory(0, total);
        }
    }

    private FdoTransportException TooLarge(HttpResponseMessage response) => new(
        FdoTransportFailure.ResponseTooLarge,
        string.Create(CultureInfo.InvariantCulture, $"The response body exceeds the {MaxResponseBytes}-byte limit."),
        response.StatusCode);

    private abstract class PairedTransport(FdoHttpClientSession session) : IFdoHttpPeer
    {
        public Uri BaseAddress => session._baseAddress;

        protected async ValueTask<FdoHttpResponse> SendPairedAsync(
            ushort version, ushort messageType, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
        {
            if (version != FdoProtocolVersion.V20.Value)
            {
                throw new InvalidOperationException("The paired HTTP transport requires FDO version 200.");
            }

            return await session.SendPairedAsync(messageType, body, cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class DeviceTransport(FdoHttpClientSession session)
        : PairedTransport(session), IFdoDeviceTransport, IFdoDeviceErrorTransport
    {
        private readonly FdoHttpClientSession _session = session;

        public async ValueTask<FdoOwnerResponse> SendAsync(
            ushort protocolVersion,
            FdoTo2MessageType messageType,
            ReadOnlyMemory<byte> encodedBody,
            CancellationToken cancellationToken)
        {
            FdoHttpResponse response = await SendPairedAsync(
                protocolVersion, (ushort)messageType, encodedBody, cancellationToken).ConfigureAwait(false);
            return new FdoOwnerResponse(200, (FdoTo2MessageType)response.MessageType, response.Body);
        }

        public async ValueTask SendErrorAsync(
            ushort protocolVersion,
            ReadOnlyMemory<byte> encodedBody,
            CancellationToken cancellationToken)
        {
            if (protocolVersion != FdoProtocolVersion.V20.Value)
            {
                throw new InvalidOperationException("The paired HTTP transport requires FDO version 200.");
            }

            await _session.SendPairedErrorAsync(encodedBody, cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class InitializeTransport(FdoHttpClientSession session)
        : PairedTransport(session), IFdoDeviceInitializeTransport
    {
        public async ValueTask<FdoDeviceInitializeResponse> SendAsync(
            ushort protocolVersion,
            FdoDeviceInitializeMessageType messageType,
            ReadOnlyMemory<byte> encodedBody,
            CancellationToken cancellationToken)
        {
            FdoHttpResponse response = await SendPairedAsync(
                protocolVersion, (ushort)messageType, encodedBody, cancellationToken).ConfigureAwait(false);
            return new FdoDeviceInitializeResponse(
                200, (FdoDeviceInitializeMessageType)response.MessageType, response.Body);
        }
    }

    private sealed class RendezvousTransport(FdoHttpClientSession session)
        : PairedTransport(session), IFdoRendezvousTransport
    {
        public async ValueTask<FdoRendezvousResponse> SendAsync(
            ushort protocolVersion,
            FdoRendezvousMessageType messageType,
            ReadOnlyMemory<byte> encodedBody,
            CancellationToken cancellationToken)
        {
            FdoHttpResponse response = await SendPairedAsync(
                protocolVersion, (ushort)messageType, encodedBody, cancellationToken).ConfigureAwait(false);
            return new FdoRendezvousResponse(200, (FdoRendezvousMessageType)response.MessageType, response.Body);
        }
    }

    private sealed class SingleUseContent(ReadOnlyMemory<byte> body) : HttpContent
    {
        private int _serialized;

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(
            Stream stream, TransportContext? context, CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _serialized, 1) != 0)
            {
                throw new InvalidOperationException("An FDO request body cannot be sent twice.");
            }

            await stream.WriteAsync(body, cancellationToken).ConfigureAwait(false);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = body.Length;
            return true;
        }
    }
}
