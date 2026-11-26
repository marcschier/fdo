// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Tests.Transport;

internal sealed record RecordedRequest(
    HttpMethod Method,
    Uri? Uri,
    string? Authorization,
    string? ContentType,
    byte[] Body);

/// <summary>
/// Records each request and answers it from a queue of response factories.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class ScriptedHandler : DelegatingHandler
{
    private readonly Queue<Func<HttpRequestMessage, Task<HttpResponseMessage>>> _responses = new();

    public ScriptedHandler(HttpMessageHandler? terminalHandler = null)
        : base(terminalHandler ?? new SocketsHttpHandler { AllowAutoRedirect = false })
    {
    }

    public List<RecordedRequest> Requests { get; } = [];

    public ScriptedHandler Respond(Func<HttpRequestMessage, HttpResponseMessage> factory)
    {
        _responses.Enqueue(request => Task.FromResult(factory(request)));
        return this;
    }

    public ScriptedHandler EnqueueResponse(Func<HttpRequestMessage, Task<HttpResponseMessage>> factory)
    {
        _responses.Enqueue(factory);
        return this;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        byte[] body = request.Content is null
            ? []
            : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        string? authorization = request.Headers.TryGetValues("Authorization", out IEnumerable<string>? values)
            ? values.Single()
            : null;
        Requests.Add(new RecordedRequest(
            request.Method,
            request.RequestUri,
            authorization,
            request.Content?.Headers.ContentType?.MediaType,
            body));

        HttpResponseMessage response = await _responses.Dequeue()(request);
        response.RequestMessage ??= request;
        return response;
    }

    public static HttpResponseMessage Message(ushort messageType, byte[] body, string? token)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
        response.Headers.TryAddWithoutValidation("Message-Type", messageType.ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (token is not null)
        {
            response.Headers.TryAddWithoutValidation("Authorization", token);
        }

        return response;
    }
}

/// <summary>
/// Content that does not report its length, like a chunked response.
/// </summary>
/// <param name="data">The response bytes to write.</param>
internal sealed class UnknownLengthContent(byte[] data) : HttpContent
{
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        stream.WriteAsync(data.AsMemory()).AsTask();

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }
}
