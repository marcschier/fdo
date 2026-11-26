// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Transport.Http;

namespace Fdo.Tests.Transport;

[UnsupportedOSPlatform("browser")]
internal sealed class LoopbackHttpServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);

    public LoopbackHttpServer()
    {
        _listener.Start();
        Address = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/");
    }

    public Uri Address { get; }

    public bool HasPendingConnection => _listener.Pending();

    public async Task<RecordedRequest> RespondOnceAsync(
        string statusAndHeaders,
        byte[] responseBody,
        CancellationToken cancellationToken)
    {
        using TcpClient connection = await _listener.AcceptTcpClientAsync(cancellationToken);
        using NetworkStream stream = connection.GetStream();
        RecordedRequest request = await ReadRequestAsync(stream, cancellationToken);
        byte[] responseHeader = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {statusAndHeaders}\r\nContent-Length: {responseBody.Length.ToString(CultureInfo.InvariantCulture)}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(responseHeader, cancellationToken);
        await stream.WriteAsync(responseBody, cancellationToken);
        return request;
    }

    public async Task<IReadOnlyList<RecordedRequest>> ServeSessionAsync(
        FdoHttpServerSession session,
        CancellationToken cancellationToken,
        ushort? dropResponseFor = null,
        Func<FdoHttpServerResponse, ReadOnlyMemory<byte>>? transformResponse = null,
        Action<RecordedRequest>? onRequest = null,
        X509Certificate2? serverCertificate = null)
    {
        var requests = new List<RecordedRequest>();
        while (!session.IsComplete)
        {
            using TcpClient connection = await _listener.AcceptTcpClientAsync(cancellationToken);
            using NetworkStream network = connection.GetStream();
            using var tls = serverCertificate is null ? null : new SslStream(network, leaveInnerStreamOpen: true);
            if (tls is not null)
            {
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCertificate,
                }, cancellationToken);
            }

            Stream stream = tls is null ? network : tls;
            RecordedRequest request = await ReadRequestAsync(stream, cancellationToken, tls is not null);
            requests.Add(request);
            onRequest?.Invoke(request);
            using var body = new MemoryStream(request.Body, writable: false);
            FdoHttpServerResponse response = await session.ProcessAsync(new FdoHttpServerRequest
            {
                Method = request.Method.Method,
                Target = request.Uri!.PathAndQuery,
                AuthorizationValues = request.Authorization is string authorization ? [authorization] : [],
                ContentTypeValues = request.ContentType is string contentType ? [contentType] : [],
                ContentLength = request.Body.Length,
                Body = body,
            }, cancellationToken);
            if (dropResponseFor is ushort type &&
                request.Uri.AbsolutePath.EndsWith("/msg/" + type.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal))
            {
                break;
            }

            byte[] responseBody = (transformResponse?.Invoke(response) ?? response.EncodedBody).ToArray();
            string status = response.StatusCode == 500 ? "500 Internal Server Error" : "200 OK";
            string messageHeaders = responseBody.Length == 0 ? string.Empty :
                $"Message-Type: {response.MessageType.ToString(CultureInfo.InvariantCulture)}\r\n" +
                $"Authorization: {response.Authorization}\r\nContent-Type: application/cbor\r\n";
            byte[] responseHeader = Encoding.ASCII.GetBytes(
                $"HTTP/1.1 {status}\r\n{messageHeaders}" +
                $"Content-Length: {responseBody.Length.ToString(CultureInfo.InvariantCulture)}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(responseHeader, cancellationToken);
            await stream.WriteAsync(responseBody, cancellationToken);
            if (response.IsTerminal)
            {
                break;
            }

            session.ConfirmResponseSent();
        }

        return requests;
    }

    public async Task<bool> AcceptTlsOnceAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        using TcpClient connection = await _listener.AcceptTcpClientAsync(cancellationToken);
        using var stream = new SslStream(connection.GetStream());
        try
        {
            await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
            }, cancellationToken);
            return await stream.ReadAsync(new byte[1], cancellationToken) != 0;
        }
        catch (AuthenticationException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private async Task<RecordedRequest> ReadRequestAsync(
        Stream stream, CancellationToken cancellationToken, bool isHttps = false)
    {
        var header = new List<byte>();
        byte[] one = new byte[1];
        while (true)
        {
            await stream.ReadExactlyAsync(one, cancellationToken);
            header.Add(one[0]);
            if (header.Count > 16384)
            {
                throw new InvalidDataException("Loopback request headers exceed the test limit.");
            }

            if (header.Count >= 4
                && header[^4] == '\r' && header[^3] == '\n'
                && header[^2] == '\r' && header[^1] == '\n')
            {
                break;
            }
        }

        string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        string[] requestLine = lines[0].Split(' ');
        var headers = lines.Skip(1)
            .Select(line => line.Split(':', 2))
            .ToDictionary(parts => parts[0], parts => parts[1].Trim(), StringComparer.OrdinalIgnoreCase);
        int contentLength = headers.TryGetValue("Content-Length", out string? length)
            ? int.Parse(length, CultureInfo.InvariantCulture)
            : 0;
        if (contentLength < 0 || contentLength > ushort.MaxValue || headers.ContainsKey("Transfer-Encoding"))
        {
            throw new InvalidDataException("The loopback fixture requires a bounded Content-Length request.");
        }

        byte[] body = new byte[contentLength];
        await stream.ReadExactlyAsync(body, cancellationToken);
        Uri requestAddress = isHttps ? new UriBuilder(Address) { Scheme = Uri.UriSchemeHttps }.Uri : Address;
        return new RecordedRequest(
            new HttpMethod(requestLine[0]),
            new Uri(requestAddress, requestLine[1]),
            headers.GetValueOrDefault("Authorization"),
            headers.GetValueOrDefault("Content-Type"),
            body);
    }

    public void Dispose() => _listener.Stop();
}
