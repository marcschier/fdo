using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Fdo.Transport.Http;

/// <summary>
/// Owns an HTTP client whose transport cannot automatically replay FDO requests
/// to redirect targets.
/// </summary>
[UnsupportedOSPlatform("browser")]
internal sealed class FdoHttpClient : IDisposable
{
    private readonly HttpMessageHandler _handler;
    private readonly HttpClient _client;
    private X509Certificate2? _trustAnchor;

    /// <summary>Creates a client with automatic redirects disabled.</summary>
    public FdoHttpClient()
        : this(new SocketsHttpHandler { AllowAutoRedirect = false })
    {
    }

    /// <summary>Creates the direct transport used by the paired role runners.</summary>
    public static FdoHttpClient CreatePaired(FdoHttpPrivateTrust? privateTrust = null)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
        };
        X509Certificate2? anchor = null;
        bool transferred = false;
        try
        {
            if (privateTrust is not null)
            {
                anchor = privateTrust.OpenAnchor();
                var policy = new X509ChainPolicy
                {
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                    RevocationMode = X509RevocationMode.NoCheck,
                    DisableCertificateDownloads = true,
                };
                policy.CustomTrustStore.Add(anchor);
                policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                handler.SslOptions.CertificateChainPolicy = policy;
            }

            var client = new FdoHttpClient(handler) { _trustAnchor = anchor };
            transferred = true;
            return client;
        }
        finally
        {
            if (!transferred)
            {
                handler.Dispose();
                anchor?.Dispose();
            }
        }
    }

    /// <summary>
    /// Takes ownership of a handler chain ending in a SocketsHttpHandler or
    /// HttpClientHandler with automatic redirects disabled. Delegating handlers
    /// must neither follow redirects themselves nor replay requests to another
    /// address. Opaque terminal handlers and existing HttpClient instances are
    /// not accepted because their redirect policy cannot be inspected.
    /// </summary>
    public FdoHttpClient(HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ValidateHandler(handler);
        _handler = handler;
        _client = new HttpClient(handler);
    }

    /// <summary>Sends without buffering the response body.</summary>
    public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ValidateHandler(_handler);
        return _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
    }

    /// <summary>Disposes the client and its handler chain.</summary>
    public void Dispose()
    {
        _client.Dispose();
        _trustAnchor?.Dispose();
    }

    private static void ValidateHandler(HttpMessageHandler handler)
    {
        var visited = new HashSet<HttpMessageHandler>();
        while (handler is DelegatingHandler delegating)
        {
            if (!visited.Add(handler))
            {
                throw new ArgumentException("The HTTP handler chain contains a cycle.", nameof(handler));
            }

            handler = delegating.InnerHandler
                ?? throw new ArgumentException("The HTTP handler chain has no terminal transport.", nameof(handler));
        }

        bool redirectsDisabled = handler switch
        {
            SocketsHttpHandler sockets => !sockets.AllowAutoRedirect,
            HttpClientHandler client => !client.AllowAutoRedirect,
            _ => throw new ArgumentException(
                "The HTTP handler chain must end in SocketsHttpHandler or HttpClientHandler.",
                nameof(handler)),
        };
        if (!redirectsDisabled)
        {
            throw new ArgumentException("Automatic HTTP redirects must be disabled before sending FDO messages.", nameof(handler));
        }
    }
}
