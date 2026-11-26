// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Initialization;
using Fdo.Samples;
using Fdo.Transport.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace Fdo.HttpLoopback;

internal static class Program
{
    private static async Task Main()
    {
        using var fixture = new ManufacturingFixture();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        FdoManufacturerInitializeSession manufacturer = fixture.CreateManufacturer();
        using var binding = FdoHttpServerSession.ForManufacturer(manufacturer, ManufacturingFixture.MaxMessageSize);
        using var gate = new SemaphoreSlim(1, 1);
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
        await using WebApplication app = builder.Build();
        app.Run(context => ProcessAsync(context, binding, gate));
        await app.StartAsync(timeout.Token).ConfigureAwait(false);

        FdoDeviceInitializeCredential credential =
            await fixture.InitializeAsync(new Uri(app.Urls.Single()), timeout.Token).ConfigureAwait(false);
        await gate.WaitAsync(timeout.Token).ConfigureAwait(false);
        gate.Release();

        if (!manufacturer.DoneHandoffConfirmed)
        {
            throw new InvalidOperationException("The HTTP server did not confirm the response handoff.");
        }

        fixture.Transfer(credential);
        Console.WriteLine("FDO HTTP initialization complete; transferred voucher has one Owner entry.");
        await app.StopAsync(timeout.Token).ConfigureAwait(false);
    }

    private static async Task ProcessAsync(
        HttpContext context,
        FdoHttpServerSession binding,
        SemaphoreSlim gate)
    {
        CancellationToken cancellationToken = context.RequestAborted;
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            HttpRequest request = context.Request;
            FdoHttpServerResponse response = await binding.ProcessAsync(new FdoHttpServerRequest
            {
                Method = request.Method,
                Target = request.HttpContext.Features.GetRequiredFeature<IHttpRequestFeature>().RawTarget,
                AuthorizationValues = request.Headers.Authorization.Select(value => value ?? string.Empty).ToArray(),
                ContentTypeValues = request.Headers.ContentType.Select(value => value ?? string.Empty).ToArray(),
                ContentLength = request.ContentLength,
                Body = request.Body
            }, cancellationToken).ConfigureAwait(false);
            HttpResponse http = context.Response;
            http.StatusCode = response.StatusCode;
            ReadOnlyMemory<byte> body = response.EncodedBody;
            http.ContentLength = body.Length;
            if (!body.IsEmpty)
            {
                http.ContentType = "application/cbor";
                http.Headers.Authorization = response.Authorization;
                http.Headers["Message-Type"] = response.MessageType.ToString(CultureInfo.InvariantCulture);
                await http.Body.WriteAsync(body, cancellationToken).ConfigureAwait(false);
            }

            await http.CompleteAsync().ConfigureAwait(false);
            if (!response.IsTerminal)
            {
                binding.ConfirmResponseSent();
            }
        }
        catch
        {
            binding.Dispose();
            throw;
        }
        finally
        {
            gate.Release();
        }
    }
}
