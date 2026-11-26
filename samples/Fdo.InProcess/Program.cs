// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Initialization;
using Fdo.Samples;

namespace Fdo.InProcess;

internal static class Program
{
    private static async Task Main()
    {
        using var fixture = new ManufacturingFixture();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using FdoManufacturerInitializeSession manufacturer = fixture.CreateManufacturer();
        FdoDeviceInitializeCredential credential =
            await fixture.InitializeAsync(new InProcessStation(manufacturer), timeout.Token).ConfigureAwait(false);
        OneOwnerVoucher(fixture, manufacturer, credential);
    }

    private static void OneOwnerVoucher(
        ManufacturingFixture fixture,
        FdoManufacturerInitializeSession manufacturer,
        FdoDeviceInitializeCredential credential)
    {
        if (!manufacturer.DoneHandoffConfirmed)
        {
            throw new InvalidOperationException("The manufacturer did not confirm the response handoff.");
        }

        fixture.Transfer(credential);
        Console.WriteLine("FDO initialization complete; transferred voucher has one Owner entry.");
    }

    private sealed class InProcessStation(FdoManufacturerInitializeSession manufacturer) : IFdoDeviceInitializeTransport
    {
        public async ValueTask<FdoDeviceInitializeResponse> SendAsync(
            ushort protocolVersion,
            FdoDeviceInitializeMessageType messageType,
            ReadOnlyMemory<byte> encodedBody,
            CancellationToken cancellationToken)
        {
            FdoDeviceInitializeResponse response = await manufacturer.ProcessAsync(
                protocolVersion, messageType, encodedBody, cancellationToken).ConfigureAwait(false);
            manufacturer.ConfirmResponseSent();
            return response;
        }
    }
}
