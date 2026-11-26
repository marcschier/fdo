// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Serialization;
using Fdo.ServiceInfo;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.Tests.ServiceInfo;

public sealed class FdoDeviceServiceInfoProcessorTests
{
    private static readonly byte[] True = [0xF5];
    private static readonly byte[] False = [0xF4];

    [Test]
    public async Task ProcessesEntriesAndProducesResponsesInReceivedOrder()
    {
        var calls = new List<string>();
        var first = new RecordingModule("first", calls)
        {
            OnReceive = (name, value, _) => name == "read"
                ? Result(new Entry("first:reply", value))
                : Result(),
        };
        var second = new RecordingModule("second", calls)
        {
            OnReceive = (name, value, _) => name == "read"
                ? Result(new Entry("second:reply", value))
                : Result(),
        };
        var processor = new FdoDeviceServiceInfoProcessor([first, second]);
        ReadOnlyMemory<byte> input = Encode(
            new Entry("first:active", True),
            new Entry("first:read", new byte[] { 0x01 }),
            new Entry("second:active", True),
            new Entry("first:read", new byte[] { 0x02 }),
            new Entry("second:read", new byte[] { 0x03 }));

        IReadOnlyList<Entry> response = Decode(await processor.ProcessAsync(input));

        await Assert.That(calls.SequenceEqual(
            [
                "first:active=F5",
                "first:read=01",
                "second:active=F5",
                "first:read=02",
                "second:read=03",
            ])).IsTrue();
        await Assert.That(response.Select(entry => entry.Key).SequenceEqual(
            ["first:active", "first:reply", "second:active", "first:reply", "second:reply"])).IsTrue();
        await Assert.That(response.Select(entry => Convert.ToHexString(entry.EncodedValue.Span)).SequenceEqual(
            ["F5", "01", "F5", "02", "03"])).IsTrue();
        await Assert.That(processor.IsFaulted).IsFalse();
    }

    [Test]
    public async Task UnknownModulesReceiveFalseWithoutBlockingOtherEntries()
    {
        var calls = new List<string>();
        var module = new RecordingModule("known", calls);
        var processor = new FdoDeviceServiceInfoProcessor([module]);

        IReadOnlyList<Entry> response = Decode(await processor.ProcessAsync(Encode(
            new Entry("missing:active", True),
            new Entry("missing:configure", new byte[] { 0x01 }),
            new Entry("known:active", True),
            new Entry("known:configure", new byte[] { 0x02 }))));

        await Assert.That(response.Any(entry =>
            entry.Key == "missing:active" && entry.EncodedValue.Span.SequenceEqual(False))).IsTrue();
        await Assert.That(response.Any(entry =>
            entry.Key == "known:active" && entry.EncodedValue.Span.SequenceEqual(True))).IsTrue();
        await Assert.That(calls.SequenceEqual(["known:active=F5", "known:configure=02"])).IsTrue();
        await Assert.That(processor.IsFaulted).IsFalse();
    }

    [Test]
    public async Task ActivationPersistsAcrossMessagesAndDisablingPreventsLaterUse()
    {
        var calls = new List<string>();
        var module = new RecordingModule("m", calls);
        var processor = new FdoDeviceServiceInfoProcessor([module]);

        IReadOnlyList<Entry> first = Decode(await processor.ProcessAsync(Encode(
            new Entry("m:active", True),
            new Entry("m:active", True),
            new Entry("m:work", new byte[] { 0x01 }))));
        IReadOnlyList<Entry> second = Decode(await processor.ProcessAsync(Encode(
            new Entry("m:active", False))));

        await Assert.That(first.Count).IsEqualTo(1);
        await Assert.That(first[0].Key).IsEqualTo("m:active");
        await Assert.That(second.Count).IsEqualTo(0);
        await Assert.That(calls.SequenceEqual(["m:active=F5", "m:work=01", "m:active=F4"])).IsTrue();
        await CatchAsync<CborContentException>(() => processor.ProcessAsync(Encode(
            new Entry("m:work", new byte[] { 0x01 }))));
        await Assert.That(processor.IsFaulted).IsTrue();
        await CatchAsync<InvalidOperationException>(() => processor.ProcessAsync(Encode()));
    }

    [Test]
    [Arguments("m:active", "00")]
    [Arguments("m:active", "F4")]
    [Arguments("m:work", "01")]
    [Arguments(":work", "01")]
    [Arguments("m:", "01")]
    [Arguments("missingcolon", "01")]
    public async Task InvalidActivationOrKeyFaultsTheProcessor(string key, string value)
    {
        var calls = new List<string>();
        var processor = new FdoDeviceServiceInfoProcessor([new RecordingModule("m", calls)]);

        await CatchAsync<CborContentException>(() => processor.ProcessAsync(
            Encode(new Entry(key, Convert.FromHexString(value)))));

        await Assert.That(calls.Count).IsEqualTo(0);
        await Assert.That(processor.IsFaulted).IsTrue();
    }

    [Test]
    public async Task ModuleFailureStopsTheMessageAndPreventsAnotherExchange()
    {
        var calls = new List<string>();
        var module = new RecordingModule("m", calls)
        {
            OnReceive = (name, _, _) => name == "work"
                ? throw new InvalidOperationException("module failed")
                : Result(),
        };
        var processor = new FdoDeviceServiceInfoProcessor([module]);

        InvalidOperationException failure = await CatchAsync<InvalidOperationException>(() => processor.ProcessAsync(Encode(
            new Entry("m:active", True),
            new Entry("m:work", new byte[] { 0x01 }),
            new Entry("m:later", new byte[] { 0x02 }))));

        await Assert.That(failure.Message).IsEqualTo("module failed");
        await Assert.That(calls.SequenceEqual(["m:active=F5", "m:work=01"])).IsTrue();
        await Assert.That(processor.IsFaulted).IsTrue();
        await CatchAsync<InvalidOperationException>(() => processor.ProcessAsync(Encode()));
    }

    [Test]
    public async Task ConcurrentCallIsRejectedWithoutFaultingTheRunningExchange()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var module = new RecordingModule("m", [])
        {
            OnReceive = (_, _, _) => WaitForReleaseAsync(started, release),
        };
        var processor = new FdoDeviceServiceInfoProcessor([module]);

        Task<ReadOnlyMemory<byte>> first = processor.ProcessAsync(Encode(new Entry("m:active", True)));
        await started.Task;
        await CatchAsync<InvalidOperationException>(() => processor.ProcessAsync(Encode()));
        release.SetResult();
        IReadOnlyList<Entry> response = Decode(await first);

        await Assert.That(response.Count).IsEqualTo(1);
        await Assert.That(response[0].Key).IsEqualTo("m:active");
        await Assert.That(processor.IsFaulted).IsFalse();
    }

    [Test]
    public async Task CancellationDuringModuleExecutionFaultsTheExchange()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var module = new RecordingModule("m", [])
        {
            OnReceive = (_, _, token) => WaitForCancellationAsync(started, token),
        };
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        using var cancellation = new CancellationTokenSource();

        Task<ReadOnlyMemory<byte>> exchange = processor.ProcessAsync(
            Encode(new Entry("m:active", True)), cancellation.Token);
        await started.Task;
        await cancellation.CancelAsync();
        await CatchAsync<OperationCanceledException>(() => exchange);

        await Assert.That(processor.IsFaulted).IsTrue();
        await CatchAsync<InvalidOperationException>(() => processor.ProcessAsync(Encode()));
    }

    [Test]
    public async Task AggregateResponseHonorsTheExactByteLimit()
    {
        static RecordingModule CreateModule() => new("m", [])
        {
            OnReceive = (name, _, _) => name == "go"
                ? Result(new Entry("m:result", new byte[] { 0x01 }))
                : Result(),
        };

        ReadOnlyMemory<byte> input = Encode(
            new Entry("m:active", True),
            new Entry("m:go", new byte[] { 0x01 }));
        var atLimit = new FdoDeviceServiceInfoProcessor([CreateModule()], maxEncodedBytes: 25);
        var belowLimit = new FdoDeviceServiceInfoProcessor([CreateModule()], maxEncodedBytes: 24);

        ReadOnlyMemory<byte> response = await atLimit.ProcessAsync(input);
        await CatchAsync<CborContentException>(() => belowLimit.ProcessAsync(input));

        await Assert.That(response.Length).IsEqualTo(25);
        await Assert.That(Decode(response).Select(entry => entry.Key).SequenceEqual(
            ["m:active", "m:result"])).IsTrue();
        await Assert.That(belowLimit.IsFaulted).IsTrue();
    }

    [Test]
    public async Task InvalidModuleOutputFaultsTheExchange()
    {
        var module = new RecordingModule("m", [])
        {
            OnReceive = (_, _, _) => Result(new Entry("m:active", True)),
        };
        var processor = new FdoDeviceServiceInfoProcessor([module]);

        await CatchAsync<CborContentException>(() => processor.ProcessAsync(
            Encode(new Entry("m:active", True))));

        await Assert.That(processor.IsFaulted).IsTrue();
    }

    private static ReadOnlyMemory<byte> Encode(params Entry[] entries) => new FdoServiceInfoCodec().Encode(entries);

    private static IReadOnlyList<Entry> Decode(ReadOnlyMemory<byte> encoded) => new FdoServiceInfoCodec().Decode(encoded);

    private static ValueTask<IReadOnlyList<Entry>> Result(params Entry[] entries) =>
        ValueTask.FromResult<IReadOnlyList<Entry>>(entries);

    private static async ValueTask<IReadOnlyList<Entry>> WaitForReleaseAsync(
        TaskCompletionSource started,
        TaskCompletionSource release)
    {
        started.SetResult();
        await release.Task;
        return Array.Empty<Entry>();
    }

    private static async ValueTask<IReadOnlyList<Entry>> WaitForCancellationAsync(
        TaskCompletionSource started,
        CancellationToken cancellationToken)
    {
        started.SetResult();
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        return Array.Empty<Entry>();
    }

    private static async Task<TException> CatchAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private sealed class RecordingModule(string name, List<string> calls) : IFdoDeviceServiceInfoModule
    {
        public string Name { get; } = name;

        public Func<string, ReadOnlyMemory<byte>, CancellationToken, ValueTask<IReadOnlyList<Entry>>>? OnReceive { get; init; }

        public ValueTask<IReadOnlyList<Entry>> ReceiveAsync(
            string messageName,
            ReadOnlyMemory<byte> encodedValue,
            CancellationToken cancellationToken)
        {
            calls.Add($"{Name}:{messageName}={Convert.ToHexString(encodedValue.Span)}");
            return OnReceive?.Invoke(messageName, encodedValue, cancellationToken) ?? Result();
        }
    }
}
