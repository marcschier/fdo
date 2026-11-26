// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Rendezvous;

namespace Fdo.Tests.Rendezvous;

public sealed class FdoAtomicRendezvousStoreTests
{
    [Test]
    public async Task ConcurrentWritersCannotOverwriteTheWinningRevision()
    {
        using var disk = new TestDisk();
        Guid device = Guid.NewGuid();
        FdoRendezvousRegistrationMutation first = disk.Mutation(device);
        FdoRendezvousRegistrationMutation second = disk.Mutation(device);
        IFdoAtomicRendezvousRegistrationStore left = disk.Open();
        IFdoAtomicRendezvousRegistrationStore right = disk.Open();
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<FdoRendezvousMutationResult> one = WriteAfterStartAsync(left, first);
        Task<FdoRendezvousMutationResult> two = WriteAfterStartAsync(right, second);
        start.SetResult();

        FdoRendezvousMutationResult[] outcomes = await Task.WhenAll(one, two);
        await Assert.That(outcomes.Count(r => r == FdoRendezvousMutationResult.Applied)).IsEqualTo(1);
        await Assert.That(outcomes.Count(r => r == FdoRendezvousMutationResult.RevisionConflict)).IsEqualTo(1);
        FdoRendezvousRegistrationMutation winner = outcomes[0] == FdoRendezvousMutationResult.Applied ? first : second;
        FdoRendezvousRegistrationMutation loser = ReferenceEquals(winner, first) ? second : first;
        IFdoAtomicRendezvousRegistrationStore reopened = disk.Open();
        var snapshot = await reopened.ReadAsync(device, default);
        await Assert.That(snapshot.Revision).IsEqualTo((Guid?)Revision(winner));
        await Assert.That(snapshot.Records.Single().Registration.RegistrationId).IsEqualTo(snapshot.Revision!.Value);
        await Assert.That(await reopened.HasCommittedAsync(loser, default)).IsFalse();

        async Task<FdoRendezvousMutationResult> WriteAfterStartAsync(
            IFdoAtomicRendezvousRegistrationStore store, FdoRendezvousRegistrationMutation mutation)
        {
            await start.Task;
            return await store.TryWriteAsync(mutation, default);
        }
    }

    [Test]
    public async Task SharedIpDoesNotAuthorizeReplacementOrAffectOtherSlots()
    {
        using var disk = new TestDisk();
        IFdoAtomicRendezvousRegistrationStore store = disk.Open();
        Guid device = Guid.NewGuid();
        var direct = disk.Mutation(device);
        var first = disk.Mutation(device, Revision(direct), source: "192.0.2.10");
        var other = disk.Mutation(device, Revision(first), source: "2001:db8::1");
        var unrelated = disk.Mutation(Guid.NewGuid());
        foreach (var mutation in new[] { direct, first, other, unrelated })
        {
            await Assert.That(await store.TryWriteAsync(mutation, default)).IsEqualTo(FdoRendezvousMutationResult.Applied);
        }

        var collision = disk.Mutation(device, Revision(other), source: "::ffff:192.0.2.10");
        var wrongGrant = new FdoRendezvousRegistrationMutation(collision.Record, Revision(other), Revision(direct));
        foreach (var attempt in new[] { collision, wrongGrant })
        {
            await Assert.That(await store.TryWriteAsync(attempt, default))
                .IsEqualTo(FdoRendezvousMutationResult.ReplacementNotAuthorized);
        }

        var allowed = new FdoRendezvousRegistrationMutation(collision.Record, Revision(other), Revision(first));
        await Assert.That(await store.TryWriteAsync(allowed, default)).IsEqualTo(FdoRendezvousMutationResult.Applied);
        var staleGrant = new FdoRendezvousRegistrationMutation(
            disk.Mutation(device, source: "192.0.2.10").Record, Revision(other), Revision(first));
        await Assert.That(await store.TryWriteAsync(staleGrant, default))
            .IsEqualTo(FdoRendezvousMutationResult.RevisionConflict);
        var retargeted = new FdoRendezvousRegistrationMutation(staleGrant.Record, Revision(allowed), Revision(first));
        await Assert.That(await store.TryWriteAsync(retargeted, default))
            .IsEqualTo(FdoRendezvousMutationResult.ReplacementNotAuthorized);
        var sameIdentity = disk.Mutation(device, Revision(allowed), collision.Record.AuthenticatedIdentity, "192.0.2.10");
        await Assert.That(await store.TryWriteAsync(sameIdentity, default)).IsEqualTo(FdoRendezvousMutationResult.Applied);

        var snapshot = await disk.Open().ReadAsync(device, default);
        await Assert.That(snapshot.Records.Count).IsEqualTo(3);
        await Assert.That(snapshot.Records.Single(r => r.DelegateSource is null).Registration.RegistrationId)
            .IsEqualTo(Revision(direct));
        await Assert.That(snapshot.Records.Single(r => Equals(r.DelegateSource, IPAddress.Parse("192.0.2.10")))
            .Registration.RegistrationId).IsEqualTo(Revision(sameIdentity));
        await Assert.That(snapshot.Records.Any(r => r.Registration.RegistrationId == Revision(other))).IsTrue();
        await Assert.That((await store.ReadAsync(unrelated.Record.DeviceId, default)).Records.Single()
            .Registration.RegistrationId).IsEqualTo(Revision(unrelated));
    }

    [Test]
    public async Task ExpiryIsIndependentAndNeverResetsTheRevision()
    {
        using var disk = new TestDisk();
        IFdoAtomicRendezvousRegistrationStore store = disk.Open();
        Guid device = Guid.NewGuid();
        var direct = disk.Mutation(device, expiresInSeconds: 30);
        var delegated = disk.Mutation(device, Revision(direct), source: "192.0.2.10", expiresInSeconds: 10);
        await Assert.That(await store.TryWriteAsync(direct, default)).IsEqualTo(FdoRendezvousMutationResult.Applied);
        await Assert.That(await store.TryWriteAsync(delegated, default)).IsEqualTo(FdoRendezvousMutationResult.Applied);
        disk.Now = disk.Now.AddSeconds(9);
        await Assert.That((await store.ReadAsync(device, default)).Records.Count).IsEqualTo(2);
        disk.Now = disk.Now.AddSeconds(1);
        await Assert.That((await store.ReadAsync(device, default)).Records.Single().Registration.RegistrationId)
            .IsEqualTo(Revision(direct));
        disk.Now = disk.Now.AddSeconds(20);
        var empty = await disk.Open().ReadAsync(device, default);
        await Assert.That(empty.Records.Count).IsEqualTo(0);
        await Assert.That(empty.Revision).IsEqualTo((Guid?)Revision(delegated));
        await Assert.That(await store.TryWriteAsync(disk.Mutation(device), default))
            .IsEqualTo(FdoRendezvousMutationResult.RevisionConflict);
        await Assert.That(await store.TryWriteAsync(disk.Mutation(device, empty.Revision, expiresInSeconds: 0), default))
            .IsEqualTo(FdoRendezvousMutationResult.Expired);
        await Assert.That(await store.TryWriteAsync(disk.Mutation(device, empty.Revision, source: "192.0.2.10"), default))
            .IsEqualTo(FdoRendezvousMutationResult.Applied);
    }

    [Test]
    public async Task LostAcknowledgmentCanBeReconciledAfterReplacementWithoutReplaying()
    {
        using var disk = new TestDisk();
        Guid device = Guid.NewGuid();
        var first = disk.Mutation(device, source: "192.0.2.10", blob: 4);
        IFdoAtomicRendezvousRegistrationStore disrupted = disk.Open(loseAcknowledgment: true);
        await Assert.That(await LostAcknowledgmentAsync()).IsTrue();
        IFdoAtomicRendezvousRegistrationStore reopened = disk.Open();
        await Assert.That(await reopened.HasCommittedAsync(first, default)).IsTrue();
        var second = disk.Mutation(device, Revision(first), first.Record.AuthenticatedIdentity, "192.0.2.10", blob: 5);
        await Assert.That(await reopened.TryWriteAsync(second, default)).IsEqualTo(FdoRendezvousMutationResult.Applied);
        var alteredBlob = disk.Mutation(device, identity: first.Record.AuthenticatedIdentity, source: "192.0.2.10",
            blob: 6, mutationId: Revision(first));
        var alteredRevision = new FdoRendezvousRegistrationMutation(first.Record, Revision(second));
        var alteredAuthorization = new FdoRendezvousRegistrationMutation(first.Record, null, Revision(second));
        foreach (var altered in new[] { alteredBlob, alteredRevision, alteredAuthorization })
        {
            await Assert.That(await reopened.HasCommittedAsync(altered, default)).IsFalse();
            await Assert.That(await reopened.TryWriteAsync(altered, default))
                .IsEqualTo(FdoRendezvousMutationResult.MutationIdConflict);
        }
        await Assert.That(await reopened.HasCommittedAsync(first, default)).IsTrue();
        await Assert.That(await reopened.TryWriteAsync(first, default)).IsEqualTo(FdoRendezvousMutationResult.Applied);
        var current = await reopened.ReadAsync(device, default);
        await Assert.That(current.Revision).IsEqualTo((Guid?)Revision(second));
        await Assert.That(current.Records.Single().Registration.SignedRedirect.Span[0]).IsEqualTo((byte)5);

        async Task<bool> LostAcknowledgmentAsync()
        {
            try
            {
                await disrupted.TryWriteAsync(first, default);
                return false;
            }
            catch (IOException e) when (e.Message == LostAcknowledgmentMessage)
            {
                return true;
            }
        }
    }

    private const string LostAcknowledgmentMessage = "Injected failure after the journal replacement.";

    private static Guid Revision(FdoRendezvousRegistrationMutation mutation) => mutation.Record.Registration.RegistrationId;

    internal sealed class TestDisk : IDisposable
    {
        private readonly string _path = Path.Combine(Path.GetTempPath(), $"fdo-rv-{Guid.NewGuid():N}.json");
        private readonly object _gate = new();

        public DateTimeOffset Now { get; set; } = new(2026, 11, 26, 0, 0, 0, TimeSpan.Zero);

        public IFdoAtomicRendezvousRegistrationStore Open(bool loseAcknowledgment = false) =>
            new JournalStore(_path, _gate, () => Now, loseAcknowledgment);

        public FdoRendezvousRegistrationMutation Mutation(
            Guid device, Guid? expected = null, Guid? identity = null, string? source = null,
            int expiresInSeconds = 120, byte blob = 42, Guid? mutationId = null)
        {
            var registration = new FdoRendezvousRegistration(
                mutationId ?? Guid.NewGuid(), device.ToByteArray(bigEndian: true),
                new byte[] { 1 }, new byte[] { 2 }, new byte[] { 3 }, new byte[] { blob }, Now.AddSeconds(expiresInSeconds));
            var record = new FdoRendezvousRegistrationRecord(
                registration, identity ?? Guid.NewGuid(), source is null ? null : IPAddress.Parse(source));
            return new FdoRendezvousRegistrationMutation(record, expected);
        }

        public void Dispose()
        {
            File.Delete(_path);
            File.Delete(_path + ".next");
        }
    }

    /// <summary>
    /// Test adapter: serializes transactions between instances in this process.
    /// Reopen tests file persistence and lost acknowledgment, not power-loss durability.
    /// </summary>
    private sealed class JournalStore(string path, object gate, Func<DateTimeOffset> utcNow, bool loseAcknowledgment)
        : IFdoAtomicRendezvousRegistrationStore
    {
        public ValueTask<FdoRendezvousRegistrationSnapshot> ReadAsync(Guid deviceId, CancellationToken cancellationToken)
        {
            lock (gate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                StoredWrite[] writes = ReadJournal().Where(w => w.DeviceId == deviceId).ToArray();
                return ValueTask.FromResult(new FdoRendezvousRegistrationSnapshot(
                    writes.LastOrDefault()?.Id, LiveRecords(writes, utcNow()).Select(w => w.Rehydrate()).ToArray()));
            }
        }

        public ValueTask<FdoRendezvousMutationResult> TryWriteAsync(
            FdoRendezvousRegistrationMutation mutation, CancellationToken cancellationToken)
        {
            StoredWrite next = StoredWrite.From(mutation);
            lock (gate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                List<StoredWrite> journal = ReadJournal();
                StoredWrite[] writes = journal.Where(w => w.DeviceId == next.DeviceId).ToArray();
                StoredWrite? receipt = Array.Find(writes, w => w.Id == next.Id);
                if (receipt is not null)
                {
                    return ValueTask.FromResult(receipt.Matches(next)
                        ? FdoRendezvousMutationResult.Applied : FdoRendezvousMutationResult.MutationIdConflict);
                }

                if (writes.LastOrDefault()?.Id != next.ExpectedRevision)
                {
                    return ValueTask.FromResult(FdoRendezvousMutationResult.RevisionConflict);
                }

                DateTimeOffset now = utcNow();
                if (next.ExpiresAt <= now)
                {
                    return ValueTask.FromResult(FdoRendezvousMutationResult.Expired);
                }

                StoredWrite? incumbent = LiveRecords(writes, now).FirstOrDefault(w => w.Source == next.Source);
                if (incumbent is not null && incumbent.Identity != next.Identity && incumbent.Id != next.AuthorizedReplacementOf)
                {
                    return ValueTask.FromResult(FdoRendezvousMutationResult.ReplacementNotAuthorized);
                }

                journal.Add(next);
                using (var stream = new FileStream(path + ".next", FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    JsonSerializer.Serialize(stream, journal);
                    stream.Flush(flushToDisk: true);
                }

                File.Move(path + ".next", path, overwrite: true);
                if (loseAcknowledgment)
                {
                    throw new IOException(LostAcknowledgmentMessage);
                }

                return ValueTask.FromResult(FdoRendezvousMutationResult.Applied);
            }
        }

        public ValueTask<bool> HasCommittedAsync(
            FdoRendezvousRegistrationMutation mutation, CancellationToken cancellationToken)
        {
            StoredWrite next = StoredWrite.From(mutation);
            lock (gate)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ValueTask.FromResult(ReadJournal().Any(w => w.DeviceId == next.DeviceId && w.Id == next.Id && w.Matches(next)));
            }
        }

        private List<StoredWrite> ReadJournal()
        {
            try
            {
                using FileStream stream = File.OpenRead(path);
                return JsonSerializer.Deserialize<List<StoredWrite>>(stream) ?? throw new InvalidDataException("Null journal.");
            }
            catch (FileNotFoundException)
            {
                return [];
            }
        }

        private static IEnumerable<StoredWrite> LiveRecords(StoredWrite[] writes, DateTimeOffset now) =>
            writes.GroupBy(w => w.Source).Select(slot => slot.Last()).Where(w => w.ExpiresAt > now);
    }

    private sealed record StoredWrite(
        Guid DeviceId, Guid Id, Guid Identity, string? Source, Guid? ExpectedRevision, Guid? AuthorizedReplacementOf,
        DateTimeOffset ExpiresAt, byte[] Manufacturer, byte[] Owner, byte[] Chain, byte[] Blob)
    {
        public static StoredWrite From(FdoRendezvousRegistrationMutation mutation)
        {
            FdoRendezvousRegistrationRecord record = mutation.Record;
            FdoRendezvousRegistration registration = record.Registration;
            return new StoredWrite(record.DeviceId, registration.RegistrationId, record.AuthenticatedIdentity,
                record.DelegateSource?.ToString(), mutation.ExpectedRevision, mutation.AuthorizedReplacementOf,
                registration.ExpiresAt, registration.EncodedManufacturerKey.ToArray(), registration.EncodedOwnerKey.ToArray(),
                registration.EncodedDeviceCertificateChain.ToArray(), registration.SignedRedirect.ToArray());
        }

        public bool Matches(StoredWrite other) =>
            DeviceId == other.DeviceId && Id == other.Id && Identity == other.Identity && Source == other.Source
            && ExpectedRevision == other.ExpectedRevision && AuthorizedReplacementOf == other.AuthorizedReplacementOf
            && ExpiresAt.EqualsExact(other.ExpiresAt)
            && Manufacturer.AsSpan().SequenceEqual(other.Manufacturer) && Owner.AsSpan().SequenceEqual(other.Owner)
            && Chain.AsSpan().SequenceEqual(other.Chain) && Blob.AsSpan().SequenceEqual(other.Blob);

        public FdoRendezvousRegistrationRecord Rehydrate() => new(
            new FdoRendezvousRegistration(Id, DeviceId.ToByteArray(bigEndian: true), Manufacturer, Owner, Chain, Blob, ExpiresAt),
            Identity, Source is null ? null : IPAddress.Parse(Source));
    }
}
