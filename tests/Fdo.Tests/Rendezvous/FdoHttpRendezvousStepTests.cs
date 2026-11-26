// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Fdo.Rendezvous;
using Fdo.Tests.Transport;
using Fdo.Transport;
using Fdo.Transport.Http;
using static Fdo.Tests.Rendezvous.FdoRendezvousInfoTests;
using AuthenticationFixture = Fdo.Tests.Cryptography.FdoTo2OwnerDeviceAuthenticatorTests.Fixture;

namespace Fdo.Tests.Rendezvous;

[UnsupportedOSPlatform("browser")]
public sealed class FdoHttpRendezvousStepTests
{
    [Test]
    public async Task DeviceStepDeclinesWithoutConnectingThenLooksUpOnTheAuthorizedCandidate()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        await fixture.RegisterAsync();
        using var server = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        FdoRendezvousAttemptPlan plan = DevicePlan(server.Address.Port);
        var authorized = new List<Uri>();
        int created = 0;

        FdoRendezvousStepResult<FdoDeviceRendezvousResult> declined = await FdoHttp.RunDeviceRendezvousStepAsync(
            plan, () => { created++; return fixture.CreateDevice(); }, attempt => Authorize(attempt, authorized),
            8192, timeout.Token);
        await Assert.That(declined.Reported).IsEqualTo(FdoRendezvousAttemptResult.Declined);
        await Assert.That(declined.HasValue).IsFalse();
        await Assert.That(declined.Error).IsNull();
        await Assert.That(created).IsEqualTo(0);
        await Assert.That(server.HasPendingConnection).IsFalse();

        using var binding = FdoHttpServerSession.ForRendezvous(
            fixture.CreateServer(FdoRendezvousProtocol.DeviceLookup), 8192);
        Task<IReadOnlyList<RecordedRequest>> serving = server.ServeSessionAsync(binding, timeout.Token);
        FdoRendezvousStepResult<FdoDeviceRendezvousResult> found = await FdoHttp.RunDeviceRendezvousStepAsync(
            plan, () => { created++; return fixture.CreateDevice(); }, attempt => Authorize(attempt, authorized),
            8192, timeout.Token);
        IReadOnlyList<RecordedRequest> requests = await serving;

        await Assert.That(found.Step.Attempt!.AttemptNumber).IsEqualTo(2);
        await Assert.That(found.Reported).IsEqualTo(FdoRendezvousAttemptResult.Succeeded);
        await Assert.That(found.HasValue).IsTrue();
        await Assert.That(found.Value!.SignedRedirect.Span.SequenceEqual(
            fixture.Store.LastWritten!.SignedRedirect.Span)).IsTrue();
        await Assert.That(created).IsEqualTo(1);
        await Assert.That(requests.Count).IsEqualTo(2);
        await Assert.That(authorized.Count).IsEqualTo(2);
        await Assert.That(authorized[0].AbsoluteUri).IsEqualTo("https://rvserver.local/");
        await Assert.That(authorized[1]).IsEqualTo(server.Address);
        await Assert.That(plan.Next().Kind).IsEqualTo(FdoRendezvousPlanStepKind.Succeeded);
        FdoRendezvousStepResult<FdoDeviceRendezvousResult> after = await FdoHttp.RunDeviceRendezvousStepAsync(
            plan, () => throw new InvalidOperationException(), _ => throw new InvalidOperationException());
        await Assert.That(after.Step.Kind).IsEqualTo(FdoRendezvousPlanStepKind.Succeeded);
        await Assert.That(after.Reported).IsNull();
    }

    [Test]
    public async Task DeviceStepReportsATransportFailureAndOffersTheNextCandidate()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        int closed = ClosedPort();
        FdoRendezvousAttemptPlan plan = DevicePlan(closed, secondPort: closed);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await Decline(plan, fixture);

        FdoRendezvousStepResult<FdoDeviceRendezvousResult> failed = await FdoHttp.RunDeviceRendezvousStepAsync(
            plan, fixture.CreateDevice, _ => true, 8192, timeout.Token);
        FdoRendezvousPlanStep next = plan.Next();

        await Assert.That(failed.Reported).IsEqualTo(FdoRendezvousAttemptResult.Failed);
        await Assert.That(failed.Error).IsNotNull();
        await Assert.That(failed.HasValue).IsFalse();
        await Assert.That(next.Kind).IsEqualTo(FdoRendezvousPlanStepKind.Attempt);
        await Assert.That(next.Attempt!.Candidate.BaseAddress.AbsoluteUri).IsEqualTo($"http://127.0.0.2:{closed}/");
    }

    [Test]
    public async Task DeviceStepStopsOnARedirectWithoutFollowingIt()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using var origin = new LoopbackHttpServer();
        using var target = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        FdoRendezvousAttemptPlan plan = DevicePlan(origin.Address.Port);
        await Decline(plan, fixture);
        Uri location = new(target.Address, "fdo/200/msg/30");
        Task<RecordedRequest> received = origin.RespondOnceAsync(
            $"307 Temporary Redirect\r\nLocation: {location.AbsoluteUri}", [], timeout.Token);

        FdoRendezvousStepResult<FdoDeviceRendezvousResult> redirected = await FdoHttp.RunDeviceRendezvousStepAsync(
            plan, fixture.CreateDevice, _ => true, 8192, timeout.Token);
        await received;

        await Assert.That(redirected.Reported).IsEqualTo(FdoRendezvousAttemptResult.Stop);
        FdoTransportException error = (FdoTransportException)redirected.Error!;
        await Assert.That(error.Failure).IsEqualTo(FdoTransportFailure.RendezvousRedirect);
        await Assert.That(error.RedirectLocation).IsEqualTo(location);
        await Assert.That(target.HasPendingConnection).IsFalse();
        await Assert.That(plan.Next().Kind).IsEqualTo(FdoRendezvousPlanStepKind.Stopped);
    }

    [Test]
    [Arguments("404 Not Found", FdoTransportFailure.UnexpectedStatus, FdoRendezvousAttemptResult.Failed)]
    [Arguments("200 OK", FdoTransportFailure.InvalidResponse, FdoRendezvousAttemptResult.Stop)]
    public async Task DeviceStepAdvancesOnlyPastAnOrdinaryRunFailure(
        string status, FdoTransportFailure failure, FdoRendezvousAttemptResult expected)
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using var server = new LoopbackHttpServer();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        FdoRendezvousAttemptPlan plan = DevicePlan(server.Address.Port, secondPort: ClosedPort());
        await Decline(plan, fixture);
        Task<RecordedRequest> received = server.RespondOnceAsync(status, [], timeout.Token);

        FdoRendezvousStepResult<FdoDeviceRendezvousResult> result = await FdoHttp.RunDeviceRendezvousStepAsync(
            plan, fixture.CreateDevice, _ => true, 8192, timeout.Token);
        await received;

        await Assert.That(result.Reported).IsEqualTo(expected);
        await Assert.That(((FdoTransportException)result.Error!).Failure).IsEqualTo(failure);
        await Assert.That(result.HasValue).IsFalse();
        await Assert.That(server.HasPendingConnection).IsFalse();
        await Assert.That(plan.Next().Kind).IsEqualTo(expected == FdoRendezvousAttemptResult.Failed
            ? FdoRendezvousPlanStepKind.Attempt
            : FdoRendezvousPlanStepKind.Stopped);
    }

    [Test]
    public async Task StepHelpersStopWithoutARequestWhenACallbackRequestsCancellation()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        using var server = new LoopbackHttpServer();
        FdoRendezvousAttemptPlan device = DevicePlan(server.Address.Port);
        await Decline(device, fixture);
        using var duringAuthorization = new CancellationTokenSource();
        int created = 0;

        await CatchAsync<OperationCanceledException>(async () => await FdoHttp.RunDeviceRendezvousStepAsync(
            device,
            () => { created++; return fixture.CreateDevice(); },
            _ => { duringAuthorization.Cancel(); return true; },
            8192,
            duringAuthorization.Token));

        await Assert.That(created).IsEqualTo(0);
        await Assert.That(device.Next().Kind).IsEqualTo(FdoRendezvousPlanStepKind.Stopped);

        FdoRendezvousAttemptPlan owner = OwnerPlan(server.Address.Port);
        await FdoHttp.RunOwnerRendezvousStepAsync(owner, () => fixture.CreateOwner(), _ => false);
        using var duringCreation = new CancellationTokenSource();

        await CatchAsync<OperationCanceledException>(async () => await FdoHttp.RunOwnerRendezvousStepAsync(
            owner,
            () => { duringCreation.Cancel(); return fixture.CreateOwner(); },
            _ => true,
            8192,
            duringCreation.Token));

        await Assert.That(owner.Next().Kind).IsEqualTo(FdoRendezvousPlanStepKind.Stopped);
        await Assert.That(server.HasPendingConnection).IsFalse();
        await Assert.That(fixture.Store.Writes).IsEqualTo(0);
    }

    [Test]
    [Arguments("cancelled")]
    [Arguments("authorize-throws")]
    [Arguments("null-session")]
    [Arguments("started-session")]
    public async Task DeviceStepStopsAndRethrowsWhenNothingCanBeSent(string scenario)
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        FdoRendezvousAttemptPlan plan = DevicePlan(ClosedPort());
        using var cancelled = new CancellationTokenSource();
        if (scenario == "cancelled")
        {
            await cancelled.CancelAsync();
        }

        FdoDeviceRendezvousSession? session = scenario == "null-session" ? null : fixture.CreateDevice();
        if (scenario == "started-session")
        {
            await fixture.RegisterAsync();
            using FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.DeviceLookup);
            await session!.RunAsync(fixture.CreateTransport(server));
        }

        Exception error = await CatchAsync<Exception>(async () => await FdoHttp.RunDeviceRendezvousStepAsync(
            plan,
            () => session!,
            _ => scenario == "authorize-throws" ? throw new InvalidOperationException("policy") : true,
            8192,
            cancelled.Token));

        await Assert.That(scenario == "cancelled"
            ? error is OperationCanceledException
            : error is InvalidOperationException).IsTrue();
        FdoRendezvousPlanStep step = plan.Next();
        await Assert.That(step.Kind).IsEqualTo(FdoRendezvousPlanStepKind.Stopped);
        await Assert.That(step.Attempt!.AttemptNumber).IsEqualTo(1);
    }

    [Test]
    public async Task StepHelpersValidateTheirArgumentsBeforeTakingAStep()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        FdoRendezvousAttemptPlan device = DevicePlan(ClosedPort());
        FdoRendezvousAttemptPlan owner = OwnerPlan(ClosedPort());

        await CatchAsync<ArgumentException>(async () => await FdoHttp.RunOwnerRendezvousStepAsync(
            device, () => fixture.CreateOwner(), _ => true));
        await CatchAsync<ArgumentException>(async () => await FdoHttp.RunDeviceRendezvousStepAsync(
            owner, fixture.CreateDevice, _ => true));
        await CatchAsync<ArgumentOutOfRangeException>(async () => await FdoHttp.RunDeviceRendezvousStepAsync(
            device, fixture.CreateDevice, _ => true, 0));
        await CatchAsync<ArgumentOutOfRangeException>(async () => await FdoHttp.RunOwnerRendezvousStepAsync(
            owner, () => fixture.CreateOwner(), _ => true, 65536));
        await CatchAsync<ArgumentNullException>(async () => await FdoHttp.RunDeviceRendezvousStepAsync(
            device, null!, _ => true));
        await CatchAsync<ArgumentNullException>(async () => await FdoHttp.RunOwnerRendezvousStepAsync(
            owner, () => fixture.CreateOwner(), null!));

        await Assert.That(device.AttemptsOffered).IsEqualTo(0);
        await Assert.That(owner.AttemptsOffered).IsEqualTo(0);
    }

    [Test]
    public async Task OwnerStepReportsAFailedRegistrationAsUncertainUntilReconciled()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        int closed = ClosedPort();
        FdoRendezvousAttemptPlan plan = OwnerPlan(closed);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var authorized = new List<Uri>();

        FdoRendezvousStepResult<uint> declined = await FdoHttp.RunOwnerRendezvousStepAsync(
            plan, () => fixture.CreateOwner(), attempt => Authorize(attempt, authorized), 8192, timeout.Token);
        FdoRendezvousStepResult<uint> uncertain = await FdoHttp.RunOwnerRendezvousStepAsync(
            plan, () => fixture.CreateOwner(), attempt => Authorize(attempt, authorized), 8192, timeout.Token);
        FdoRendezvousStepResult<uint> blocked = await FdoHttp.RunOwnerRendezvousStepAsync(
            plan, () => throw new InvalidOperationException(), _ => throw new InvalidOperationException());

        await Assert.That(declined.Reported).IsEqualTo(FdoRendezvousAttemptResult.Declined);
        await Assert.That(authorized[1].AbsoluteUri).IsEqualTo($"https://127.0.0.2:{closed}/");
        await Assert.That(uncertain.Reported).IsEqualTo(FdoRendezvousAttemptResult.Uncertain);
        await Assert.That(uncertain.Error).IsNotNull();
        await Assert.That(uncertain.HasValue).IsFalse();
        await Assert.That(blocked.Step.Kind).IsEqualTo(FdoRendezvousPlanStepKind.ReconciliationRequired);
        await Assert.That(ReferenceEquals(blocked.Step.Attempt, uncertain.Step.Attempt)).IsTrue();
        await Assert.That(blocked.Reported).IsNull();
        await Assert.That(fixture.Store.Writes).IsEqualTo(0);

        plan.Reconcile(FdoRendezvousAttemptResult.Failed);
        await Assert.That(plan.Next().Kind).IsEqualTo(FdoRendezvousPlanStepKind.Wait);
    }

    [Test]
    public async Task OwnerStepCancelledDuringTheRunIsUncertainAndRethrows()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        var silent = new TcpListener(IPAddress.Parse("127.0.0.2"), 0);
        silent.Start();
        try
        {
            FdoRendezvousAttemptPlan plan = OwnerPlan(((IPEndPoint)silent.LocalEndpoint).Port);
            await FdoHttp.RunOwnerRendezvousStepAsync(plan, () => fixture.CreateOwner(), _ => false);
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));

            await CatchAsync<OperationCanceledException>(async () => await FdoHttp.RunOwnerRendezvousStepAsync(
                plan, () => fixture.CreateOwner(), _ => true, 8192, cancellation.Token));

            await Assert.That(plan.Next().Kind).IsEqualTo(FdoRendezvousPlanStepKind.ReconciliationRequired);
            plan.Reconcile(FdoRendezvousAttemptResult.Stop);
            await Assert.That(plan.Next().Kind).IsEqualTo(FdoRendezvousPlanStepKind.Stopped);
        }
        finally
        {
            silent.Stop();
        }
    }

    [Test]
    public async Task OwnerStepStopsWithoutSendingForAStartedSession()
    {
        using var authentication = new AuthenticationFixture();
        var fixture = new RendezvousFixture(authentication);
        FdoRendezvousAttemptPlan plan = OwnerPlan(ClosedPort());
        FdoOwnerRendezvousSession used = fixture.CreateOwner();
        using (FdoRendezvousServerSession server = fixture.CreateServer(FdoRendezvousProtocol.OwnerRegistration))
        {
            await used.RunAsync(fixture.CreateTransport(server));
        }

        await FdoHttp.RunOwnerRendezvousStepAsync(plan, () => fixture.CreateOwner(), _ => false);

        await CatchAsync<InvalidOperationException>(async () => await FdoHttp.RunOwnerRendezvousStepAsync(
            plan, () => used, _ => true));

        await Assert.That(plan.Next().Kind).IsEqualTo(FdoRendezvousPlanStepKind.Stopped);
        await Assert.That(fixture.Store.Writes).IsEqualTo(1);
    }

    private static FdoRendezvousAttemptPlan DevicePlan(int port, int? secondPort = null)
    {
        var directives = new List<Instruction[]>
        {
            new[] { Dns("rvserver.local") },
            new[] { Ip([127, 0, 0, 1]), Unsigned(12, 1), Unsigned(3, (ulong)port) },
        };
        if (secondPort is int second)
        {
            directives.Add([Ip([127, 0, 0, 2]), Unsigned(12, 1), Unsigned(3, (ulong)second)]);
        }

        return new FdoRendezvousAttemptPlan(
            FdoRendezvousInfo.ParseDirectives(Info([.. directives]), FdoRendezvousProtocol.DeviceLookup),
            new FdoRendezvousAttemptPlanOptions { MaxAttempts = 10, Deadline = DateTimeOffset.MaxValue });
    }

    private static FdoRendezvousAttemptPlan OwnerPlan(int port) => new(
        FdoRendezvousInfo.ParseDirectives(
            Info([Dns("rvserver.local")], [Ip([127, 0, 0, 2]), Unsigned(4, (ulong)port)]),
            FdoRendezvousProtocol.OwnerRegistration),
        new FdoRendezvousAttemptPlanOptions { MaxAttempts = 10, Deadline = DateTimeOffset.MaxValue });

    private static bool Authorize(FdoRendezvousAttempt attempt, List<Uri> authorized)
    {
        authorized.Add(attempt.Candidate.BaseAddress);
        return attempt.Candidate.BaseAddress.HostNameType == UriHostNameType.IPv4;
    }

    private static async Task Decline(FdoRendezvousAttemptPlan plan, RendezvousFixture fixture)
    {
        FdoRendezvousStepResult<FdoDeviceRendezvousResult> declined =
            await FdoHttp.RunDeviceRendezvousStepAsync(plan, fixture.CreateDevice, _ => false);
        await Assert.That(declined.Reported).IsEqualTo(FdoRendezvousAttemptResult.Declined);
    }

    private static int ClosedPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
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
}
