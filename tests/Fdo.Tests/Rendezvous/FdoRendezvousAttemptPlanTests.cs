// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Fdo.Rendezvous;
using static Fdo.Tests.Rendezvous.FdoRendezvousInfoTests;

namespace Fdo.Tests.Rendezvous;

[UnsupportedOSPlatform("browser")]
public sealed class FdoRendezvousAttemptPlanTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task OffersDnsBeforeIpAndDirectivesInOrderThenWaitsTheDefaultPassDelay()
    {
        var clock = new Clock();
        FdoRendezvousAttemptPlan plan = Plan(
            Info([Dns("rvserver.local"), Ip([192, 0, 2, 1])], [Dns("second.example")]), clock);

        FdoRendezvousAttempt first = await ExpectAttemptAsync(plan, "https://rvserver.local/", 1, 1);
        plan.Report(first, FdoRendezvousAttemptResult.Failed);
        FdoRendezvousAttempt second = await ExpectAttemptAsync(plan, "https://192.0.2.1/", 2, 1);
        plan.Report(second, FdoRendezvousAttemptResult.Declined);
        FdoRendezvousAttempt third = await ExpectAttemptAsync(plan, "https://second.example/", 3, 1);
        plan.Report(third, FdoRendezvousAttemptResult.Failed);

        await ExpectWaitAsync(plan, Start.AddSeconds(120));
        await Assert.That(plan.AttemptsOffered).IsEqualTo(3);
        clock.Now = Start.AddSeconds(120).AddTicks(-1);
        await ExpectWaitAsync(plan, Start.AddSeconds(120));
        clock.Now = Start.AddSeconds(120);
        FdoRendezvousAttempt fourth = await ExpectAttemptAsync(plan, "https://rvserver.local/", 4, 2);
        await Assert.That(fourth.Candidate.DirectiveIndex).IsEqualTo(0);
    }

    [Test]
    public async Task AppliesAJitteredExplicitDelayOncePerExhaustedDirective()
    {
        var clock = new Clock();
        FdoRendezvousAttemptPlan plan = Plan(
            Info([Dns("rvserver.local"), Ip([192, 0, 2, 1]), Unsigned(13, 10)], [Dns("b.example"), Unsigned(13, 40)]),
            clock,
            new SequenceRandom(0, 1));

        plan.Report(await ExpectAttemptAsync(plan, "https://rvserver.local/", 1, 1), FdoRendezvousAttemptResult.Failed);
        plan.Report(await ExpectAttemptAsync(plan, "https://192.0.2.1/", 2, 1), FdoRendezvousAttemptResult.Failed);
        await ExpectWaitAsync(plan, Start.AddSeconds(7.5));
        clock.Now = Start.AddSeconds(7.5);
        plan.Report(await ExpectAttemptAsync(plan, "https://b.example/", 3, 1), FdoRendezvousAttemptResult.Failed);

        await ExpectWaitAsync(plan, Start.AddSeconds(57.5));
    }

    [Test]
    [Arguments(null, 120.0)]
    [Arguments(5U, 5.0)]
    [Arguments(0U, 0.0)]
    public async Task TrailingExplicitDelayReplacesTheDefaultPassDelay(uint? delay, double expectedSeconds)
    {
        var clock = new Clock();
        Instruction[] last = delay is uint seconds ? [Dns("b.example"), Unsigned(13, seconds)] : [Dns("b.example")];
        FdoRendezvousAttemptPlan plan = Plan(Info([Dns("rvserver.local")], last), clock);

        plan.Report(await ExpectAttemptAsync(plan, "https://rvserver.local/", 1, 1), FdoRendezvousAttemptResult.Failed);
        plan.Report(await ExpectAttemptAsync(plan, "https://b.example/", 2, 1), FdoRendezvousAttemptResult.Failed);

        if (expectedSeconds == 0)
        {
            await ExpectAttemptAsync(plan, "https://rvserver.local/", 3, 2);
        }
        else
        {
            await ExpectWaitAsync(plan, Start.AddSeconds(expectedSeconds));
        }
    }

    [Test]
    [Arguments(0.0, 90.0)]
    [Arguments(0.25, 105.0)]
    [Arguments(1.0, 150.0)]
    public async Task JittersTheDefaultPassDelayWithinTwentyFivePercent(double sample, double expectedSeconds)
    {
        FdoRendezvousAttemptPlan plan = Plan(Info([Dns("rvserver.local")]), new Clock(), new SequenceRandom(sample));

        plan.Report(await ExpectAttemptAsync(plan, "https://rvserver.local/", 1, 1), FdoRendezvousAttemptResult.Failed);

        await ExpectWaitAsync(plan, Start.AddSeconds(expectedSeconds));
    }

    [Test]
    [Arguments(FdoRendezvousProtocol.DeviceLookup, "https://rvserver.local/")]
    [Arguments(FdoRendezvousProtocol.OwnerRegistration, "https://owner.example/")]
    public async Task OtherRoleDirectivesAddNoDelay(FdoRendezvousProtocol role, string expected)
    {
        var clock = new Clock();
        byte[] encoded = Info(
            [Marker(1), Dns("owner.example"), Unsigned(13, 600)],
            [Marker(0), Dns("rvserver.local"), Unsigned(13, 900)],
            [Marker(1), Dns("owner.example"), Unsigned(13, 700)]);
        FdoRendezvousAttemptPlan plan = Plan(encoded, clock, protocol: role);
        await Assert.That(plan.Directives.Directives.Count).IsEqualTo(role == FdoRendezvousProtocol.DeviceLookup ? 1 : 2);

        plan.Report(await ExpectAttemptAsync(plan, expected, 1, 1), FdoRendezvousAttemptResult.Failed);

        if (role == FdoRendezvousProtocol.DeviceLookup)
        {
            await ExpectWaitAsync(plan, Start.AddSeconds(900));
        }
        else
        {
            await ExpectWaitAsync(plan, Start.AddSeconds(600));
            clock.Now = Start.AddSeconds(600);
            plan.Report(await ExpectAttemptAsync(plan, expected, 2, 1), FdoRendezvousAttemptResult.Failed);
            await ExpectWaitAsync(plan, Start.AddSeconds(1300));
        }
    }

    [Test]
    public async Task ReportsNoApplicableDirectiveWithoutAnAttempt()
    {
        FdoRendezvousAttemptPlan plan = Plan(
            Info([Marker(0), Dns("rvserver.local")]), new Clock(), protocol: FdoRendezvousProtocol.OwnerRegistration);

        FdoRendezvousPlanStep step = plan.Next();

        await Assert.That(step.Kind).IsEqualTo(FdoRendezvousPlanStepKind.Exhausted);
        await Assert.That(step.Exhaustion).IsEqualTo(FdoRendezvousExhaustion.NoApplicableDirective);
        await Assert.That(step.NotBefore).IsNull();
        await Assert.That(step.IsTerminal).IsTrue();
        await Assert.That(plan.AttemptsOffered).IsEqualTo(0);
    }

    [Test]
    [Arguments(0)]
    [Arguments(-1)]
    [Arguments(FdoRendezvousAttemptPlanOptions.MaxAttemptLimit + 1)]
    public async Task RejectsAnAttemptBudgetOutsideItsBounds(int maxAttempts)
    {
        FdoRendezvousDirectiveSet set = FdoRendezvousInfo.ParseDirectives(
            Info([Dns("rvserver.local")]), FdoRendezvousProtocol.DeviceLookup);

        await Assert.That(Throws<ArgumentOutOfRangeException>(() => _ = new FdoRendezvousAttemptPlan(set, new()
        {
            MaxAttempts = maxAttempts,
            Deadline = DateTimeOffset.MaxValue,
        }))).IsTrue();
        await Assert.That(new FdoRendezvousAttemptPlan(set, new()
        {
            MaxAttempts = FdoRendezvousAttemptPlanOptions.MaxAttemptLimit,
            Deadline = DateTimeOffset.MaxValue,
        }).Next().Kind).IsEqualTo(FdoRendezvousPlanStepKind.Attempt);
    }

    [Test]
    public async Task ExhaustsTheAttemptBudgetIncludingDeclinedAttempts()
    {
        FdoRendezvousAttemptPlan plan = Plan(
            Info([Dns("rvserver.local"), Ip([192, 0, 2, 1])]), new Clock(), maxAttempts: 2);

        plan.Report(await ExpectAttemptAsync(plan, "https://rvserver.local/", 1, 1), FdoRendezvousAttemptResult.Declined);
        plan.Report(await ExpectAttemptAsync(plan, "https://192.0.2.1/", 2, 1), FdoRendezvousAttemptResult.Failed);
        FdoRendezvousPlanStep step = plan.Next();

        await Assert.That(step.Kind).IsEqualTo(FdoRendezvousPlanStepKind.Exhausted);
        await Assert.That(step.Exhaustion).IsEqualTo(FdoRendezvousExhaustion.AttemptBudget);
        await Assert.That(step.NotBefore).IsEqualTo(Start.AddSeconds(120));
        await Assert.That(ReferenceEquals(plan.Next(), step)).IsTrue();
        await Assert.That(plan.AttemptsOffered).IsEqualTo(2);
    }

    [Test]
    public async Task ReportsDeadlineExhaustionWithTheUnshortenedNotBefore()
    {
        var clock = new Clock();
        FdoRendezvousAttemptPlan plan = Plan(Info([Dns("rvserver.local")]), clock, deadline: Start.AddSeconds(60));

        plan.Report(await ExpectAttemptAsync(plan, "https://rvserver.local/", 1, 1), FdoRendezvousAttemptResult.Failed);
        FdoRendezvousPlanStep step = plan.Next();

        await Assert.That(step.Kind).IsEqualTo(FdoRendezvousPlanStepKind.Exhausted);
        await Assert.That(step.Exhaustion).IsEqualTo(FdoRendezvousExhaustion.Deadline);
        await Assert.That(step.NotBefore).IsEqualTo(Start.AddSeconds(120));
        clock.Now = Start.AddSeconds(120);
        await Assert.That(ReferenceEquals(plan.Next(), step)).IsTrue();
    }

    [Test]
    public async Task ReportsDeadlineExhaustionBeforeTheFirstAttempt()
    {
        FdoRendezvousAttemptPlan plan = Plan(Info([Dns("rvserver.local")]), new Clock(), deadline: Start);

        FdoRendezvousPlanStep step = plan.Next();

        await Assert.That(step.Exhaustion).IsEqualTo(FdoRendezvousExhaustion.Deadline);
        await Assert.That(step.NotBefore).IsEqualTo(Start);
        await Assert.That(plan.AttemptsOffered).IsEqualTo(0);
    }

    [Test]
    public async Task KeepsTheLongestDelayAndClampsAtTheEndOfTime()
    {
        var clock = new Clock();
        byte[] encoded = Info([Dns("rvserver.local"), Unsigned(13, uint.MaxValue)]);
        FdoRendezvousAttemptPlan plan = Plan(encoded, clock);

        plan.Report(await ExpectAttemptAsync(plan, "https://rvserver.local/", 1, 1), FdoRendezvousAttemptResult.Failed);
        await ExpectWaitAsync(plan, Start.AddSeconds(uint.MaxValue));

        clock.Now = DateTimeOffset.MaxValue.AddDays(-1);
        FdoRendezvousAttemptPlan late = Plan(encoded, clock);
        late.Report(late.Next().Attempt!, FdoRendezvousAttemptResult.Failed);
        FdoRendezvousPlanStep step = late.Next();

        await Assert.That(step.Exhaustion).IsEqualTo(FdoRendezvousExhaustion.Deadline);
        await Assert.That(step.NotBefore).IsEqualTo(DateTimeOffset.MaxValue);
    }

    [Test]
    [Arguments(FdoRendezvousAttemptResult.Succeeded)]
    [Arguments(FdoRendezvousAttemptResult.Failed)]
    [Arguments(FdoRendezvousAttemptResult.Stop)]
    public async Task UncertainAttemptBlocksUntilTheHostReconcilesIt(FdoRendezvousAttemptResult resolved)
    {
        FdoRendezvousAttemptPlan plan = Plan(Info([Dns("rvserver.local"), Ip([192, 0, 2, 1])]), new Clock());
        FdoRendezvousAttempt attempt = await ExpectAttemptAsync(plan, "https://rvserver.local/", 1, 1);

        plan.Report(attempt, FdoRendezvousAttemptResult.Uncertain);
        FdoRendezvousPlanStep blocked = plan.Next();

        await Assert.That(blocked.Kind).IsEqualTo(FdoRendezvousPlanStepKind.ReconciliationRequired);
        await Assert.That(ReferenceEquals(blocked.Attempt, attempt)).IsTrue();
        await Assert.That(blocked.IsTerminal).IsFalse();
        await Assert.That(plan.Next().Kind).IsEqualTo(FdoRendezvousPlanStepKind.ReconciliationRequired);
        await Assert.That(Throws<InvalidOperationException>(() =>
            plan.Report(attempt, FdoRendezvousAttemptResult.Failed))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            plan.Reconcile(FdoRendezvousAttemptResult.Uncertain))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            plan.Reconcile(FdoRendezvousAttemptResult.Declined))).IsTrue();
        await Assert.That(plan.AttemptsOffered).IsEqualTo(1);

        plan.Reconcile(resolved);
        FdoRendezvousPlanStep next = plan.Next();

        switch (resolved)
        {
            case FdoRendezvousAttemptResult.Failed:
                await Assert.That(next.Kind).IsEqualTo(FdoRendezvousPlanStepKind.Attempt);
                await Assert.That(next.Attempt!.Candidate.BaseAddress.AbsoluteUri).IsEqualTo("https://192.0.2.1/");
                break;
            case FdoRendezvousAttemptResult.Succeeded:
                await Assert.That(next.Kind).IsEqualTo(FdoRendezvousPlanStepKind.Succeeded);
                await Assert.That(ReferenceEquals(next.Attempt, attempt)).IsTrue();
                break;
            default:
                await Assert.That(next.Kind).IsEqualTo(FdoRendezvousPlanStepKind.Stopped);
                await Assert.That(ReferenceEquals(next.Attempt, attempt)).IsTrue();
                break;
        }

        await Assert.That(Throws<InvalidOperationException>(() =>
            plan.Reconcile(FdoRendezvousAttemptResult.Failed))).IsTrue();
    }

    [Test]
    [Arguments(FdoRendezvousAttemptResult.Succeeded, FdoRendezvousPlanStepKind.Succeeded)]
    [Arguments(FdoRendezvousAttemptResult.Stop, FdoRendezvousPlanStepKind.Stopped)]
    public async Task TerminalOutcomesRepeatAndRejectFurtherReports(
        FdoRendezvousAttemptResult result, FdoRendezvousPlanStepKind expected)
    {
        FdoRendezvousAttemptPlan plan = Plan(Info([Dns("rvserver.local"), Ip([192, 0, 2, 1])]), new Clock());
        FdoRendezvousAttempt attempt = await ExpectAttemptAsync(plan, "https://rvserver.local/", 1, 1);

        plan.Report(attempt, result);
        FdoRendezvousPlanStep step = plan.Next();

        await Assert.That(step.Kind).IsEqualTo(expected);
        await Assert.That(step.IsTerminal).IsTrue();
        await Assert.That(ReferenceEquals(step.Attempt, attempt)).IsTrue();
        await Assert.That(step.NotBefore).IsNull();
        await Assert.That(ReferenceEquals(plan.Next(), step)).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            plan.Report(attempt, FdoRendezvousAttemptResult.Failed))).IsTrue();
        await Assert.That(plan.AttemptsOffered).IsEqualTo(1);
    }

    [Test]
    public async Task RejectsOutOfOrderAndForeignReports()
    {
        byte[] encoded = Info([Dns("rvserver.local")]);
        FdoRendezvousAttemptPlan plan = Plan(encoded, new Clock());
        FdoRendezvousAttemptPlan other = Plan(encoded, new Clock());
        FdoRendezvousAttempt foreign = other.Next().Attempt!;

        await Assert.That(Throws<InvalidOperationException>(() =>
            plan.Report(foreign, FdoRendezvousAttemptResult.Failed))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            plan.Reconcile(FdoRendezvousAttemptResult.Failed))).IsTrue();
        FdoRendezvousAttempt attempt = plan.Next().Attempt!;
        await Assert.That(Throws<InvalidOperationException>(() => plan.Next())).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            plan.Report(foreign, FdoRendezvousAttemptResult.Failed))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            plan.Report(attempt, (FdoRendezvousAttemptResult)99))).IsTrue();
        await Assert.That(Throws<ArgumentNullException>(() =>
            plan.Report(null!, FdoRendezvousAttemptResult.Failed))).IsTrue();

        plan.Report(attempt, FdoRendezvousAttemptResult.Failed);
        await Assert.That(Throws<InvalidOperationException>(() =>
            plan.Report(attempt, FdoRendezvousAttemptResult.Failed))).IsTrue();
        await Assert.That(plan.Next().Kind).IsEqualTo(FdoRendezvousPlanStepKind.Wait);
    }

    private static FdoRendezvousAttemptPlan Plan(
        byte[] encoded,
        Clock clock,
        Random? random = null,
        FdoRendezvousProtocol protocol = FdoRendezvousProtocol.DeviceLookup,
        int maxAttempts = 100,
        DateTimeOffset? deadline = null) =>
        new(FdoRendezvousInfo.ParseDirectives(encoded, protocol), new FdoRendezvousAttemptPlanOptions
        {
            MaxAttempts = maxAttempts,
            Deadline = deadline ?? DateTimeOffset.MaxValue,
            TimeProvider = clock,
            Random = random ?? new SequenceRandom(0.5),
        });

    private static async Task<FdoRendezvousAttempt> ExpectAttemptAsync(
        FdoRendezvousAttemptPlan plan, string uri, int number, int pass)
    {
        FdoRendezvousPlanStep step = plan.Next();
        await Assert.That(step.Kind).IsEqualTo(FdoRendezvousPlanStepKind.Attempt);
        await Assert.That(step.IsTerminal).IsFalse();
        await Assert.That(step.Attempt!.Candidate.BaseAddress.AbsoluteUri).IsEqualTo(uri);
        await Assert.That(step.Attempt.AttemptNumber).IsEqualTo(number);
        await Assert.That(step.Attempt.Pass).IsEqualTo(pass);
        return step.Attempt;
    }

    private static async Task ExpectWaitAsync(FdoRendezvousAttemptPlan plan, DateTimeOffset notBefore)
    {
        int offered = plan.AttemptsOffered;
        FdoRendezvousPlanStep step = plan.Next();
        await Assert.That(step.Kind).IsEqualTo(FdoRendezvousPlanStepKind.Wait);
        await Assert.That(step.Attempt).IsNull();
        await Assert.That(step.NotBefore).IsEqualTo(notBefore);
        await Assert.That(plan.AttemptsOffered).IsEqualTo(offered);
    }

    private static bool Throws<T>(Action action)
        where T : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (T)
        {
            return true;
        }
    }

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = Start;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class SequenceRandom(params double[] samples) : Random
    {
        private readonly Queue<double> _samples = new(samples);
        private readonly double _last = samples[^1];

        public override double NextDouble() => _samples.Count > 0 ? _samples.Dequeue() : _last;
    }
}
