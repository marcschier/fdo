// Copyright (c) marcschier. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using Fdo.Cryptography;

namespace Fdo.Tests.Cryptography;

internal sealed class OfflineStatusFixture(TimeProvider clock) : IFdoDelegateOfflineStatusSource
{
    public int Calls { get; private set; }
    public IReadOnlyList<FdoDelegateRevocationTarget>? Path { get; private set; }
    public Func<FdoDelegateOfflineStatus[], FdoDelegateOfflineStatus[]>? Transform { get; set; }

    public FdoDelegateOfflineRevocationPolicy Policy => new(this, TimeSpan.FromHours(2), TimeSpan.FromHours(4));

    public IReadOnlyList<FdoDelegateOfflineStatus> GetStatuses(IReadOnlyList<FdoDelegateRevocationTarget> path)
    {
        Calls++;
        Path = path;
        DateTimeOffset now = clock.GetUtcNow();
        FdoDelegateOfflineStatus[] statuses = path.Select(target => new FdoDelegateOfflineStatus(
            target.CertificateSha256, target.IssuerKeySha256, FdoDelegateCertificateStatus.Good,
            now.AddHours(-1), now.AddHours(1))).ToArray();
        return Transform?.Invoke(statuses) ?? statuses;
    }
}
