namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Services;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;

public sealed class InMemoryBruteForceProtection : IBruteForceProtection
{
    private sealed record Key(Guid TenantId, string Username, string Ip);

    private sealed class Entry
    {
        public DateTimeOffset WindowStart { get; set; }
        public int Failures { get; set; }
        public DateTimeOffset? BlockedUntil { get; set; }
    }

    private readonly IOptionsMonitor<BruteForceProtectionOptions> _options;
    private readonly ConcurrentDictionary<Key, Entry> _entries = new();

    public InMemoryBruteForceProtection(IOptionsMonitor<BruteForceProtectionOptions> options)
    {
        _options = options;
    }

    public ValueTask<BruteForceDecision> CheckAsync(Guid tenantId, string username, string ip, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var opts = _options.CurrentValue;
        if (!opts.Enabled)
        {
            return ValueTask.FromResult(new BruteForceDecision(true, TimeSpan.Zero, null));
        }

        var key = new Key(tenantId, Normalize(username), Normalize(ip));
        var now = DateTimeOffset.UtcNow;
        var entry = _entries.GetOrAdd(key, _ => new Entry { WindowStart = now, Failures = 0, BlockedUntil = null });

        lock (entry)
        {
            ResetWindowIfNeeded(entry, now, opts);

            if (entry.BlockedUntil is DateTimeOffset until && until > now)
            {
                return ValueTask.FromResult(new BruteForceDecision(false, TimeSpan.Zero, until));
            }

            // Delay is based on current failures (before this attempt)
            var delay = ComputeDelay(entry.Failures, opts);
            return ValueTask.FromResult(new BruteForceDecision(true, delay, null));
        }
    }

    public ValueTask RecordFailureAsync(Guid tenantId, string username, string ip, string reason, CancellationToken cancellationToken = default)
    {
        _ = reason;
        _ = cancellationToken;

        var opts = _options.CurrentValue;
        if (!opts.Enabled)
        {
            return ValueTask.CompletedTask;
        }

        var key = new Key(tenantId, Normalize(username), Normalize(ip));
        var now = DateTimeOffset.UtcNow;
        var entry = _entries.GetOrAdd(key, _ => new Entry { WindowStart = now, Failures = 0, BlockedUntil = null });

        lock (entry)
        {
            ResetWindowIfNeeded(entry, now, opts);
            entry.Failures++;
            if (entry.Failures >= Math.Max(1, opts.MaxFailures))
            {
                entry.BlockedUntil = now.AddSeconds(Math.Max(1, opts.BlockSeconds));
            }
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask RecordSuccessAsync(Guid tenantId, string username, string ip, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var key = new Key(tenantId, Normalize(username), Normalize(ip));
        _entries.TryRemove(key, out _);
        return ValueTask.CompletedTask;
    }

    private static void ResetWindowIfNeeded(Entry entry, DateTimeOffset now, BruteForceProtectionOptions opts)
    {
        var window = TimeSpan.FromSeconds(Math.Max(1, opts.WindowSeconds));
        if (now - entry.WindowStart > window)
        {
            entry.WindowStart = now;
            entry.Failures = 0;
            entry.BlockedUntil = null;
        }
        else if (entry.BlockedUntil is DateTimeOffset until && until <= now)
        {
            entry.BlockedUntil = null;
        }
    }

    private static TimeSpan ComputeDelay(int failures, BruteForceProtectionOptions opts)
    {
        if (failures < Math.Max(0, opts.DelayAfterFailures))
        {
            return TimeSpan.Zero;
        }

        var steps = failures - opts.DelayAfterFailures + 1;
        var delayMs = Math.Min(Math.Max(0, opts.MaxDelayMs), steps * Math.Max(0, opts.DelayStepMs));
        return delayMs <= 0 ? TimeSpan.Zero : TimeSpan.FromMilliseconds(delayMs);
    }

    private static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value) ? "" : value.Trim().ToLowerInvariant();
}
