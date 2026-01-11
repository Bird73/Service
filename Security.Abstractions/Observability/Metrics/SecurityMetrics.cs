namespace Birdsoft.Security.Abstractions.Observability.Metrics;

using System.Collections.Concurrent;
using System.Globalization;

public static class SecurityMetrics
{
    private static readonly ConcurrentDictionary<string, long> _counters = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, (long Count, double TotalMs)> _latencies = new(StringComparer.OrdinalIgnoreCase);

    public static void Increment(string name, long value = 1)
        => _counters.AddOrUpdate(name, value, (_, old) => old + value);

    public static void ObserveLatencyMs(string name, double ms)
        => _latencies.AddOrUpdate(name, (1, ms), (_, old) => (old.Count + 1, old.TotalMs + ms));

    public static MetricsSnapshot Snapshot()
    {
        var counters = _counters.ToDictionary(k => k.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);
        var lat = _latencies.ToDictionary(k => k.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);
        return new MetricsSnapshot(counters, lat);
    }

    public static string ToPrometheusText(MetricsSnapshot snapshot)
    {
        static string Sanitize(string s)
        {
            Span<char> buf = stackalloc char[s.Length];
            var j = 0;
            foreach (var ch in s)
            {
                buf[j++] = char.IsLetterOrDigit(ch) ? char.ToLowerInvariant(ch) : '_';
            }
            return new string(buf[..j]);
        }

        var lines = new List<string>(snapshot.Counters.Count + snapshot.Latencies.Count * 2);

        foreach (var kv in snapshot.Counters.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
        {
            lines.Add($"{Sanitize(kv.Key)} {kv.Value.ToString(CultureInfo.InvariantCulture)}");
        }

        foreach (var kv in snapshot.Latencies.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
        {
            var baseName = Sanitize(kv.Key);
            lines.Add($"{baseName}_count {kv.Value.Count.ToString(CultureInfo.InvariantCulture)}");
            lines.Add($"{baseName}_sum_ms {kv.Value.TotalMs.ToString(CultureInfo.InvariantCulture)}");
        }

        return string.Join("\n", lines) + "\n";
    }
}

public sealed record MetricsSnapshot(
    IReadOnlyDictionary<string, long> Counters,
    IReadOnlyDictionary<string, (long Count, double TotalMs)> Latencies);
