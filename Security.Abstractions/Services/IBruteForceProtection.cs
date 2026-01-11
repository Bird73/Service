namespace Birdsoft.Security.Abstractions.Services;

public sealed record BruteForceDecision(
    bool Allowed,
    TimeSpan Delay,
    DateTimeOffset? BlockedUntil)
{
    public int? RetryAfterSeconds
        => BlockedUntil is null ? null : Math.Max(0, (int)Math.Ceiling((BlockedUntil.Value - DateTimeOffset.UtcNow).TotalSeconds));
}

/// <summary>
/// 暴力破解防護（tenant + username + ip 維度）。
/// </summary>
public interface IBruteForceProtection
{
    ValueTask<BruteForceDecision> CheckAsync(
        Guid tenantId,
        string username,
        string ip,
        CancellationToken cancellationToken = default);

    ValueTask RecordFailureAsync(
        Guid tenantId,
        string username,
        string ip,
        string reason,
        CancellationToken cancellationToken = default);

    ValueTask RecordSuccessAsync(
        Guid tenantId,
        string username,
        string ip,
        CancellationToken cancellationToken = default);
}
