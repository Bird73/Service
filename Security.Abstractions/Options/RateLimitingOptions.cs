namespace Birdsoft.Security.Abstractions.Options;

/// <summary>
/// Rate limiting 設定（可針對 tenant 與 IP 分別限制）。
/// </summary>
public sealed class RateLimitingOptions
{
    public const string SectionName = "Security:RateLimiting";

    public bool Enabled { get; init; } = true;

    public RateLimitBucketOptions Tenant { get; init; } = new();

    public RateLimitBucketOptions Ip { get; init; } = new();

    /// <summary>
    /// Tenant overrides by tenantId (Guid string).
    /// </summary>
    public Dictionary<string, RateLimitBucketOptions> TenantOverrides { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class RateLimitBucketOptions
{
    public bool Enabled { get; init; } = true;

    /// <summary>每分鐘可用的 token 數</summary>
    public int RequestsPerMinute { get; init; } = 60;

    /// <summary>桶容量（burst）</summary>
    public int Burst { get; init; } = 30;
}
