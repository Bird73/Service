namespace Birdsoft.Security.Abstractions.Audit;

public sealed record AuditReliabilityOptions
{
    public const string SectionName = "Audit";

    public int MaxRetries { get; init; } = 2;
    public int RetryDelayMilliseconds { get; init; } = 50;

    /// <summary>
    /// When true, if audit persistence fails even after retries + fallback, the request should fail.
    /// </summary>
    public bool FailClosed { get; init; } = false;

    public string? FallbackFilePath { get; init; } = "audit-fallback.jsonl";
}
