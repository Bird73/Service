namespace Birdsoft.Security.Abstractions.Models;

public sealed record AuthEvent
{
    public required Guid Id { get; init; }
    public required DateTimeOffset OccurredAt { get; init; }

    public Guid? TenantId { get; init; }
    public Guid? OurSubject { get; init; }
    public Guid? SessionId { get; init; }

    /// <summary>
    /// App-level correlation identifier (propagated via X-Correlation-Id).
    /// </summary>
    public string? CorrelationId { get; init; }

    /// <summary>
    /// Distributed tracing identifier (W3C traceparent / Activity.TraceId).
    /// </summary>
    public string? TraceId { get; init; }

    public string? Ip { get; init; }
    public string? UserAgent { get; init; }

    public required AuthEventType Type { get; init; }
    public required string Outcome { get; init; }

    /// <summary>
    /// Stable machine-readable code (e.g. invalid_request, mfa_failed, rate_limited).
    /// </summary>
    public string? Code { get; init; }

    /// <summary>
    /// Optional detail string (human readable or free-form).
    /// </summary>
    public string? Detail { get; init; }

    /// <summary>
    /// Optional JSON payload for structured details.
    /// </summary>
    public string? DataJson { get; init; }
}
