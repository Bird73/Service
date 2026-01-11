namespace Birdsoft.Security.Abstractions.Models;

public sealed record AuthEvent
{
    public required Guid Id { get; init; }
    public required DateTimeOffset OccurredAt { get; init; }

    public Guid? TenantId { get; init; }
    public Guid? OurSubject { get; init; }
    public Guid? SessionId { get; init; }

    public required AuthEventType Type { get; init; }
    public required string Outcome { get; init; }
    public string? Detail { get; init; }
}
