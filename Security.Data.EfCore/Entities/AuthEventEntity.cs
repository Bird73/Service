namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class AuthEventEntity
{
    public Guid Id { get; set; }
    public DateTimeOffset OccurredAt { get; set; }

    public Guid? TenantId { get; set; }
    public Guid? OurSubject { get; set; }
    public Guid? SessionId { get; set; }

    public int Type { get; set; }
    public string Outcome { get; set; } = string.Empty;

    public string? Code { get; set; }
    public string? Detail { get; set; }

    public string? CorrelationId { get; set; }
    public string? TraceId { get; set; }
    public string? Ip { get; set; }
    public string? UserAgent { get; set; }
    public string? DataJson { get; set; }
}
