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
    public string? Detail { get; set; }
}
