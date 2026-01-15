namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class SubjectScopeEntity
{
    public Guid TenantId { get; set; }
    public Guid OurSubject { get; set; }

    public string ScopeKey { get; set; } = string.Empty;

    public DateTimeOffset AssignedAt { get; set; }
}
