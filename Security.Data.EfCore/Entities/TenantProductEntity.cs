namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class TenantProductEntity
{
    public Guid TenantId { get; set; }
    public string ProductKey { get; set; } = string.Empty;

    public int Status { get; set; }

    public DateTimeOffset StartAt { get; set; }
    public DateTimeOffset? EndAt { get; set; }

    public string? PlanJson { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
