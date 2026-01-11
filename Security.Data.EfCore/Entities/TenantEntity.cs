namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class TenantEntity
{
    public Guid TenantId { get; set; }
    public string Name { get; set; } = string.Empty;
    public int TokenVersion { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
