namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class RoleEntity
{
    public Guid TenantId { get; set; }
    public Guid RoleId { get; set; }

    public string RoleName { get; set; } = string.Empty;
    public string? Description { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
