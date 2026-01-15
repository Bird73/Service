namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class RolePermissionEntity
{
    public Guid TenantId { get; set; }
    public Guid RoleId { get; set; }
    public Guid PermId { get; set; }

    public DateTimeOffset AssignedAt { get; set; }
}
