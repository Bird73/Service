namespace Birdsoft.Security.Data.EfCore.Entities;

/// <summary>
/// Tracks tenant-level authorization model versioning without forcing JWT invalidation.
/// </summary>
public sealed class AuthzTenantVersionEntity
{
    public Guid TenantId { get; set; }
    public long ModelVersion { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
