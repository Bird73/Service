namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class PermissionEntity
{
    public Guid PermId { get; set; }

    public string PermKey { get; set; } = string.Empty;
    public string? ProductKey { get; set; }
    public string? Description { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
