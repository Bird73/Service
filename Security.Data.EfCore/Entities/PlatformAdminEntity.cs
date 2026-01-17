namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class PlatformAdminEntity
{
    public Guid OurSubject { get; set; }

    public string Role { get; set; } = string.Empty;

    public int Status { get; set; }

    public long TokenVersion { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public DateTimeOffset? DisabledAt { get; set; }
}
