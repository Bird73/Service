namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class PlatformTokenVersionEntity
{
    /// <summary>
    /// Single-row key. Use "global".
    /// </summary>
    public string Id { get; set; } = "global";

    public long TokenVersion { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
}
