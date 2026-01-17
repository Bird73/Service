namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class BootstrapKeyEntity
{
    public Guid Id { get; set; }
    public string Label { get; set; } = string.Empty;

    public string KeyHash { get; set; } = string.Empty;
    public string KeyLookup { get; set; } = string.Empty;

    public int Status { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevocationReason { get; set; }
}
