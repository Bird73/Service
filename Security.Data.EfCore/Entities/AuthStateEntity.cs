namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class AuthStateEntity
{
    public string State { get; set; } = string.Empty;
    public Guid TenantId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? UsedAt { get; set; }

    public string? Provider { get; set; }

    public string? CodeVerifier { get; set; }
    public string? Nonce { get; set; }
}
