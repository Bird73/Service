namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class AccessTokenDenylistEntity
{
    public Guid TenantId { get; set; }
    public string Jti { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
