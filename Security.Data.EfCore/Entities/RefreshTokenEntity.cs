namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class RefreshTokenEntity
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid OurSubject { get; set; }
    public Guid SessionId { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public string TokenLookup { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public Guid? ReplacedByRefreshTokenId { get; set; }
    public string? RevocationReason { get; set; }

    public int IssuedTenantTokenVersion { get; set; }
    public int IssuedSubjectTokenVersion { get; set; }
}
