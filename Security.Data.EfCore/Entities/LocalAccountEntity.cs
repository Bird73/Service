namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class LocalAccountEntity
{
    public Guid Id { get; set; }
    public Guid TenantId { get; set; }
    public Guid OurSubject { get; set; }
    public string UsernameOrEmail { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;
    public string PasswordSalt { get; set; } = string.Empty;
    public int PasswordIterations { get; set; }

    public int HashVersion { get; set; }
    public DateTimeOffset? LastPasswordChangeAt { get; set; }

    public int FailedAccessCount { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
