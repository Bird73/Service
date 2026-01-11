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

    public DateTimeOffset CreatedAt { get; set; }
}
