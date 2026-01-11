namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class OidcProviderConfigEntity
{
    public Guid TenantId { get; set; }
    public string Provider { get; set; } = string.Empty;

    public bool Enabled { get; set; }

    public string? Authority { get; set; }
    public string? Issuer { get; set; }

    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;

    public string CallbackPath { get; set; } = "/api/v1/auth/oidc/{provider}/callback";

    // JSON array of strings
    public string? ScopesJson { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
