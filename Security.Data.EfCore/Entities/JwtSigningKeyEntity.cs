namespace Birdsoft.Security.Data.EfCore.Entities;

public sealed class JwtSigningKeyEntity
{
    public string Kid { get; set; } = string.Empty;
    public string Algorithm { get; set; } = "RS256";
    public int Status { get; set; }

    // RSA
    public string? PrivateKeyPem { get; set; }
    public string? PublicKeyPem { get; set; }

    // HS*
    public string? SymmetricKey { get; set; }

    public string? Reason { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? DisabledAt { get; set; }
}
