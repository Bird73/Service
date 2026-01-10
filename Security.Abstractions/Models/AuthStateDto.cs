namespace Birdsoft.Security.Abstractions.Models;

public sealed record AuthStateDto
{
    public required string State { get; init; }
    public required System.Guid TenantId { get; init; }
    public required System.DateTimeOffset CreatedAt { get; init; }
    public required System.DateTimeOffset ExpiresAt { get; init; }
    public System.DateTimeOffset? UsedAt { get; init; }

    public string? CodeVerifier { get; init; }
    public string? Nonce { get; init; }
}
