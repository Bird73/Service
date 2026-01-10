namespace Birdsoft.Security.Abstractions.Models;

public sealed record RefreshTokenDto
{
    public required System.Guid Id { get; init; }
    public required System.Guid TenantId { get; init; }
    public required System.Guid OurSubject { get; init; }
    public required string TokenHash { get; init; }
    public required System.DateTimeOffset CreatedAt { get; init; }
    public required System.DateTimeOffset ExpiresAt { get; init; }
    public System.DateTimeOffset? RevokedAt { get; init; }
    public System.Guid? ReplacedByRefreshTokenId { get; init; }
    public required int IssuedTenantTokenVersion { get; init; }
    public required int IssuedSubjectTokenVersion { get; init; }

    public bool IsValid(System.DateTimeOffset now) => RevokedAt is null && ExpiresAt > now;
}
