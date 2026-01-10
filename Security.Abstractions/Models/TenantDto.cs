namespace Birdsoft.Security.Abstractions.Models;

public sealed record TenantDto
{
    public required System.Guid TenantId { get; init; }
    public required string Name { get; init; }
    public required int TokenVersion { get; init; }
    public required System.DateTimeOffset CreatedAt { get; init; }
}
