namespace Birdsoft.Security.Abstractions.Models;

public sealed record ExternalIdentityDto
{
    public required System.Guid TenantId { get; init; }
    public required System.Guid OurSubject { get; init; }
    public required string Provider { get; init; }
    public required string Issuer { get; init; }
    public required string ProviderSub { get; init; }
    public required bool Enabled { get; init; }
    public System.DateTimeOffset? DisabledAt { get; init; }
    public string? DisabledReason { get; init; }
}
