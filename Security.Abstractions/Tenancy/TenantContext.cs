namespace Birdsoft.Security.Abstractions.Tenancy;

public enum TenantResolutionSource
{
    Unknown = 0,
    TokenClaim = 1,
    Header = 2,
    Host = 3,
    Path = 4,
}

public sealed record TenantContext(
    Guid TenantId,
    TenantResolutionSource Source);
