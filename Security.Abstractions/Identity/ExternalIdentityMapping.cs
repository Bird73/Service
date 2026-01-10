namespace Birdsoft.Security.Abstractions.Identity;

/// <summary>
/// 外部身份對應紀錄。
/// </summary>
public sealed record ExternalIdentityMapping(
    Guid TenantId,
    Guid OurSubject,
    string Provider,
    string Issuer,
    string ProviderSubject,
    DateTimeOffset CreatedAt);
