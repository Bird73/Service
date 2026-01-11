namespace Birdsoft.Security.Abstractions.Identity;

/// <summary>
/// 外部身份唯一鍵：同一 tenant 下，同一 provider/issuer/provider_sub 對應到唯一 our_subject。
/// </summary>
public sealed record ExternalIdentityKey(
    Guid TenantId,
    string Provider,
    string Issuer,
    string ProviderSubject);
