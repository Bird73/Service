namespace Company.Security.Abstractions.Services;

/// <summary>
/// 外部身份對應服務（ExternalIdentity mapping）
/// </summary>
public interface IExternalIdentityService
{
    /// <summary>
    /// 查詢或建立 subject（首次 OIDC 登入時自動註冊）
    /// </summary>
    /// <returns>對應的 our_subject</returns>
    Task<Guid> FindOrCreateSubjectAsync(
        Guid tenantId,
        string provider,
        string issuer,
        string providerSub,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 僅查詢（不建立）
    /// </summary>
    Task<Guid?> FindSubjectAsync(
        Guid tenantId,
        string provider,
        string issuer,
        string providerSub,
        CancellationToken cancellationToken = default);
}
