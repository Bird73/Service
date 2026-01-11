namespace Birdsoft.Security.Abstractions.Services;

using Birdsoft.Security.Abstractions.Identity;

/// <summary>
/// 第一次 OIDC 登入時建立 our_subject 與必要 user 記錄。
/// </summary>
public interface IUserProvisioner
{
    /// <summary>
    /// 建立並回傳新的 our_subject。
    /// </summary>
    Task<Guid> ProvisionAsync(
        Guid tenantId,
        ExternalIdentityKey externalIdentity,
        OidcUserInfo? userInfo = null,
        CancellationToken cancellationToken = default);
}
