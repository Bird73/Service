namespace Company.Security.Abstractions.Repositories;

using Company.Security.Abstractions.Models;

/// <summary>
/// 本地帳號 Repository
/// </summary>
public interface ILocalAccountRepository
{
    Task<LocalAccountProfileDto?> FindByUsernameAsync(
        Guid tenantId,
        string usernameOrEmail,
        CancellationToken cancellationToken = default);

    Task<LocalAccountProfileDto> CreateAsync(
        Guid tenantId,
        Guid ourSubject,
        string usernameOrEmail,
        string password,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 驗證帳密；成功則回傳 our_subject，失敗回傳 null。
    ///
    /// 注意：密碼雜湊/pepper/演算法細節不應成為跨層合約；由 repository/資料存取層封裝。
    /// </summary>
    Task<Guid?> VerifyPasswordAsync(
        Guid tenantId,
        string usernameOrEmail,
        string password,
        CancellationToken cancellationToken = default);
}
