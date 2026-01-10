namespace Company.Security.Abstractions.Services;

/// <summary>
/// Tenant 服務
/// </summary>
public interface ITenantService
{
    /// <summary>
    /// 遞增 tenant 的 token_version（強制該 tenant 所有使用者重新登入）
    /// </summary>
    Task<int> BumpTenantTokenVersionAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 取得 tenant 的目前 token_version
    /// </summary>
    Task<int?> GetTenantTokenVersionAsync(
        Guid tenantId,
        CancellationToken cancellationToken = default);
}
