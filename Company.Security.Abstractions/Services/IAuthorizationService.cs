namespace Company.Security.Abstractions.Services;

/// <summary>
/// 授權檢查服務
/// </summary>
public interface IAuthorizationService
{
    /// <summary>
    /// 檢查指定 subject 是否擁有指定權限
    /// </summary>
    Task<AuthorizationResult> CheckPermissionAsync(
        Guid tenantId,
        Guid ourSubject,
        string permission,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 檢查指定 subject 是否擁有指定角色
    /// </summary>
    Task<bool> IsInRoleAsync(
        Guid tenantId,
        Guid ourSubject,
        string role,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 取得 subject 的所有角色
    /// </summary>
    Task<IReadOnlyList<string>> GetRolesAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 取得 subject 的所有權限（透過角色展開）
    /// </summary>
    Task<IReadOnlyList<string>> GetPermissionsAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);
}
