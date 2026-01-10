namespace Birdsoft.Security.Abstractions.Stores;

/// <summary>
/// 授權資料存取（最小集合）：角色與權限/範圍。
/// </summary>
public interface IAuthorizationDataStore
{
    ValueTask<IReadOnlyList<string>> GetRolesAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);

    ValueTask<IReadOnlyList<string>> GetScopesAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);
}
