namespace Company.Security.Abstractions.Services;

/// <summary>
/// Subject 服務
/// </summary>
public interface ISubjectService
{
    /// <summary>
    /// 遞增 subject 的 token_version（強制該使用者重新登入）
    /// </summary>
    Task<int> BumpSubjectTokenVersionAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 取得 subject 的目前 token_version
    /// </summary>
    Task<int?> GetSubjectTokenVersionAsync(
        Guid tenantId,
        Guid ourSubject,
        CancellationToken cancellationToken = default);
}
