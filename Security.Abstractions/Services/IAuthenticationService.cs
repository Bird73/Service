namespace Birdsoft.Security.Abstractions.Services;

/// <summary>
/// 帳密驗證服務
/// </summary>
public interface IAuthenticationService
{
    /// <summary>
    /// 以帳號密碼進行驗證
    /// </summary>
    Task<AuthResult> AuthenticateByPasswordAsync(
        Guid tenantId,
        string usernameOrEmail,
        string password,
        CancellationToken cancellationToken = default);
}
