namespace Birdsoft.Security.Abstractions;

/// <summary>
/// Access Token 驗證結果（僅定義契約；具體驗證可由 JWT middleware / TokenService 實作）。
/// </summary>
public sealed record AccessTokenValidationResult
{
    public bool Succeeded { get; init; }
    public string? ErrorCode { get; init; }

    public Guid? TenantId { get; init; }
    public Guid? OurSubject { get; init; }
    public string? Jti { get; init; }

    public static AccessTokenValidationResult Success(Guid tenantId, Guid ourSubject, string jti) =>
        new() { Succeeded = true, TenantId = tenantId, OurSubject = ourSubject, Jti = jti };

    public static AccessTokenValidationResult Fail(string errorCode) =>
        new() { Succeeded = false, ErrorCode = errorCode };
}
