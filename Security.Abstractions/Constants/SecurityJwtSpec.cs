namespace Birdsoft.Security.Abstractions.Constants;

using System.Collections.ObjectModel;

/// <summary>
/// JWT 規格契約（claim 要求與約定）。
/// </summary>
public static class SecurityJwtSpec
{
    /// <summary>
    /// 必要 claim（Access Token 最少必須具備）。
    /// </summary>
    public static readonly IReadOnlyList<string> RequiredClaimNames = new ReadOnlyCollection<string>(
        [
            "iss",
            "aud",
            "exp",
            "iat",
            "nbf",
            SecurityClaimTypes.Jti,
            "sub",
            SecurityClaimTypes.TenantId,
        ]);

    /// <summary>
    /// 角色 claim 名稱（預設使用 <see cref="SecurityClaimTypes.Roles"/>）。
    /// </summary>
    public const string RolesClaim = SecurityClaimTypes.Roles;

    /// <summary>
    /// 權限/範圍 claim 名稱（預設使用 <see cref="SecurityClaimTypes.Scopes"/>）。
    /// </summary>
    public const string ScopesClaim = SecurityClaimTypes.Scopes;

    /// <summary>
    /// Access Token 的 subject 規則：<c>sub</c> 必須等於 <c>our_subject</c>。
    /// </summary>
    public const string SubjectSemantic = "sub == our_subject";

    /// <summary>
    /// Issuer 規則：必須完全匹配設定的 Issuer。
    /// </summary>
    public const string IssuerRule = "iss must equal configured JwtOptions.Issuer";

    /// <summary>
    /// Audience 規則：必須包含設定的 Audience。
    /// </summary>
    public const string AudienceRule = "aud must contain configured JwtOptions.Audience";
}
