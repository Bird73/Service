namespace Birdsoft.Security.Abstractions.Constants;

/// <summary>
/// JWT 中的自訂 claim 名稱常數
/// </summary>
public static class SecurityClaimTypes
{
    /// <summary>租戶 ID</summary>
    public const string TenantId = "tenant_id";

    /// <summary>本系統 Subject（our_subject）</summary>
    public const string OurSubject = "our_subject";

    /// <summary>角色（建議為多值 claim）</summary>
    public const string Roles = "roles";

    /// <summary>OAuth 慣例角色 claim（相容用）</summary>
    public const string Role = "role";

    /// <summary>權限/範圍（建議為 space-delimited scope 或多值 claim）</summary>
    public const string Scopes = "scopes";

    /// <summary>OAuth 慣例 scope claim（space-delimited string，相容用）</summary>
    public const string Scope = "scope";

    /// <summary>權限（建議為多值 claim）</summary>
    public const string Permissions = "permissions";

    /// <summary>外部登入使用的 provider（例如 google / line / microsoft）</summary>
    public const string Provider = "provider";

    /// <summary>外部身分 issuer（對應 OIDC issuer/authority）</summary>
    public const string Issuer = "issuer";

    /// <summary>外部身分 subject（provider_sub / external_sub）</summary>
    public const string ExternalSubject = "external_sub";

    /// <summary>JWT ID（jti）</summary>
    public const string Jti = "jti";

    /// <summary>租戶 Token Version（強制重新登入用）</summary>
    public const string TenantTokenVersion = "tenant_tv";

    /// <summary>Subject Token Version（強制重新登入用）</summary>
    public const string SubjectTokenVersion = "subject_tv";
}
