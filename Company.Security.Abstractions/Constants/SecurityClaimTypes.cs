namespace Company.Security.Abstractions.Constants;

/// <summary>
/// JWT 中的自訂 claim 名稱常數
/// </summary>
public static class SecurityClaimTypes
{
    /// <summary>租戶 ID</summary>
    public const string TenantId = "tenant_id";

    /// <summary>本系統 Subject（our_subject）</summary>
    public const string OurSubject = "our_subject";

    /// <summary>租戶 Token Version（強制重新登入用）</summary>
    public const string TenantTokenVersion = "tenant_tv";

    /// <summary>Subject Token Version（強制重新登入用）</summary>
    public const string SubjectTokenVersion = "subject_tv";
}
