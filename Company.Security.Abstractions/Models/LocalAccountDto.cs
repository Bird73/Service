namespace Company.Security.Abstractions.Models;

/// <summary>
/// 對外可安全暴露的本地帳號資訊（不包含密碼雜湊等敏感資訊）。
/// </summary>
public sealed record LocalAccountProfileDto
{
    public required System.Guid TenantId { get; init; }
    public required System.Guid OurSubject { get; init; }
    public required string UsernameOrEmail { get; init; }
}
