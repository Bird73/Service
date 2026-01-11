namespace Birdsoft.Security.Abstractions.Tenancy;

/// <summary>
/// 與 ASP.NET Core 解耦的 tenant 解析輸入。
/// </summary>
public sealed record TenantResolveInput(
    string? Host,
    string? Path,
    IReadOnlyDictionary<string, string?> Headers,
    IReadOnlyDictionary<string, string?> Claims);
