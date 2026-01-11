namespace Birdsoft.Security.Abstractions.Options;

/// <summary>
/// Refresh token 儲存用的 hash/encryption 設定。
/// 目前採用 HMAC-SHA256（pepper），並支援向後相容的 SHA256。
/// </summary>
public sealed class RefreshTokenHashingOptions
{
    public const string SectionName = "Security:RefreshTokenHashing";

    /// <summary>
    /// HMAC key (pepper). 若未提供，會退回到無 pepper 的 SHA256（相容性/開發方便）。
    /// </summary>
    public string? Pepper { get; init; }
}
