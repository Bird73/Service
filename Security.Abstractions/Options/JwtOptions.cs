namespace Birdsoft.Security.Abstractions.Options;

/// <summary>
/// JWT 簽發與驗證設定。
/// </summary>
public sealed class JwtOptions
{
    public const string SectionName = "Security:Jwt";

    /// <summary>Token issuer（iss）</summary>
    public string Issuer { get; init; } = string.Empty;

    /// <summary>Token audience（aud）</summary>
    public string Audience { get; init; } = string.Empty;

    /// <summary>
    /// 簽章金鑰。
    /// - 當 <see cref="SigningAlgorithm"/> 為 RS256：建議使用 PEM 私鑰（PKCS#8 / PKCS#1）
    /// - 當 <see cref="SigningAlgorithm"/> 為 HS256/HS512：使用對稱 secret（不會在 JWKS 公開）
    /// </summary>
    public string SigningKey { get; init; } = string.Empty;

    /// <summary>
    /// 簽章演算法（例如 RS256 / HS256）。預設 RS256。
    /// </summary>
    public string SigningAlgorithm { get; init; } = "RS256";

    /// <summary>
    /// Key identifier（kid），用於 key rotation / JWKS。
    /// </summary>
    public string? Kid { get; init; }

    /// <summary>Access Token 有效分鐘數</summary>
    public int AccessTokenMinutes { get; init; } = 10;

    /// <summary>Refresh Token 有效天數</summary>
    public int RefreshTokenDays { get; init; } = 14;

    /// <summary>Clock skew（秒）</summary>
    public int ClockSkewSeconds { get; init; } = 30;
}
