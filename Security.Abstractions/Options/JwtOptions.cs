namespace Birdsoft.Security.Abstractions.Options;

using System;

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

    /// <summary>
    /// Key ring rotation 設定：支援多把 key 並行驗證。
    /// 若有設定 KeyRing.Keys，簽章會使用 ActiveSigningKid 或第一把 Active 可簽章的 key。
    /// </summary>
    public JwtKeyRingOptions? KeyRing { get; init; }

    /// <summary>
    /// Tenant-scoped JWT settings.
    /// When configured, each tenant can have its own issuer/audience and independent key ring.
    /// </summary>
    public JwtTenantOptions[] Tenants { get; init; } = Array.Empty<JwtTenantOptions>();

    /// <summary>Access Token 有效分鐘數</summary>
    public int AccessTokenMinutes { get; init; } = 10;

    /// <summary>Refresh Token 有效天數</summary>
    public int RefreshTokenDays { get; init; } = 14;

    /// <summary>Clock skew（秒）</summary>
    public int ClockSkewSeconds { get; init; } = 30;
}

public sealed class JwtTenantOptions
{
    public Guid TenantId { get; init; }

    /// <summary>Token issuer (iss) override for this tenant.</summary>
    public string? Issuer { get; init; }

    /// <summary>Token audience (aud) override for this tenant.</summary>
    public string? Audience { get; init; }

    /// <summary>
    /// Per-tenant key ring. If set, must not be shared across tenants.
    /// </summary>
    public JwtKeyRingOptions? KeyRing { get; init; }

    /// <summary>
    /// Legacy single-key override per tenant.
    /// </summary>
    public string? SigningKey { get; init; }

    public string? SigningAlgorithm { get; init; }

    public string? Kid { get; init; }
}

public sealed class JwtKeyRingOptions
{
    public string? ActiveSigningKid { get; init; }

    public JwtKeyMaterialOptions[] Keys { get; init; } = Array.Empty<JwtKeyMaterialOptions>();
}

public enum JwtKeyStatus
{
    Active = 0,
    Retired = 1,
    Disabled = 2,
}

public sealed class JwtKeyMaterialOptions
{
    public string Kid { get; init; } = string.Empty;
    public string Algorithm { get; init; } = "RS256";
    public JwtKeyStatus Status { get; init; } = JwtKeyStatus.Active;

    /// <summary>PEM private key（PKCS#8 / PKCS#1）。僅簽章端需要。</summary>
    public string? PrivateKeyPem { get; init; }

    /// <summary>PEM public key（可選）。若未提供且有 private key，會從 private 推導。</summary>
    public string? PublicKeyPem { get; init; }

    /// <summary>Symmetric key for HS* algorithms (UTF-8 string)。</summary>
    public string? SymmetricKey { get; init; }
}
