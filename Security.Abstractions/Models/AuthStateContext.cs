namespace Birdsoft.Security.Abstractions.Models;

/// <summary>
/// OIDC Callback 時需要的 state 內容（ConsumeState 取得）。
///
/// 注意：code_verifier 屬於敏感資訊，實作層應採加密/保護性儲存。
/// </summary>
public sealed record AuthStateContext
{
    public required Guid TenantId { get; init; }

    public required string Provider { get; init; }

    public required string CodeVerifier { get; init; }

    public required string Nonce { get; init; }

    public DateTimeOffset? ExpiresAt { get; init; }
}
