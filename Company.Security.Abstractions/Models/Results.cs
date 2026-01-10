namespace Company.Security.Abstractions;

/// <summary>
/// 驗證結果
/// </summary>
public sealed record AuthResult
{
    public bool Succeeded { get; init; }
    public string? ErrorCode { get; init; }
    public TokenPair? Tokens { get; init; }

    public static AuthResult Success(TokenPair tokens) => new() { Succeeded = true, Tokens = tokens };
    public static AuthResult Fail(string errorCode) => new() { Succeeded = false, ErrorCode = errorCode };
}

/// <summary>
/// Refresh 結果
/// </summary>
public sealed record RefreshResult
{
    public bool Succeeded { get; init; }
    public string? ErrorCode { get; init; }
    public TokenPair? Tokens { get; init; }

    public static RefreshResult Success(TokenPair tokens) => new() { Succeeded = true, Tokens = tokens };
    public static RefreshResult Fail(string errorCode) => new() { Succeeded = false, ErrorCode = errorCode };
}

/// <summary>
/// 撤銷結果
/// </summary>
public sealed record RevokeResult
{
    public bool Succeeded { get; init; }
    public string? ErrorCode { get; init; }

    public static RevokeResult Success() => new() { Succeeded = true };
    public static RevokeResult Fail(string errorCode) => new() { Succeeded = false, ErrorCode = errorCode };
}

/// <summary>
/// Access Token + Refresh Token
/// </summary>
public sealed record TokenPair
{
    public required string AccessToken { get; init; }
    public required string RefreshToken { get; init; }
    public required int ExpiresIn { get; init; }
}

/// <summary>
/// 授權檢查結果
/// </summary>
public sealed record AuthorizationResult
{
    public bool Allowed { get; init; }

    public static AuthorizationResult Allow() => new() { Allowed = true };
    public static AuthorizationResult Deny() => new() { Allowed = false };
}

/// <summary>
/// OIDC Provider 回傳的使用者資訊
/// </summary>
public sealed record OidcUserInfo
{
    public required string Issuer { get; init; }
    public required string ProviderSub { get; init; }
    public string? Email { get; init; }
    public string? Name { get; init; }
}

/// <summary>
/// Auth State 資訊
/// </summary>
public sealed record AuthStateInfo
{
    public required string State { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
}
