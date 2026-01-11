namespace Birdsoft.Security.Authentication.Persistence;

using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authentication.Jwt;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public sealed class RepositoryTokenService : ITokenService
{
    private readonly IOptionsMonitor<JwtOptions> _jwtOptions;
    private readonly IJwtKeyProvider _keys;
    private readonly ITenantRepository _tenants;
    private readonly ISubjectRepository _subjects;
    private readonly IRefreshTokenRepository _refresh;
    private readonly IAccessTokenDenylistStore _denylist;
    private readonly ISessionStore _sessions;

    public RepositoryTokenService(
        IOptionsMonitor<JwtOptions> jwtOptions,
        IJwtKeyProvider keys,
        ITenantRepository tenants,
        ISubjectRepository subjects,
        IRefreshTokenRepository refresh,
        IAccessTokenDenylistStore denylist,
        ISessionStore sessions)
    {
        _jwtOptions = jwtOptions;
        _keys = keys;
        _tenants = tenants;
        _subjects = subjects;
        _refresh = refresh;
        _denylist = denylist;
        _sessions = sessions;
    }

    public async Task<AccessTokenValidationResult> ValidateAccessTokenAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        var opts = _jwtOptions.CurrentValue;
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return AccessTokenValidationResult.Fail("invalid_token");
        }

        var parts = accessToken.Split('.');
        if (parts.Length != 3)
        {
            return AccessTokenValidationResult.Fail("invalid_token");
        }

        var headerJson = Encoding.UTF8.GetString(Base64Url.Decode(parts[0]));
        var payloadJson = Encoding.UTF8.GetString(Base64Url.Decode(parts[1]));

        if (!TryGetHeaderAlg(headerJson, out var tokenAlg))
        {
            return AccessTokenValidationResult.Fail("invalid_token");
        }

        if (!string.Equals(tokenAlg, _keys.Algorithm, StringComparison.OrdinalIgnoreCase))
        {
            return AccessTokenValidationResult.Fail("invalid_token");
        }

        if (!VerifySignature(parts[0] + "." + parts[1], parts[2]))
        {
            return AccessTokenValidationResult.Fail("invalid_token");
        }

        using var doc = JsonDocument.Parse(payloadJson);
        var root = doc.RootElement;

        if (!TryGetString(root, "iss", out var iss) || !string.Equals(iss, opts.Issuer, StringComparison.Ordinal))
        {
            return AccessTokenValidationResult.Fail("invalid_issuer");
        }

        if (!TryAudienceContains(root, opts.Audience))
        {
            return AccessTokenValidationResult.Fail("invalid_audience");
        }

        if (!TryGetLong(root, "exp", out var exp))
        {
            return AccessTokenValidationResult.Fail("invalid_token");
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var skew = opts.ClockSkewSeconds;
        if (exp + skew < now)
        {
            return AccessTokenValidationResult.Fail("expired_token");
        }

        if (!TryGetString(root, SecurityClaimTypes.TenantId, out var tenantIdRaw) || !Guid.TryParse(tenantIdRaw, out var tenantId))
        {
            return AccessTokenValidationResult.Fail("invalid_tenant");
        }

        if (!TryGetString(root, "sub", out var subRaw) || !Guid.TryParse(subRaw, out var ourSubject))
        {
            return AccessTokenValidationResult.Fail("invalid_subject");
        }

        if (!TryGetString(root, SecurityClaimTypes.Jti, out var jti) || string.IsNullOrWhiteSpace(jti))
        {
            return AccessTokenValidationResult.Fail("invalid_token");
        }

        if (await _denylist.ContainsAsync(tenantId, jti, cancellationToken))
        {
            return AccessTokenValidationResult.Fail("revoked_token");
        }

        if (TryGetString(root, SecurityClaimTypes.SessionId, out var sessionRaw)
            && Guid.TryParse(sessionRaw, out var sessionId))
        {
            var active = await _sessions.IsSessionActiveAsync(tenantId, sessionId, cancellationToken);
            if (!active)
            {
                return AccessTokenValidationResult.Fail("session_terminated");
            }
        }

        var tenant = await _tenants.FindAsync(tenantId, cancellationToken);
        if (tenant is null)
        {
            return AccessTokenValidationResult.Fail("invalid_tenant");
        }

        if (tenant.Status != Birdsoft.Security.Abstractions.Models.TenantStatus.Active)
        {
            return AccessTokenValidationResult.Fail(tenant.Status == Birdsoft.Security.Abstractions.Models.TenantStatus.Archived ? "tenant_archived" : "tenant_suspended");
        }

        var subject = await _subjects.FindAsync(tenantId, ourSubject, cancellationToken);
        if (subject is null)
        {
            return AccessTokenValidationResult.Fail("invalid_subject");
        }

        if (subject.Status != Birdsoft.Security.Abstractions.Models.UserStatus.Active)
        {
            return AccessTokenValidationResult.Fail(subject.Status == Birdsoft.Security.Abstractions.Models.UserStatus.Locked ? "user_locked" : "user_disabled");
        }

        var tokenTenantTv = TryGetInt(root, SecurityClaimTypes.TenantTokenVersion);
        var tokenSubjectTv = TryGetInt(root, SecurityClaimTypes.SubjectTokenVersion);

        var currentTenantTv = tenant.TokenVersion;
        var currentSubjectTv = subject.TokenVersion;

        if ((tokenTenantTv ?? 0) != currentTenantTv || (tokenSubjectTv ?? 0) != currentSubjectTv)
        {
            return AccessTokenValidationResult.Fail("invalid_token_version");
        }

        return AccessTokenValidationResult.Success(tenantId, ourSubject, jti);
    }

    public Task<bool> IsJtiRevokedAsync(Guid tenantId, string jti, CancellationToken cancellationToken = default)
        => _denylist.ContainsAsync(tenantId, jti, cancellationToken);

    public async Task<TokenPair> GenerateTokensAsync(
        Guid tenantId,
        Guid ourSubject,
        IReadOnlyList<string>? roles = null,
        IReadOnlyList<string>? scopes = null,
        CancellationToken cancellationToken = default)
    {
        var opts = _jwtOptions.CurrentValue;

        var tenant = await _tenants.FindAsync(tenantId, cancellationToken)
            ?? await _tenants.CreateAsync(tenantId, $"tenant-{tenantId:N}", cancellationToken);

        var subject = await _subjects.FindAsync(tenantId, ourSubject, cancellationToken)
            ?? await _subjects.CreateAsync(tenantId, ourSubject, cancellationToken);

        var sessionId = await _sessions.CreateSessionAsync(tenantId, ourSubject, DateTimeOffset.UtcNow, cancellationToken);
        var jti = Guid.NewGuid().ToString("N");
        var accessToken = CreateAccessToken(opts, tenantId, ourSubject, jti, sessionId, tenant.TokenVersion, subject.TokenVersion, roles, scopes);

        var refreshToken = Base64Url.Encode(RandomNumberGenerator.GetBytes(48));
        var refreshExpires = DateTimeOffset.UtcNow.AddDays(Math.Max(1, opts.RefreshTokenDays));
        var refreshHash = HashRefreshToken(refreshToken);
        _ = await _refresh.CreateAsync(
            tenantId,
            ourSubject,
            sessionId,
            refreshHash,
            refreshExpires,
            issuedTenantTokenVersion: tenant.TokenVersion,
            issuedSubjectTokenVersion: subject.TokenVersion,
            cancellationToken);

        return new TokenPair
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = Math.Max(1, opts.AccessTokenMinutes) * 60,
        };
    }

    public async Task<RefreshResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return RefreshResult.Fail("invalid_refresh_token");
        }

        var now = DateTimeOffset.UtcNow;
        var tokenHash = HashRefreshToken(refreshToken);
        var dto = await _refresh.FindByHashAsync(tokenHash, cancellationToken);
        if (dto is null)
        {
            return RefreshResult.Fail("invalid_refresh_token");
        }

        if (!dto.IsValid(now))
        {
            return RefreshResult.Fail(dto.RevokedAt is not null ? "revoked_refresh_token" : "expired_refresh_token");
        }

        var sessionActive = await _sessions.IsSessionActiveAsync(dto.TenantId, dto.SessionId, cancellationToken);
        if (!sessionActive)
        {
            _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.TokenHash, now, cancellationToken: cancellationToken);
            return RefreshResult.Fail("session_terminated");
        }

        var tenant = await _tenants.FindAsync(dto.TenantId, cancellationToken);
        var subject = await _subjects.FindAsync(dto.TenantId, dto.OurSubject, cancellationToken);
        if (tenant is null)
        {
            _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.TokenHash, now, cancellationToken: cancellationToken);
            return RefreshResult.Fail("invalid_tenant");
        }

        if (tenant.Status != Birdsoft.Security.Abstractions.Models.TenantStatus.Active)
        {
            _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.TokenHash, now, cancellationToken: cancellationToken);
            return RefreshResult.Fail(tenant.Status == Birdsoft.Security.Abstractions.Models.TenantStatus.Archived ? "tenant_archived" : "tenant_suspended");
        }

        if (subject is null)
        {
            _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.TokenHash, now, cancellationToken: cancellationToken);
            return RefreshResult.Fail("invalid_subject");
        }

        if (subject.Status != Birdsoft.Security.Abstractions.Models.UserStatus.Active)
        {
            _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.TokenHash, now, cancellationToken: cancellationToken);
            return RefreshResult.Fail(subject.Status == Birdsoft.Security.Abstractions.Models.UserStatus.Locked ? "user_locked" : "user_disabled");
        }

        var currentTenantTv = tenant.TokenVersion;
        var currentSubjectTv = subject.TokenVersion;

        if (dto.IssuedTenantTokenVersion != currentTenantTv || dto.IssuedSubjectTokenVersion != currentSubjectTv)
        {
            _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.TokenHash, now, cancellationToken: cancellationToken);
            return RefreshResult.Fail("revoked_refresh_token");
        }

        // rotation: create new refresh, revoke old with replacedBy
        var opts = _jwtOptions.CurrentValue;
        var newRefreshToken = Base64Url.Encode(RandomNumberGenerator.GetBytes(48));
        var newHash = HashRefreshToken(newRefreshToken);
        var newDto = await _refresh.CreateAsync(
            dto.TenantId,
            dto.OurSubject,
            dto.SessionId,
            newHash,
            dto.ExpiresAt,
            issuedTenantTokenVersion: currentTenantTv,
            issuedSubjectTokenVersion: currentSubjectTv,
            cancellationToken);

        _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.TokenHash, now, replacedByTokenId: newDto.Id, cancellationToken: cancellationToken);

        var jti = Guid.NewGuid().ToString("N");
        var accessToken = CreateAccessToken(opts, dto.TenantId, dto.OurSubject, jti, dto.SessionId, currentTenantTv, currentSubjectTv, roles: null, scopes: null);

        return RefreshResult.Success(new TokenPair
        {
            AccessToken = accessToken,
            RefreshToken = newRefreshToken,
            ExpiresIn = Math.Max(1, opts.AccessTokenMinutes) * 60,
        });
    }

    public async Task<RevokeResult> RevokeAsync(Guid tenantId, Guid ourSubject, string refreshToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return RevokeResult.Fail("invalid_request");
        }

        var tokenHash = HashRefreshToken(refreshToken);
        var dto = await _refresh.FindByHashAsync(tokenHash, cancellationToken);
        if (dto is null)
        {
            return RevokeResult.Fail("refresh_token_not_found");
        }

        if (dto.TenantId != tenantId || dto.OurSubject != ourSubject)
        {
            return RevokeResult.Fail("forbidden");
        }

        var ok = await _refresh.RevokeAsync(tenantId, ourSubject, tokenHash, DateTimeOffset.UtcNow, cancellationToken: cancellationToken);
        _ = await _sessions.TerminateSessionAsync(tenantId, dto.SessionId, DateTimeOffset.UtcNow, reason: "refresh_revoke", cancellationToken);
        return ok ? RevokeResult.Success() : RevokeResult.Fail("revoke_failed");
    }

    public Task<int> RevokeAllAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
        => RevokeAllCoreAsync(tenantId, ourSubject, cancellationToken);

    private async Task<int> RevokeAllCoreAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken)
    {
        _ = await _sessions.TerminateAllAsync(tenantId, ourSubject, DateTimeOffset.UtcNow, reason: "revoke_all", cancellationToken);
        return await _refresh.RevokeAllBySubjectAsync(tenantId, ourSubject, DateTimeOffset.UtcNow, cancellationToken);
    }

    private string CreateAccessToken(
        JwtOptions opts,
        Guid tenantId,
        Guid ourSubject,
        string jti,
        Guid sessionId,
        int tenantTokenVersion,
        int subjectTokenVersion,
        IReadOnlyList<string>? roles,
        IReadOnlyList<string>? scopes)
    {
        var now = DateTimeOffset.UtcNow;
        var exp = now.AddMinutes(Math.Max(1, opts.AccessTokenMinutes));

        var alg = string.IsNullOrWhiteSpace(opts.SigningAlgorithm) ? _keys.Algorithm : opts.SigningAlgorithm;
        var kid = !string.IsNullOrWhiteSpace(opts.Kid) ? opts.Kid : _keys.Kid;

        var header = new Dictionary<string, object?>
        {
            ["typ"] = "JWT",
            ["alg"] = alg,
            ["kid"] = kid,
        };

        var payload = new Dictionary<string, object?>
        {
            ["iss"] = opts.Issuer,
            ["aud"] = opts.Audience,
            ["exp"] = exp.ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["nbf"] = now.ToUnixTimeSeconds(),
            [SecurityClaimTypes.Jti] = jti,
            [SecurityClaimTypes.SessionId] = sessionId.ToString(),
            ["sub"] = ourSubject.ToString(),
            [SecurityClaimTypes.TenantId] = tenantId.ToString(),
            [SecurityClaimTypes.OurSubject] = ourSubject.ToString(),
            [SecurityClaimTypes.TenantTokenVersion] = tenantTokenVersion,
            [SecurityClaimTypes.SubjectTokenVersion] = subjectTokenVersion,
        };

        if (roles is { Count: > 0 })
        {
            payload[SecurityClaimTypes.Roles] = roles;
        }

        if (scopes is { Count: > 0 })
        {
            payload[SecurityClaimTypes.Scopes] = scopes;
            payload[SecurityClaimTypes.Scope] = string.Join(' ', scopes);
        }

        var headerJson = JsonSerializer.Serialize(header, new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
        var payloadJson = JsonSerializer.Serialize(payload, new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });

        var headerPart = Base64Url.Encode(Encoding.UTF8.GetBytes(headerJson));
        var payloadPart = Base64Url.Encode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = headerPart + "." + payloadPart;

        var signature = Sign(signingInput);
        return signingInput + "." + signature;
    }

    private string Sign(string signingInput)
    {
        if (_keys.Algorithm.Equals("RS256", StringComparison.OrdinalIgnoreCase))
        {
            var rsa = _keys.GetRsaPrivateKey();
            if (rsa is null)
            {
                throw new InvalidOperationException("RS256 requires an RSA private key.");
            }

            var sig = rsa.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Base64Url.Encode(sig);
        }

        var key = _keys.GetSymmetricKeyBytes();
        if (key is null || key.Length == 0)
        {
            throw new InvalidOperationException("HMAC signing requires JwtOptions.SigningKey.");
        }

        return ComputeHmacSha256(signingInput, key);
    }

    private bool VerifySignature(string signingInput, string signaturePart)
    {
        if (_keys.Algorithm.Equals("RS256", StringComparison.OrdinalIgnoreCase))
        {
            var rsa = _keys.GetRsaPublicKey();
            if (rsa is null)
            {
                return false;
            }

            var sigBytes = Base64Url.Decode(signaturePart);
            return rsa.VerifyData(Encoding.ASCII.GetBytes(signingInput), sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        var key = _keys.GetSymmetricKeyBytes();
        if (key is null || key.Length == 0)
        {
            return false;
        }

        var expected = ComputeHmacSha256(signingInput, key);
        return CryptographicOperations.FixedTimeEquals(Base64Url.Decode(signaturePart), Base64Url.Decode(expected));
    }

    private static bool TryGetHeaderAlg(string headerJson, out string alg)
    {
        try
        {
            using var doc = JsonDocument.Parse(headerJson);
            if (doc.RootElement.TryGetProperty("alg", out var a) && a.ValueKind == JsonValueKind.String)
            {
                alg = a.GetString() ?? string.Empty;
                return !string.IsNullOrWhiteSpace(alg);
            }
        }
        catch
        {
            // ignore
        }

        alg = string.Empty;
        return false;
    }

    private static string ComputeHmacSha256(string signingInput, byte[] keyBytes)
    {
        var data = Encoding.UTF8.GetBytes(signingInput);
        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(data);
        return Base64Url.Encode(hash);
    }

    private static bool TryGetString(JsonElement root, string name, out string value)
    {
        if (root.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String)
        {
            value = prop.GetString() ?? string.Empty;
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static bool TryGetLong(JsonElement root, string name, out long value)
    {
        if (root.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.Number && prop.TryGetInt64(out value))
        {
            return true;
        }

        value = 0;
        return false;
    }

    private static int? TryGetInt(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var prop))
        {
            return null;
        }

        if (prop.ValueKind == JsonValueKind.Number && prop.TryGetInt32(out var n))
        {
            return n;
        }

        if (prop.ValueKind == JsonValueKind.String && int.TryParse(prop.GetString(), out n))
        {
            return n;
        }

        return null;
    }

    private static bool TryAudienceContains(JsonElement root, string expectedAudience)
    {
        if (string.IsNullOrWhiteSpace(expectedAudience))
        {
            return true;
        }

        if (!root.TryGetProperty("aud", out var aud))
        {
            return false;
        }

        return aud.ValueKind switch
        {
            JsonValueKind.String => string.Equals(aud.GetString(), expectedAudience, StringComparison.Ordinal),
            JsonValueKind.Array => aud.EnumerateArray().Any(e => e.ValueKind == JsonValueKind.String && string.Equals(e.GetString(), expectedAudience, StringComparison.Ordinal)),
            _ => false,
        };
    }

    private static string HashRefreshToken(string refreshToken)
    {
        var bytes = Encoding.UTF8.GetBytes(refreshToken);
        var hash = SHA256.HashData(bytes);
        return Base64Url.Encode(hash);
    }
}
