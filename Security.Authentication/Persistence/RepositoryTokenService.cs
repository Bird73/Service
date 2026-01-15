namespace Birdsoft.Security.Authentication.Persistence;

using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authentication.Jwt;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public sealed class RepositoryTokenService : ITokenService
{
    private readonly IOptionsMonitor<JwtOptions> _jwtOptions;
    private readonly IOptionsMonitor<SecurityEnvironmentOptions> _envOptions;
    private readonly IOptionsMonitor<SecuritySafetyOptions> _safetyOptions;
    private readonly IHostEnvironment _hostEnvironment;
    private readonly IOptionsMonitor<RefreshTokenHashingOptions> _refreshHashing;
    private readonly IJwtKeyProvider _keys;
    private readonly ITenantRepository _tenants;
    private readonly ISubjectRepository _subjects;
    private readonly IRefreshTokenRepository _refresh;
    private readonly IAccessTokenDenylistStore _denylist;
    private readonly ISessionStore _sessions;
    private readonly TimeProvider _time;

    public RepositoryTokenService(
        IOptionsMonitor<JwtOptions> jwtOptions,
        IOptionsMonitor<SecurityEnvironmentOptions> envOptions,
        IOptionsMonitor<SecuritySafetyOptions> safetyOptions,
        IHostEnvironment hostEnvironment,
        IOptionsMonitor<RefreshTokenHashingOptions> refreshHashing,
        IJwtKeyProvider keys,
        ITenantRepository tenants,
        ISubjectRepository subjects,
        IRefreshTokenRepository refresh,
        IAccessTokenDenylistStore denylist,
        ISessionStore sessions,
        TimeProvider? timeProvider = null)
    {
        _jwtOptions = jwtOptions;
        _envOptions = envOptions;
        _safetyOptions = safetyOptions;
        _hostEnvironment = hostEnvironment;
        _refreshHashing = refreshHashing;
        _keys = keys;
        _tenants = tenants;
        _subjects = subjects;
        _refresh = refresh;
        _denylist = denylist;
        _sessions = sessions;
        _time = timeProvider ?? TimeProvider.System;
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

        if (!TryGetHeaderKid(headerJson, out var tokenKid))
        {
            // Spec requires kid.
            return AccessTokenValidationResult.Fail("invalid_token");
        }

        if (!VerifySignature(parts[0] + "." + parts[1], parts[2], tokenAlg, tokenKid, opts))
        {
            return AccessTokenValidationResult.Fail("invalid_token");
        }

        using var doc = JsonDocument.Parse(payloadJson);
        var root = doc.RootElement;

        if (!TryGetLong(root, "exp", out var exp))
        {
            return AccessTokenValidationResult.Fail("invalid_token");
        }

        var skew = opts.ClockSkewSeconds;
        var now = _time.GetUtcNow().ToUnixTimeSeconds();

        // nbf not reached => fail (allow within clock skew)
        if (TryGetLong(root, "nbf", out var nbf) && nbf - skew > now)
        {
            return AccessTokenValidationResult.Fail(AuthErrorCodes.TokenNotYetValid);
        }

        // exp passed => fail (deterministic boundary rule: valid if now <= exp + skew)
        if (exp + skew < now)
        {
            return AccessTokenValidationResult.Fail(AuthErrorCodes.TokenExpired);
        }

        if (!TryGetString(root, SecurityClaimTypes.TenantId, out var tenantIdRaw) || !Guid.TryParse(tenantIdRaw, out var tenantId))
        {
            return AccessTokenValidationResult.Fail("invalid_tenant");
        }

        // Environment isolation (runtime): require env claim match when safety enabled or outside Development.
        var safety = _safetyOptions.CurrentValue;
        var enforceEnv = safety.Enabled || !_hostEnvironment.IsDevelopment();
        if (enforceEnv)
        {
            var env = _envOptions.CurrentValue;
            if (string.IsNullOrWhiteSpace(env.EnvironmentId))
            {
                return AccessTokenValidationResult.Fail("invalid_environment");
            }

            if (!TryGetString(root, TokenConstants.EnvironmentIdClaim, out var tokenEnv) || !string.Equals(tokenEnv, env.EnvironmentId, StringComparison.Ordinal))
            {
                return AccessTokenValidationResult.Fail("env_mismatch");
            }
        }

        var eff = JwtTenantResolution.Resolve(opts, tenantId);
        var legacyIssuer = eff.Issuer;
        var legacyAudience = eff.Audience;
        var envScopedIssuer = JwtTenantResolution.ApplyEnvironmentSuffix(legacyIssuer, _envOptions.CurrentValue);
        var envScopedAudience = JwtTenantResolution.ApplyEnvironmentSuffix(legacyAudience, _envOptions.CurrentValue);

        if (!TryGetString(root, "iss", out var iss)
            || (!string.Equals(iss, legacyIssuer, StringComparison.Ordinal) && !string.Equals(iss, envScopedIssuer, StringComparison.Ordinal)))
        {
            return AccessTokenValidationResult.Fail("invalid_issuer");
        }

        if (!TryAudienceContains(root, legacyAudience) && !TryAudienceContains(root, envScopedAudience))
        {
            return AccessTokenValidationResult.Fail("invalid_audience");
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

        // Spec: refresh token rotation creates a new refresh session each time.
        // Initial issuance creates the first refresh session and uses it as the JWT session_id.
        var sessionId = Guid.NewGuid();
        var jti = Guid.NewGuid().ToString("N");
        var accessToken = CreateAccessToken(opts, tenantId, ourSubject, jti, sessionId, tenant.TokenVersion, subject.TokenVersion, roles, scopes);

        var refreshToken = CreateRefreshToken(tenantId);
        var refreshExpires = _time.GetUtcNow().AddDays(Math.Max(1, opts.RefreshTokenDays));
        var refreshHash = HashRefreshToken(refreshToken);
        var refreshLookup = ComputeTokenLookup(refreshHash);
        _ = await _refresh.CreateAsync(
            tenantId,
            ourSubject,
            sessionId,
            refreshLookup,
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

    public async Task<RefreshResult> RefreshAsync(Guid tenantId, string refreshToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return RefreshResult.Fail("invalid_refresh_token");
        }

        if (TryExtractTenantId(refreshToken, out var tokenTenantId) && tokenTenantId != tenantId)
        {
            return RefreshResult.Fail("invalid_tenant");
        }

        var now = _time.GetUtcNow();
        var tokenHash = HashRefreshToken(refreshToken);
        var tokenLookup = ComputeTokenLookup(tokenHash);
        var dto = await _refresh.FindByHashAsync(tenantId, tokenLookup, tokenHash, cancellationToken);
        if (dto is null)
        {
            return RefreshResult.Fail("invalid_refresh_token");
        }

        // Tenant hardening is enforced by tenant-scoped lookup and token prefix.

        // refresh token reuse detection (rotation): old token used again => revoke whole session
        if (dto.RevokedAt is not null && dto.ReplacedByRefreshTokenId is not null)
        {
            _ = await _refresh.RevokeAllBySubjectAsync(dto.TenantId, dto.OurSubject, now, cancellationToken);
            _ = await _sessions.TerminateAllAsync(dto.TenantId, dto.OurSubject, now, reason: "refresh_reuse", cancellationToken);
            return RefreshResult.Fail(Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.RefreshTokenReuseDetected);
        }

        // If the refresh session was terminated externally (governance/admin), surface it as session_terminated.
        // Internal revocations use well-known reasons like refresh_revoke/refresh_reuse/rotated.
        if (dto.RevokedAt is not null && dto.ReplacedByRefreshTokenId is null && !IsInternalRefreshRevocationReason(dto.RevocationReason))
        {
            return RefreshResult.Fail("session_terminated");
        }

        if (!dto.IsValid(now))
        {
            return RefreshResult.Fail(dto.RevokedAt is not null ? "revoked_refresh_token" : "expired_refresh_token");
        }

        // Session existence/active is implied by the refresh session row itself.

        var tenant = await _tenants.FindAsync(dto.TenantId, cancellationToken);
        var subject = await _subjects.FindAsync(dto.TenantId, dto.OurSubject, cancellationToken);
        if (tenant is null)
        {
            _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.SessionId, dto.TokenLookup, dto.TokenHash, now, revokeReason: "invalid_tenant", cancellationToken: cancellationToken);
            return RefreshResult.Fail("invalid_tenant");
        }

        if (tenant.Status != Birdsoft.Security.Abstractions.Models.TenantStatus.Active)
        {
            _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.SessionId, dto.TokenLookup, dto.TokenHash, now, revokeReason: "tenant_inactive", cancellationToken: cancellationToken);
            return RefreshResult.Fail(tenant.Status == Birdsoft.Security.Abstractions.Models.TenantStatus.Archived ? "tenant_archived" : "tenant_suspended");
        }

        if (subject is null)
        {
            _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.SessionId, dto.TokenLookup, dto.TokenHash, now, revokeReason: "invalid_subject", cancellationToken: cancellationToken);
            return RefreshResult.Fail("invalid_subject");
        }

        if (subject.Status != Birdsoft.Security.Abstractions.Models.UserStatus.Active)
        {
            _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.SessionId, dto.TokenLookup, dto.TokenHash, now, revokeReason: "subject_inactive", cancellationToken: cancellationToken);
            return RefreshResult.Fail(subject.Status == Birdsoft.Security.Abstractions.Models.UserStatus.Locked ? "user_locked" : "user_disabled");
        }

        var currentTenantTv = tenant.TokenVersion;
        var currentSubjectTv = subject.TokenVersion;

        if (dto.IssuedTenantTokenVersion != currentTenantTv || dto.IssuedSubjectTokenVersion != currentSubjectTv)
        {
            _ = await _refresh.RevokeAsync(dto.TenantId, dto.OurSubject, dto.SessionId, dto.TokenLookup, dto.TokenHash, now, revokeReason: "token_version_mismatch", cancellationToken: cancellationToken);
            return RefreshResult.Fail("invalid_token_version");
        }

        // rotation (atomic): create new refresh and revoke old with replacedBy in the same transaction
        var opts = _jwtOptions.CurrentValue;
        var newRefreshToken = CreateRefreshToken(dto.TenantId);
        var newHash = HashRefreshToken(newRefreshToken);
        var newLookup = ComputeTokenLookup(newHash);
        var newSessionId = Guid.NewGuid();
        var newDto = await _refresh.TryRotateAsync(
            tenantId: dto.TenantId,
            ourSubject: dto.OurSubject,
            currentSessionId: dto.SessionId,
            currentTokenLookup: dto.TokenLookup,
            currentTokenHash: dto.TokenHash,
            newSessionId: newSessionId,
            newTokenLookup: newLookup,
            newTokenHash: newHash,
            expiresAt: dto.ExpiresAt,
            now: now,
            issuedTenantTokenVersion: currentTenantTv,
            issuedSubjectTokenVersion: currentSubjectTv,
            revokeReason: "rotated",
            cancellationToken);

        if (newDto is null)
        {
            // Another request rotated/revoked it first (concurrent refresh). Deterministic: fail this attempt.
            return RefreshResult.Fail("revoked_refresh_token");
        }

        var jti = Guid.NewGuid().ToString("N");
        var accessToken = CreateAccessToken(opts, dto.TenantId, dto.OurSubject, jti, newSessionId, currentTenantTv, currentSubjectTv, roles: null, scopes: null);

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

        if (TryExtractTenantId(refreshToken, out var tokenTenantId) && tokenTenantId != tenantId)
        {
            return RevokeResult.Fail("forbidden");
        }

        var tokenHash = HashRefreshToken(refreshToken);
        var tokenLookup = ComputeTokenLookup(tokenHash);
        var dto = await _refresh.FindByHashAsync(tenantId, tokenLookup, tokenHash, cancellationToken);
        if (dto is null)
        {
            return RevokeResult.Fail("refresh_token_not_found");
        }

        if (dto.TenantId != tenantId || dto.OurSubject != ourSubject)
        {
            return RevokeResult.Fail("forbidden");
        }

        var now = _time.GetUtcNow();
        var ok = await _refresh.RevokeAsync(tenantId, ourSubject, dto.SessionId, dto.TokenLookup, dto.TokenHash, now, revokeReason: "refresh_revoke", cancellationToken: cancellationToken);
        _ = await _sessions.TerminateSessionAsync(tenantId, dto.SessionId, now, reason: "refresh_revoke", cancellationToken);
        return ok ? RevokeResult.Success() : RevokeResult.Fail("revoke_failed");
    }

    public Task<int> RevokeAllAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
        => RevokeAllCoreAsync(tenantId, ourSubject, cancellationToken);

    private async Task<int> RevokeAllCoreAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        _ = await _sessions.TerminateAllAsync(tenantId, ourSubject, now, reason: "revoke_all", cancellationToken);
        return await _refresh.RevokeAllBySubjectAsync(tenantId, ourSubject, now, cancellationToken);
    }

    private static string ComputeTokenLookup(string tokenHash)
        => string.IsNullOrWhiteSpace(tokenHash)
            ? string.Empty
            : (tokenHash.Length <= 16 ? tokenHash : tokenHash[..16]);

    private static string CreateRefreshToken(Guid tenantId)
        => $"rt1.{tenantId:N}.{Base64Url.Encode(RandomNumberGenerator.GetBytes(48))}";

    private static bool TryExtractTenantId(string refreshToken, out Guid tenantId)
    {
        tenantId = default;
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return false;
        }

        // Format: rt1.{tenantIdN}.{random}
        var parts = refreshToken.Split('.', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
        {
            return false;
        }

        if (!string.Equals(parts[0], "rt1", StringComparison.Ordinal))
        {
            return false;
        }

        return Guid.TryParseExact(parts[1], "N", out tenantId);
    }

    private static bool IsInternalRefreshRevocationReason(string? reason)
        => !string.IsNullOrWhiteSpace(reason)
           && reason is "refresh_revoke"
               or "refresh_reuse"
               or "rotated"
               or "tenant_inactive"
               or "subject_inactive"
               or "token_version_mismatch"
               or "invalid_tenant"
               or "invalid_subject";

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
        var now = _time.GetUtcNow();
        var exp = now.AddMinutes(Math.Max(1, opts.AccessTokenMinutes));

        var signing = ResolveSigningKey(opts);
        var alg = signing.Algorithm;
        var kid = signing.Kid;

        var header = new Dictionary<string, object?>
        {
            ["typ"] = "JWT",
            ["alg"] = alg,
            ["kid"] = kid,
        };

        var env = _envOptions.CurrentValue;
        var iss = JwtTenantResolution.ApplyEnvironmentSuffix(JwtTenantResolution.Resolve(opts, tenantId).Issuer, env);
        var aud = JwtTenantResolution.ApplyEnvironmentSuffix(JwtTenantResolution.Resolve(opts, tenantId).Audience, env);

        var payload = new Dictionary<string, object?>
        {
            ["iss"] = iss,
            ["aud"] = aud,
            ["exp"] = exp.ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["nbf"] = now.ToUnixTimeSeconds(),
            [TokenConstants.TokenFormatVersionClaim] = TokenConstants.TokenFormatVersion,
            [SecurityClaimTypes.Jti] = jti,
            [SecurityClaimTypes.SessionId] = sessionId.ToString(),
            ["sub"] = ourSubject.ToString(),
            [SecurityClaimTypes.TenantId] = tenantId.ToString(),
            [SecurityClaimTypes.OurSubject] = ourSubject.ToString(),
            [SecurityClaimTypes.TenantTokenVersion] = tenantTokenVersion,
            [SecurityClaimTypes.SubjectTokenVersion] = subjectTokenVersion,
        };

        if (!string.IsNullOrWhiteSpace(env.EnvironmentId))
        {
            payload[TokenConstants.EnvironmentIdClaim] = env.EnvironmentId;
        }

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

        var signature = Sign(signingInput, signing);
        return signingInput + "." + signature;
    }

    private sealed record SigningKey(string Algorithm, string Kid, RSA? RsaPrivate, byte[]? SymmetricKey);

    private SigningKey ResolveSigningKey(JwtOptions opts)
    {
        if (opts.KeyRing?.Keys is { Length: > 0 })
        {
            var ring = opts.KeyRing;
            var keys = ring.Keys.Where(k => k.Status == JwtKeyStatus.Active).ToArray();

            var active = !string.IsNullOrWhiteSpace(ring.ActiveSigningKid)
                ? keys.FirstOrDefault(k => string.Equals(k.Kid, ring.ActiveSigningKid, StringComparison.Ordinal))
                : null;
            active ??= keys.FirstOrDefault();

            if (active is not null)
            {
                var alg = string.IsNullOrWhiteSpace(active.Algorithm) ? "RS256" : active.Algorithm.Trim();
                if (alg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
                {
                    if (string.IsNullOrWhiteSpace(active.PrivateKeyPem))
                    {
                        throw new InvalidOperationException("JwtOptions.KeyRing signing key requires PrivateKeyPem for RS256.");
                    }

                    return new SigningKey("RS256", active.Kid, TryLoadRsa(active.PrivateKeyPem), null);
                }

                if (alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
                {
                    if (string.IsNullOrWhiteSpace(active.SymmetricKey))
                    {
                        throw new InvalidOperationException("JwtOptions.KeyRing signing key requires SymmetricKey for HS*.");
                    }

                    return new SigningKey(alg.ToUpperInvariant(), active.Kid, null, Encoding.UTF8.GetBytes(active.SymmetricKey));
                }
            }
        }

        // Legacy single-key provider
        var legacyAlg = string.IsNullOrWhiteSpace(opts.SigningAlgorithm) ? _keys.Algorithm : opts.SigningAlgorithm;
        var legacyKid = !string.IsNullOrWhiteSpace(opts.Kid) ? opts.Kid : _keys.Kid;
        if (legacyAlg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
        {
            return new SigningKey("RS256", legacyKid ?? _keys.Kid, _keys.GetRsaPrivateKey(), null);
        }

        return new SigningKey(legacyAlg.ToUpperInvariant(), legacyKid ?? _keys.Kid, null, _keys.GetSymmetricKeyBytes());
    }

    private static string Sign(string signingInput, SigningKey signing)
    {
        if (signing.Algorithm.Equals("RS256", StringComparison.OrdinalIgnoreCase))
        {
            if (signing.RsaPrivate is null)
            {
                throw new InvalidOperationException("RS256 requires an RSA private key.");
            }

            var sig = signing.RsaPrivate.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Base64Url.Encode(sig);
        }

        if (signing.SymmetricKey is null || signing.SymmetricKey.Length == 0)
        {
            throw new InvalidOperationException("HMAC signing requires a symmetric key.");
        }

        return ComputeHmacSha256(signingInput, signing.SymmetricKey);
    }

    private bool VerifySignature(string signingInput, string signaturePart, string tokenAlg, string tokenKid, JwtOptions opts)
    {
        foreach (var v in ResolveValidationKeys(tokenAlg, tokenKid, opts))
        {
            if (tokenAlg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
            {
                if (v.RsaPublic is null)
                {
                    continue;
                }

                var sigBytes = Base64Url.Decode(signaturePart);
                if (v.RsaPublic.VerifyData(Encoding.ASCII.GetBytes(signingInput), sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                {
                    return true;
                }

                continue;
            }

            if (tokenAlg.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
            {
                if (v.SymmetricKey is null || v.SymmetricKey.Length == 0)
                {
                    continue;
                }

                var expected = ComputeHmacSha256(signingInput, v.SymmetricKey);
                if (CryptographicOperations.FixedTimeEquals(Base64Url.Decode(signaturePart), Base64Url.Decode(expected)))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private sealed record ValidationKey(string Kid, RSA? RsaPublic, byte[]? SymmetricKey);

    private IEnumerable<ValidationKey> ResolveValidationKeys(string tokenAlg, string tokenKid, JwtOptions opts)
    {
        if (opts.KeyRing?.Keys is { Length: > 0 })
        {
            foreach (var k in opts.KeyRing.Keys)
            {
                if (k.Status == JwtKeyStatus.Disabled)
                {
                    continue;
                }

                if (!string.Equals(k.Kid, tokenKid, StringComparison.Ordinal))
                {
                    continue;
                }

                var alg = string.IsNullOrWhiteSpace(k.Algorithm) ? "RS256" : k.Algorithm.Trim();
                if (!string.Equals(alg, tokenAlg, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (alg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
                {
                    var rsa = TryLoadRsa(k.PublicKeyPem) ?? (!string.IsNullOrWhiteSpace(k.PrivateKeyPem) ? CreatePublicFromPrivate(k.PrivateKeyPem) : null);
                    yield return new ValidationKey(k.Kid, rsa, null);
                    continue;
                }

                if (alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(k.SymmetricKey))
                {
                    yield return new ValidationKey(k.Kid, null, Encoding.UTF8.GetBytes(k.SymmetricKey));
                }
            }
        }

        // Legacy fallback
        if (_keys.Algorithm.Equals(tokenAlg, StringComparison.OrdinalIgnoreCase)
            && string.Equals(_keys.Kid, tokenKid, StringComparison.Ordinal))
        {
            if (tokenAlg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
            {
                yield return new ValidationKey(_keys.Kid, _keys.GetRsaPublicKey(), null);
            }
            else
            {
                yield return new ValidationKey(_keys.Kid, null, _keys.GetSymmetricKeyBytes());
            }
        }
    }

    private static RSA? TryLoadRsa(string? pemOrBase64)
    {
        if (string.IsNullOrWhiteSpace(pemOrBase64))
        {
            return null;
        }

        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pemOrBase64);
            return rsa;
        }
        catch
        {
            // ignore
        }

        try
        {
            var bytes = Convert.FromBase64String(pemOrBase64);
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(bytes, out _);
            return rsa;
        }
        catch
        {
            return null;
        }
    }

    private static RSA? CreatePublicFromPrivate(string privatePem)
    {
        var rsaPriv = TryLoadRsa(privatePem);
        if (rsaPriv is null)
        {
            return null;
        }

        var rsaPub = RSA.Create();
        rsaPub.ImportParameters(rsaPriv.ExportParameters(includePrivateParameters: false));
        return rsaPub;
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

    private static bool TryGetHeaderKid(string headerJson, out string kid)
    {
        try
        {
            using var doc = JsonDocument.Parse(headerJson);
            if (doc.RootElement.TryGetProperty("kid", out var k) && k.ValueKind == JsonValueKind.String)
            {
                kid = k.GetString() ?? string.Empty;
                return !string.IsNullOrWhiteSpace(kid);
            }
        }
        catch
        {
            // ignore
        }

        kid = string.Empty;
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

    private string HashRefreshToken(string refreshToken)
    {
        var bytes = Encoding.UTF8.GetBytes(refreshToken);
        var opts = _refreshHashing.CurrentValue;

        // Security requirement: use HMAC-SHA256 with server-side secret (pepper).
        if (string.IsNullOrWhiteSpace(opts.Pepper))
        {
            throw new InvalidOperationException("RefreshTokenHashingOptions.Pepper must be configured");
        }

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(opts.Pepper));
        var mac = hmac.ComputeHash(bytes);
        return Base64Url.Encode(mac);
    }
}
