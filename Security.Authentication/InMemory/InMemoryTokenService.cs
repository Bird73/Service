namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authentication.Jwt;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public sealed class InMemoryTokenService : ITokenService, IAccessTokenDenylistStore
{
    private sealed record RefreshRecord(
        Guid TenantId,
        Guid OurSubject,
        Guid SessionId,
        DateTimeOffset ExpiresAt,
        bool Revoked,
        string? ReplacedByTokenHash);

    private readonly IOptionsMonitor<JwtOptions> _jwtOptions;
    private readonly IOptionsMonitor<SecurityEnvironmentOptions> _envOptions;
    private readonly IOptionsMonitor<SecuritySafetyOptions> _safetyOptions;
    private readonly IHostEnvironment _hostEnvironment;
    private readonly IOptionsMonitor<RefreshTokenHashingOptions> _refreshHashing;
    private readonly IJwtKeyProvider _keys;
    private readonly ISessionStore _sessions;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, RefreshRecord> _refresh = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<(Guid TenantId, string Jti), DateTimeOffset> _revokedJti = new();

    public InMemoryTokenService(
        IOptionsMonitor<JwtOptions> jwtOptions,
        IOptionsMonitor<SecurityEnvironmentOptions> envOptions,
        IOptionsMonitor<SecuritySafetyOptions> safetyOptions,
        IHostEnvironment hostEnvironment,
        IOptionsMonitor<RefreshTokenHashingOptions> refreshHashing,
        IJwtKeyProvider keys,
        ISessionStore sessions,
        TimeProvider? timeProvider = null)
    {
        _jwtOptions = jwtOptions;
        _envOptions = envOptions;
        _safetyOptions = safetyOptions;
        _hostEnvironment = hostEnvironment;
        _refreshHashing = refreshHashing;
        _keys = keys;
        _sessions = sessions;
        _time = timeProvider ?? TimeProvider.System;
    }

    public Task<AccessTokenValidationResult> ValidateAccessTokenAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var opts = _jwtOptions.CurrentValue;
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return Task.FromResult(AccessTokenValidationResult.Fail("invalid_token"));
        }

        var parts = accessToken.Split('.');
        if (parts.Length != 3)
        {
            return Task.FromResult(AccessTokenValidationResult.Fail("invalid_token"));
        }

        var headerJson = Encoding.UTF8.GetString(Base64Url.Decode(parts[0]));
        var payloadJson = Encoding.UTF8.GetString(Base64Url.Decode(parts[1]));

        if (!TryGetHeaderAlg(headerJson, out var tokenAlg))
        {
            return Task.FromResult(AccessTokenValidationResult.Fail("invalid_token"));
        }

        if (!TryGetHeaderKid(headerJson, out var tokenKid))
        {
            // Spec requires kid.
            return Task.FromResult(AccessTokenValidationResult.Fail("invalid_token"));
        }

        if (!VerifySignature(parts[0] + "." + parts[1], parts[2], tokenAlg, tokenKid, opts))
        {
            return Task.FromResult(AccessTokenValidationResult.Fail("invalid_token"));
        }

        using var doc = JsonDocument.Parse(payloadJson);
        var root = doc.RootElement;

        if (!TryGetLong(root, "exp", out var exp))
        {
            return Task.FromResult(AccessTokenValidationResult.Fail("invalid_token"));
        }

        var skew = opts.ClockSkewSeconds;
        var now = _time.GetUtcNow().ToUnixTimeSeconds();

        // nbf not reached => fail (allow within clock skew)
        if (TryGetLong(root, "nbf", out var nbf) && nbf - skew > now)
        {
            return Task.FromResult(AccessTokenValidationResult.Fail(AuthErrorCodes.TokenNotYetValid));
        }

        // exp passed => fail (deterministic boundary rule: valid if now <= exp + skew)
        if (exp + skew < now)
        {
            return Task.FromResult(AccessTokenValidationResult.Fail(AuthErrorCodes.TokenExpired));
        }

        if (!TryGetString(root, SecurityClaimTypes.TenantId, out var tenantIdRaw) || !Guid.TryParse(tenantIdRaw, out var tenantId))
        {
            return Task.FromResult(AccessTokenValidationResult.Fail("invalid_tenant"));
        }

        // Environment isolation (runtime): require env claim match when safety enabled or outside Development.
        var safety = _safetyOptions.CurrentValue;
        var enforceEnv = safety.Enabled || !_hostEnvironment.IsDevelopment();
        if (enforceEnv)
        {
            var env = _envOptions.CurrentValue;
            if (string.IsNullOrWhiteSpace(env.EnvironmentId))
            {
                return Task.FromResult(AccessTokenValidationResult.Fail("invalid_environment"));
            }

            if (!TryGetString(root, TokenConstants.EnvironmentIdClaim, out var tokenEnv) || !string.Equals(tokenEnv, env.EnvironmentId, StringComparison.Ordinal))
            {
                return Task.FromResult(AccessTokenValidationResult.Fail("env_mismatch"));
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
            return Task.FromResult(AccessTokenValidationResult.Fail("invalid_issuer"));
        }

        if (!TryAudienceContains(root, legacyAudience) && !TryAudienceContains(root, envScopedAudience))
        {
            return Task.FromResult(AccessTokenValidationResult.Fail("invalid_audience"));
        }

        if (!TryGetString(root, "sub", out var subRaw) || !Guid.TryParse(subRaw, out var ourSubject))
        {
            return Task.FromResult(AccessTokenValidationResult.Fail("invalid_subject"));
        }

        if (!TryGetString(root, SecurityClaimTypes.Jti, out var jti) || string.IsNullOrWhiteSpace(jti))
        {
            return Task.FromResult(AccessTokenValidationResult.Fail("invalid_token"));
        }

        if (_revokedJti.TryGetValue((tenantId, jti), out var revokedUntil))
        {
            if (revokedUntil > _time.GetUtcNow())
            {
                return Task.FromResult(AccessTokenValidationResult.Fail("revoked_token"));
            }

            _revokedJti.TryRemove((tenantId, jti), out _);
        }

        if (TryGetString(root, SecurityClaimTypes.SessionId, out var sessionRaw)
            && Guid.TryParse(sessionRaw, out var sessionId))
        {
            var active = _sessions.IsSessionActiveAsync(tenantId, sessionId, cancellationToken)
                .GetAwaiter()
                .GetResult();

            if (!active)
            {
                return Task.FromResult(AccessTokenValidationResult.Fail("session_terminated"));
            }
        }

        return Task.FromResult(AccessTokenValidationResult.Success(tenantId, ourSubject, jti));
    }

    public Task<bool> IsJtiRevokedAsync(Guid tenantId, string jti, CancellationToken cancellationToken = default)
    {
        return ContainsAsync(tenantId, jti, cancellationToken);
    }

    public Task AddAsync(Guid tenantId, string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (tenantId == Guid.Empty || string.IsNullOrWhiteSpace(jti))
        {
            return Task.CompletedTask;
        }

        // Store until the token expires; ValidateAccessTokenAsync treats it as revoked if now < expiresAt.
        _revokedJti[(tenantId, jti)] = expiresAt;
        return Task.CompletedTask;
    }

    public Task<bool> ContainsAsync(Guid tenantId, string jti, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (tenantId == Guid.Empty || string.IsNullOrWhiteSpace(jti))
        {
            return Task.FromResult(false);
        }

        if (!_revokedJti.TryGetValue((tenantId, jti), out var until))
        {
            return Task.FromResult(false);
        }

        if (until <= _time.GetUtcNow())
        {
            _revokedJti.TryRemove((tenantId, jti), out _);
            return Task.FromResult(false);
        }

        return Task.FromResult(true);
    }

    public Task<TokenPair> GenerateTokensAsync(
        Guid tenantId,
        Guid ourSubject,
        IReadOnlyList<string>? roles = null,
        IReadOnlyList<string>? scopes = null,
        CancellationToken cancellationToken = default)
    {
        var sessionId = _sessions.CreateSessionAsync(tenantId, ourSubject, _time.GetUtcNow(), cancellationToken)
            .GetAwaiter()
            .GetResult();
        var opts = _jwtOptions.CurrentValue;

        var jti = Guid.NewGuid().ToString("N");
        var accessToken = CreateAccessToken(opts, tenantId, ourSubject, jti, sessionId, roles, scopes);

        var refreshToken = Base64Url.Encode(RandomNumberGenerator.GetBytes(48));
        var refreshExpires = _time.GetUtcNow().AddDays(Math.Max(1, opts.RefreshTokenDays));
        _refresh[HashRefreshToken(refreshToken)] = new RefreshRecord(tenantId, ourSubject, sessionId, refreshExpires, Revoked: false, ReplacedByTokenHash: null);

        return Task.FromResult(new TokenPair
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = Math.Max(1, opts.AccessTokenMinutes) * 60,
        });
    }

    public Task<RefreshResult> RefreshAsync(Guid tenantId, string refreshToken, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var tokenHash = HashRefreshToken(refreshToken);
        if (!_refresh.TryGetValue(tokenHash, out var rec))
        {
            return Task.FromResult(RefreshResult.Fail("invalid_refresh_token"));
        }

        // Tenant hardening: refresh token must be used under the same tenant context.
        if (rec.TenantId != tenantId)
        {
            return Task.FromResult(RefreshResult.Fail("invalid_tenant"));
        }

        if (!_sessions.IsSessionActiveAsync(rec.TenantId, rec.SessionId, cancellationToken).GetAwaiter().GetResult())
        {
            return Task.FromResult(RefreshResult.Fail("session_terminated"));
        }

        if (rec.ExpiresAt <= _time.GetUtcNow())
        {
            return Task.FromResult(RefreshResult.Fail("expired_refresh_token"));
        }

        if (rec.Revoked)
        {
            if (!string.IsNullOrWhiteSpace(rec.ReplacedByTokenHash))
            {
                // reuse detected => revoke whole session
                foreach (var (token, r) in _refresh)
                {
                    if (r.TenantId == rec.TenantId && r.SessionId == rec.SessionId && !r.Revoked)
                    {
                        _refresh[token] = r with { Revoked = true };
                    }
                }

                _ = _sessions.TerminateSessionAsync(rec.TenantId, rec.SessionId, _time.GetUtcNow(), reason: "refresh_reuse", cancellationToken)
                    .GetAwaiter()
                    .GetResult();

                return Task.FromResult(RefreshResult.Fail(Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.RefreshTokenReuseDetected));
            }

            return Task.FromResult(RefreshResult.Fail("revoked_refresh_token"));
        }

        // rotation
        var newRefresh = Base64Url.Encode(RandomNumberGenerator.GetBytes(48));
        var newHash = HashRefreshToken(newRefresh);
        var replaced = rec with { Revoked = true, ReplacedByTokenHash = newHash };
        _refresh[tokenHash] = replaced;

        var newRec = new RefreshRecord(rec.TenantId, rec.OurSubject, rec.SessionId, rec.ExpiresAt, Revoked: false, ReplacedByTokenHash: null);
        _refresh[newHash] = newRec;

        var opts = _jwtOptions.CurrentValue;
        var jti = Guid.NewGuid().ToString("N");
        var accessToken = CreateAccessToken(opts, rec.TenantId, rec.OurSubject, jti, rec.SessionId, roles: null, scopes: null);

        return Task.FromResult(RefreshResult.Success(new TokenPair
        {
            AccessToken = accessToken,
            RefreshToken = newRefresh,
            ExpiresIn = Math.Max(1, opts.AccessTokenMinutes) * 60,
        }));
    }

    public Task<RevokeResult> RevokeAsync(Guid tenantId, Guid ourSubject, string refreshToken, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var tokenHash = HashRefreshToken(refreshToken);
        if (!_refresh.TryGetValue(tokenHash, out var rec))
        {
            return Task.FromResult(RevokeResult.Fail("refresh_token_not_found"));
        }

        if (rec.TenantId != tenantId || rec.OurSubject != ourSubject)
        {
            return Task.FromResult(RevokeResult.Fail("forbidden"));
        }

        _refresh[tokenHash] = rec with { Revoked = true };
        _ = _sessions.TerminateSessionAsync(tenantId, rec.SessionId, _time.GetUtcNow(), reason: "refresh_revoke", cancellationToken)
            .GetAwaiter()
            .GetResult();
        return Task.FromResult(RevokeResult.Success());
    }

    public Task<int> RevokeAllAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        _ = _sessions.TerminateAllAsync(tenantId, ourSubject, _time.GetUtcNow(), reason: "revoke_all", cancellationToken)
            .GetAwaiter()
            .GetResult();
        var count = 0;
        foreach (var (token, rec) in _refresh)
        {
            if (rec.TenantId == tenantId && rec.OurSubject == ourSubject && !rec.Revoked)
            {
                _refresh[token] = rec with { Revoked = true };
                count++;
            }
        }

        return Task.FromResult(count);
    }

    private string HashRefreshToken(string refreshToken)
    {
        var opts = _refreshHashing.CurrentValue;
        var bytes = Encoding.UTF8.GetBytes(refreshToken);

        if (!string.IsNullOrWhiteSpace(opts.Pepper))
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(opts.Pepper));
            var mac = hmac.ComputeHash(bytes);
            return Base64Url.Encode(mac);
        }

        var hash = SHA256.HashData(bytes);
        return Base64Url.Encode(hash);
    }


    private string CreateAccessToken(
        JwtOptions opts,
        Guid tenantId,
        Guid ourSubject,
        string jti,
        Guid sessionId,
        IReadOnlyList<string>? roles,
        IReadOnlyList<string>? scopes)
    {
        var now = _time.GetUtcNow();
        var exp = now.AddMinutes(Math.Max(1, opts.AccessTokenMinutes));

        var alg = string.IsNullOrWhiteSpace(opts.SigningAlgorithm) ? _keys.Algorithm : opts.SigningAlgorithm;
        var kid = !string.IsNullOrWhiteSpace(opts.Kid) ? opts.Kid : _keys.Kid;

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
            // Keep current payload format (array). Authorization projection will normalize.
            payload[SecurityClaimTypes.Scopes] = scopes;

            // Compat: OAuth 'scope' (space-delimited)
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

        // Legacy fallback: only accept when both alg and kid match.
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
}
