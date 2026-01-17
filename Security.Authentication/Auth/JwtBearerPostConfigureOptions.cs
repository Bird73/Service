namespace Birdsoft.Security.Authentication.Auth;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Authentication.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;

public sealed class BirdsoftJwtBearerPostConfigureOptions : IPostConfigureOptions<JwtBearerOptions>
{
    private readonly IOptionsMonitor<JwtOptions> _jwtOptions;
    private readonly IOptionsMonitor<SecurityEnvironmentOptions> _envOptions;
    private readonly IOptionsMonitor<SecuritySafetyOptions> _safetyOptions;
    private readonly IHostEnvironment _hostEnvironment;
    private readonly IJwtKeyProvider _keys;
    private readonly IServiceScopeFactory _scopeFactory;

    public BirdsoftJwtBearerPostConfigureOptions(
        IOptionsMonitor<JwtOptions> jwtOptions,
        IOptionsMonitor<SecurityEnvironmentOptions> envOptions,
        IOptionsMonitor<SecuritySafetyOptions> safetyOptions,
        IHostEnvironment hostEnvironment,
        IJwtKeyProvider keys,
        IServiceScopeFactory scopeFactory)
    {
        _jwtOptions = jwtOptions;
        _envOptions = envOptions;
        _safetyOptions = safetyOptions;
        _hostEnvironment = hostEnvironment;
        _keys = keys;
        _scopeFactory = scopeFactory;
    }

    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        options.MapInboundClaims = false;

        // NOTE: key rotation must work without restart. Use IssuerSigningKeyResolver to resolve keys at validation time.
        IEnumerable<SecurityKey> ResolveKeys(Guid? tenantId, string? kid, string? alg)
        {
            // Spec: access tokens must include kid; missing kid must fail validation.
            if (string.IsNullOrWhiteSpace(kid))
            {
                return Array.Empty<SecurityKey>();
            }

            var jwt = _jwtOptions.CurrentValue;
            var safety = _safetyOptions.CurrentValue;
            var effective = tenantId.HasValue ? JwtTenantResolution.Resolve(jwt, tenantId.Value) : JwtTenantResolution.Resolve(jwt, Guid.Empty);
            var ring = (safety.EnforceTenantJwtIsolation && jwt.Tenants is { Length: > 0 } && tenantId.HasValue)
                ? effective.KeyRing
                : jwt.KeyRing;

            var keys = new List<SecurityKey>();

            if (ring?.Keys is { Length: > 0 })
            {
                foreach (var k in ring.Keys)
                {
                    if (k.Status == JwtKeyStatus.Disabled)
                    {
                        continue;
                    }

                    if (!string.Equals(k.Kid, kid, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    var kAlg = string.IsNullOrWhiteSpace(k.Algorithm) ? "RS256" : k.Algorithm.Trim();
                    if (!string.IsNullOrWhiteSpace(alg) && !string.Equals(kAlg, alg, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (kAlg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
                    {
                        var rsa = TryLoadRsa(k.PublicKeyPem) ?? TryLoadRsa(k.PrivateKeyPem);
                        if (rsa is not null)
                        {
                            keys.Add(new RsaSecurityKey(rsa) { KeyId = k.Kid });
                        }

                        continue;
                    }

                    if (kAlg.StartsWith("HS", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(k.SymmetricKey))
                    {
                        keys.Add(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(k.SymmetricKey)) { KeyId = k.Kid });
                    }
                }
            }

            // Back-compat: include legacy provider key
            if (keys.Count == 0)
            {
                // Commercial governance: DB-backed signing keys (active + inactive) for verification.
                using (var scope = _scopeFactory.CreateScope())
                {
                    var store = scope.ServiceProvider.GetService<IJwtSigningKeyStore>();
                    if (store is not null && store.HasAnyAsync().GetAwaiter().GetResult())
                    {
                        var mats = store.GetVerificationKeysAsync().GetAwaiter().GetResult();
                        foreach (var m in mats)
                        {
                            if (!string.Equals(m.Kid, kid, StringComparison.Ordinal))
                            {
                                continue;
                            }

                            var mAlg = string.IsNullOrWhiteSpace(m.Algorithm) ? "RS256" : m.Algorithm.Trim();
                            if (!string.IsNullOrWhiteSpace(alg) && !string.Equals(mAlg, alg, StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }

                            if (mAlg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
                            {
                                var rsa = TryLoadRsa(m.PublicKeyPem);
                                if (rsa is not null)
                                {
                                    keys.Add(new RsaSecurityKey(rsa) { KeyId = m.Kid });
                                }

                                continue;
                            }

                            if (mAlg.StartsWith("HS", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(m.SymmetricKey))
                            {
                                keys.Add(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(m.SymmetricKey)) { KeyId = m.Kid });
                            }
                        }
                    }
                }
            }

            if (keys.Count == 0)
            {
                if (!string.Equals(kid, _keys.Kid, StringComparison.Ordinal))
                {
                    return Array.Empty<SecurityKey>();
                }

                if (_keys.Algorithm.Equals("RS256", StringComparison.OrdinalIgnoreCase))
                {
                    var rsa = _keys.GetRsaPublicKey();
                    if (rsa is not null)
                    {
                        keys.Add(new RsaSecurityKey(rsa) { KeyId = _keys.Kid });
                    }
                }
                else
                {
                    var keyBytes = _keys.GetSymmetricKeyBytes();
                    if (keyBytes is not null && keyBytes.Length > 0)
                    {
                        keys.Add(new SymmetricSecurityKey(keyBytes) { KeyId = _keys.Kid });
                    }
                }
            }

            return keys;
        }

        bool TryGetTenantIdFromToken(SecurityToken? securityToken, out Guid tenantId)
        {
            tenantId = default;

            string? raw = securityToken switch
            {
                System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwt => jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, SecurityClaimTypes.TenantId, StringComparison.Ordinal))?.Value,
                JsonWebToken j => j.Claims.FirstOrDefault(c => string.Equals(c.Type, SecurityClaimTypes.TenantId, StringComparison.Ordinal))?.Value,
                _ => null,
            };

            return Guid.TryParse(raw, out tenantId);
        }

        static string? TryGetAlgFromToken(SecurityToken? securityToken)
            => securityToken switch
            {
                System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwt => jwt.Header?.Alg,
                JsonWebToken j => j.Alg,
                _ => null,
            };

        bool ShouldValidateIssuer(JwtOptions jwt)
            => !string.IsNullOrWhiteSpace(jwt.Issuer) || (jwt.Tenants?.Any(t => !string.IsNullOrWhiteSpace(t.Issuer)) ?? false);

        bool ShouldValidateAudience(JwtOptions jwt)
            => !string.IsNullOrWhiteSpace(jwt.Audience) || (jwt.Tenants?.Any(t => !string.IsNullOrWhiteSpace(t.Audience)) ?? false);

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
            {
                var alg = TryGetAlgFromToken(securityToken);
                return ResolveKeys(TryGetTenantIdFromToken(securityToken, out var tid) ? tid : null, kid, alg).ToArray();
            },
            RequireSignedTokens = true,

            ValidateIssuer = ShouldValidateIssuer(_jwtOptions.CurrentValue),
            IssuerValidator = (issuer, securityToken, parameters) =>
            {
                var jwt = _jwtOptions.CurrentValue;
                var env = _envOptions.CurrentValue;

                // If we can't resolve tenant, issuer is invalid.
                if (!TryGetTenantIdFromToken(securityToken, out var tenantId))
                {
                    throw new SecurityTokenInvalidIssuerException("missing_tenant");
                }

                var eff = JwtTenantResolution.Resolve(jwt, tenantId);
                var legacy = eff.Issuer;
                var envScoped = JwtTenantResolution.ApplyEnvironmentSuffix(legacy, env);
                if (string.Equals(issuer, legacy, StringComparison.Ordinal) || string.Equals(issuer, envScoped, StringComparison.Ordinal))
                {
                    return issuer;
                }

                throw new SecurityTokenInvalidIssuerException("invalid_issuer");
            },

            ValidateAudience = ShouldValidateAudience(_jwtOptions.CurrentValue),
            AudienceValidator = (audiences, securityToken, parameters) =>
            {
                var jwt = _jwtOptions.CurrentValue;
                var env = _envOptions.CurrentValue;

                if (!TryGetTenantIdFromToken(securityToken, out var tenantId))
                {
                    return false;
                }

                var eff = JwtTenantResolution.Resolve(jwt, tenantId);
                var legacy = eff.Audience;
                var envScoped = JwtTenantResolution.ApplyEnvironmentSuffix(legacy, env);
                return audiences.Any(a => string.Equals(a, legacy, StringComparison.Ordinal) || string.Equals(a, envScoped, StringComparison.Ordinal));
            },

            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(Math.Max(0, _jwtOptions.CurrentValue.ClockSkewSeconds)),

            NameClaimType = "sub",
            RoleClaimType = "roles",
        };

        var prior = options.Events?.OnTokenValidated;
        options.Events ??= new JwtBearerEvents();
        options.Events.OnTokenValidated = async context =>
        {
            if (prior is not null)
            {
                await prior(context);
                if (context.Result?.Succeeded == false)
                {
                    return;
                }
            }

            var principal = context.Principal;
            if (principal is null)
            {
                context.Fail("invalid_token");
                return;
            }

            // V18 freeze: APIs must only accept access tokens.
            var tokenType = principal.FindFirst(SecurityClaimTypes.TokenType)?.Value;
            if (!string.Equals(tokenType, "access", StringComparison.OrdinalIgnoreCase))
            {
                context.Fail("invalid_token_type");
                return;
            }

            // Environment isolation (runtime): require env claim match when safety enabled or outside Development.
            var safety = _safetyOptions.CurrentValue;
            var enforceEnv = safety.Enabled || !_hostEnvironment.IsDevelopment();
            if (enforceEnv)
            {
                var env = _envOptions.CurrentValue;
                if (string.IsNullOrWhiteSpace(env.EnvironmentId))
                {
                    context.Fail("invalid_environment");
                    return;
                }

                var tokenEnv = principal.FindFirst(TokenConstants.EnvironmentIdClaim)?.Value;
                if (!string.Equals(tokenEnv, env.EnvironmentId, StringComparison.Ordinal))
                {
                    context.Fail("env_mismatch");
                    return;
                }
            }

            var tenantRaw = principal.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TenantId)?.Value;
            var subjectRaw = principal.FindFirst("sub")?.Value;
            var sessionRaw = principal.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.SessionId)?.Value;

            if (!Guid.TryParse(tenantRaw, out var tenantId) || !Guid.TryParse(subjectRaw, out var ourSubject))
            {
                context.Fail("invalid_token");
                return;
            }

            if (Guid.TryParse(sessionRaw, out var sessionId))
            {
                var sessions = context.HttpContext.RequestServices.GetService<ISessionStore>();
                if (sessions is not null)
                {
                    var active = await sessions.IsSessionActiveAsync(tenantId, sessionId, context.HttpContext.RequestAborted);
                    if (!active)
                    {
                        context.Fail("session_terminated");
                        return;
                    }
                }
            }

            var tenantTvRaw = principal.FindFirst(SecurityClaimTypes.TenantTokenVersion)?.Value;
            var subjectTvRaw = principal.FindFirst(SecurityClaimTypes.SubjectTokenVersion)?.Value;
            var hasAnyTokenVersionClaim = !string.IsNullOrWhiteSpace(tenantTvRaw) || !string.IsNullOrWhiteSpace(subjectTvRaw);

            var tokenTenantTv = 0;
            var tokenSubjectTv = 0;
            if (hasAnyTokenVersionClaim)
            {
                if (!int.TryParse(tenantTvRaw, out tokenTenantTv) || tokenTenantTv < 0)
                {
                    context.Fail("tenant_token_version_invalid");
                    return;
                }

                if (!int.TryParse(subjectTvRaw, out tokenSubjectTv) || tokenSubjectTv < 0)
                {
                    context.Fail("subject_token_version_invalid");
                    return;
                }
            }

            var tenants = context.HttpContext.RequestServices.GetService<ITenantRepository>();
            var subjects = context.HttpContext.RequestServices.GetService<ISubjectRepository>();
            if (tenants is not null)
            {
                var tenant = await tenants.FindAsync(tenantId, context.HttpContext.RequestAborted);
                if (tenant is null || tenant.Status != Birdsoft.Security.Abstractions.Models.TenantStatus.Active)
                {
                    context.Fail("tenant_not_active");
                    return;
                }

                if (hasAnyTokenVersionClaim && tenant.TokenVersion != tokenTenantTv)
                {
                    context.Fail(AuthErrorCodes.TokenVersionMismatch);
                    return;
                }

                if (tenant.TokenVersion != tokenTenantTv)
                {
                    context.Fail(AuthErrorCodes.TokenVersionMismatch);
                    return;
                }
            }

            if (subjects is not null)
            {
                var subject = await subjects.FindAsync(tenantId, ourSubject, context.HttpContext.RequestAborted);
                if (subject is null || subject.Status != Birdsoft.Security.Abstractions.Models.UserStatus.Active)
                {
                    context.Fail("user_not_active");
                    return;
                }

                if (hasAnyTokenVersionClaim && subject.TokenVersion != tokenSubjectTv)
                {
                    context.Fail(AuthErrorCodes.TokenVersionMismatch);
                    return;
                }

                if (subject.TokenVersion != tokenSubjectTv)
                {
                    context.Fail(AuthErrorCodes.TokenVersionMismatch);
                    return;
                }
            }
        };
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
}
