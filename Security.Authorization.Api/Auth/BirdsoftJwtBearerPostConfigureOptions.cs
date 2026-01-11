namespace Birdsoft.Security.Authorization.Api.Auth;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Stores;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

public sealed class BirdsoftJwtBearerPostConfigureOptions : IPostConfigureOptions<JwtBearerOptions>
{
    private readonly IOptionsMonitor<JwtOptions> _jwtOptions;
    private readonly IJwtKeyProvider _keys;

    public BirdsoftJwtBearerPostConfigureOptions(IOptionsMonitor<JwtOptions> jwtOptions, IJwtKeyProvider keys)
    {
        _jwtOptions = jwtOptions;
        _keys = keys;
    }

    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        var jwt = _jwtOptions.CurrentValue;

        options.MapInboundClaims = false;

        SecurityKey? signingKey = null;
        if (_keys.Algorithm.Equals("RS256", StringComparison.OrdinalIgnoreCase))
        {
            var rsa = _keys.GetRsaPublicKey();
            if (rsa is not null)
            {
                signingKey = new RsaSecurityKey(rsa) { KeyId = _keys.Kid };
            }
        }
        else
        {
            var keyBytes = _keys.GetSymmetricKeyBytes();
            if (keyBytes is not null && keyBytes.Length > 0)
            {
                signingKey = new SymmetricSecurityKey(keyBytes) { KeyId = _keys.Kid };
            }
        }

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = signingKey is not null,
            IssuerSigningKey = signingKey,
            RequireSignedTokens = true,

            ValidateIssuer = !string.IsNullOrWhiteSpace(jwt.Issuer),
            ValidIssuer = jwt.Issuer,

            ValidateAudience = !string.IsNullOrWhiteSpace(jwt.Audience),
            ValidAudience = jwt.Audience,

            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(Math.Max(0, jwt.ClockSkewSeconds)),

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
            }

            if (subjects is not null)
            {
                var subject = await subjects.FindAsync(tenantId, ourSubject, context.HttpContext.RequestAborted);
                if (subject is null || subject.Status != Birdsoft.Security.Abstractions.Models.UserStatus.Active)
                {
                    context.Fail("user_not_active");
                    return;
                }
            }
        };
    }
}
