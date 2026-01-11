namespace Birdsoft.Security.Authentication.Auth;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Authentication.Jwt;
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
    }
}
