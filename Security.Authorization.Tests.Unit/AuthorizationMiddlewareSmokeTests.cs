namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Contracts.Common;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

public sealed class AuthorizationMiddlewareSmokeTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static string IssueToken(Guid tenantId, Guid ourSubject, bool includeAdminScope)
    {
        var claims = new List<Claim>
        {
            new Claim("sub", ourSubject.ToString()),
            new Claim(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TenantId, tenantId.ToString()),
            new Claim(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TokenType, "access"),
            new Claim(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TokenPlane, "tenant"),
        };

        if (includeAdminScope)
        {
            claims.Add(new Claim(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scope, "security.admin"));
        }

        var creds = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes("integration-test-signing-key-12345678901234567890")),
            SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: "https://security.authz.test",
            audience: "service",
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(10),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static AuthorizationApiFactory CreateFactory()
        => new AuthorizationApiFactory(new AuthorizationApiFactory.Overrides
        {
            SecurityDbConnectionString = null, // in-memory mode
            SafetyEnabled = false,
            JwtSigningAlgorithm = "HS256",
            JwtSigningKey = "integration-test-signing-key-12345678901234567890",
            JwtIssuer = "https://security.authz.test",
            JwtAudience = "service",
            ExtraConfiguration = new Dictionary<string, string?>
            {
                ["TestEndpoints:Enabled"] = "true",
            },
        });

    [Fact]
    public async Task AdminOnlyEndpoint_When_MissingAdminScope_Returns_403()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
        });

        var token = IssueToken(Guid.NewGuid(), Guid.NewGuid(), includeAdminScope: false);

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/test/admin-only");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.False(body!.Success);
    }

    [Fact]
    public async Task AdminOnlyEndpoint_When_HasAdminScope_Returns_200()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
        });

        var token = IssueToken(Guid.NewGuid(), Guid.NewGuid(), includeAdminScope: true);

        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/test/admin-only");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.True(body!.Success);
    }
}
