namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Contracts.Authz;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authorization.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

public sealed class FailClosedInMemoryModeIntegrationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static string IssueTenantToken(Guid tenantId, Guid ourSubject)
    {
        var claims = new List<Claim>
        {
            new("sub", ourSubject.ToString()),
            new(SecurityClaimTypes.TenantId, tenantId.ToString()),
            new(SecurityClaimTypes.TokenType, "access"),
            new(SecurityClaimTypes.TokenPlane, "tenant"),
        };

        var creds = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes("dev-signing-key-123456789012345678901234567890")),
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

    [Fact]
    public async Task NonEfMode_UnknownPermission_AlwaysDenies_With_UnknownPermission_Reason()
    {
        using var factory = new AuthorizationApiFactory(new AuthorizationApiFactory.Overrides
        {
            SecurityDbConnectionString = null,
            SafetyEnabled = false,
        });

        using var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
        });

        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();
        var token = IssueTenantToken(tenantId, ourSubject);

        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/authz/check");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        req.Headers.Add("X-Tenant-Id", tenantId.ToString());
        req.Content = JsonContent.Create(new AuthzCheckRequest(ourSubject, "unknown", "perm", Context: null), options: JsonOptions);

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<AuthzCheckResponse>>(JsonOptions);
        Assert.NotNull(body);
        Assert.True(body!.Success);
        Assert.NotNull(body.Data);
        Assert.False(body.Data!.Allowed);
        Assert.Equal("unknown_permission", body.Data.Reason);
    }

    [Fact]
    public async Task NonEfMode_ProductPermission_WithoutEntitlement_Denies_With_EntitlementReason()
    {
        using var factory = new AuthorizationApiFactory(new AuthorizationApiFactory.Overrides
        {
            SecurityDbConnectionString = null,
            SafetyEnabled = false,
            ExtraConfiguration = new Dictionary<string, string?>
            {
                // Seed a single product-bound permission in the non-EF permission catalog.
                [$"Security:Authorization:PermissionCatalog:0:PermissionKey"] = "orders:read",
                [$"Security:Authorization:PermissionCatalog:0:ProductKey"] = "orders",
            },
        });

        using var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
        });

        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();
        var token = IssueTenantToken(tenantId, ourSubject);

        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/authz/check");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        req.Headers.Add("X-Tenant-Id", tenantId.ToString());
        req.Content = JsonContent.Create(new AuthzCheckRequest(ourSubject, "orders", "read", Context: null), options: JsonOptions);

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<AuthzCheckResponse>>(JsonOptions);
        Assert.NotNull(body);
        Assert.True(body!.Success);
        Assert.NotNull(body.Data);
        Assert.False(body.Data!.Allowed);
        Assert.Equal("entitlement_missing_or_disabled", body.Data.Reason);
    }

    [Fact]
    public void Guardrail_When_AllowAllStoresInjected_And_UnsafeDevModeFalse_FailsFast_OnStartup()
    {
        using var factory = new AuthorizationApiFactory(new AuthorizationApiFactory.Overrides
        {
            SecurityDbConnectionString = null,
            SafetyEnabled = false,
            ExtraConfiguration = new Dictionary<string, string?>
            {
                ["Security:Authorization:UnsafeDevMode"] = "false",
            },
            ConfigureTestServices = services =>
            {
                services.RemoveAll<IPermissionCatalogStore>();
                services.RemoveAll<ITenantEntitlementStore>();
                services.AddSingleton<IPermissionCatalogStore, NullPermissionCatalogStore>();
                services.AddSingleton<ITenantEntitlementStore, AllowAllTenantEntitlementStore>();
            },
        });

        // WebApplicationFactory will throw when the host fails to start.
        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("Unsafe authorization configuration", ex.ToString(), StringComparison.OrdinalIgnoreCase);
    }
}
