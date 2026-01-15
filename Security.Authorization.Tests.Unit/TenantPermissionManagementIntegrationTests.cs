namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Authorization.Api;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

public sealed class TenantPermissionManagementIntegrationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static string CreateTempSqliteDbPath()
    {
        var dir = Path.Combine(Path.GetTempPath(), "Birdsoft.Security.Authorization.Tests");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, $"security-{Guid.NewGuid():N}.db");
    }

    private static AuthorizationApiFactory CreateEfFactory(string dbPath)
    {
        var cs = $"Data Source={dbPath}";
        return new AuthorizationApiFactory(new AuthorizationApiFactory.Overrides
        {
            SecurityDbConnectionString = cs,
            SafetyEnabled = false,
            JwtSigningAlgorithm = "HS256",
            JwtSigningKey = "integration-test-signing-key-12345678901234567890",
            JwtIssuer = "https://security.authz.test",
            JwtAudience = "service",
        });
    }

    private static async Task EnsureDbCreatedAsync(AuthorizationApiFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
        await db.Database.EnsureCreatedAsync();
    }

    private static string IssueTenantAdminToken(
        string issuer,
        string audience,
        string symmetricKey,
        Guid tenantId,
        Guid ourSubject,
        DateTimeOffset? now = null)
    {
        var clock = now ?? DateTimeOffset.UtcNow;

        var claims = new List<Claim>
        {
            new Claim("sub", ourSubject.ToString()),
            new Claim(SecurityClaimTypes.TenantId, tenantId.ToString()),
            new Claim(SecurityClaimTypes.Scope, "security.admin"),
        };

        var creds = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(symmetricKey)),
            SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: clock.UtcDateTime.AddMinutes(-1),
            expires: clock.UtcDateTime.AddMinutes(10),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static async Task SeedAsync(AuthorizationApiFactory factory, Guid tenantId, Guid ourSubject)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();

        var now = DateTimeOffset.UtcNow;

        db.Tenants.Add(new TenantEntity
        {
            TenantId = tenantId,
            Name = "test-tenant",
            Status = 0, // Active
            TokenVersion = 1,
            CreatedAt = now,
            UpdatedAt = now,
        });

        db.Subjects.Add(new SubjectEntity
        {
            TenantId = tenantId,
            OurSubject = ourSubject,
            DisplayName = "test",
            Status = 0, // Active
            TokenVersion = 1,
            CreatedAt = now,
            UpdatedAt = now,
        });

        db.Products.Add(new ProductEntity
        {
            ProductId = Guid.NewGuid(),
            ProductKey = "orders",
            DisplayName = "Orders",
            Description = null,
            Status = 1, // Enabled
            CreatedAt = now,
            UpdatedAt = now,
        });

        db.Permissions.Add(new PermissionEntity
        {
            PermId = Guid.NewGuid(),
            PermKey = "orders:read",
            ProductKey = "orders",
            Description = null,
            CreatedAt = now,
            UpdatedAt = now,
        });

        db.TenantProducts.Add(new TenantProductEntity
        {
            TenantId = tenantId,
            ProductKey = "orders",
            Status = 1, // Enabled
            StartAt = now.AddMinutes(-5),
            EndAt = null,
            PlanJson = "{\"plan\":\"pro\"}",
            CreatedAt = now,
            UpdatedAt = now,
        });

        await db.SaveChangesAsync();
    }

    private static async Task DisableEntitlementAsync(AuthorizationApiFactory factory, Guid tenantId, string productKey)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();

        var row = await db.TenantProducts.FirstAsync(x => x.TenantId == tenantId && x.ProductKey == productKey);
        row.Status = 0; // Disabled
        row.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task DisableEntitlement_DeniesTenantPermissionApisImmediately_WithSameToken()
    {
        var dbPath = CreateTempSqliteDbPath();
        AuthorizationApiFactory? factory = null;
        HttpClient? client = null;

        try
        {
            factory = CreateEfFactory(dbPath);
            client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });

            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            await SeedAsync(factory, tenantId, ourSubject);

            var token = IssueTenantAdminToken(
                issuer: "https://security.authz.test",
                audience: "service",
                symmetricKey: "integration-test-signing-key-12345678901234567890",
                tenantId: tenantId,
                ourSubject: ourSubject);

            async Task<HttpResponseMessage> GetPermissionsAsync()
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/permissions?productKey=orders");
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                return await client!.SendAsync(req);
            }

            async Task<HttpResponseMessage> AddPermissionAsync()
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/tenant/users/{ourSubject}/permissions");
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                req.Content = JsonContent.Create(new { permissionKey = "orders:read", reason = (string?)null }, options: JsonOptions);
                return await client!.SendAsync(req);
            }

            // Enabled: should allow.
            {
                var res = await GetPermissionsAsync();
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            }

            {
                var res = await AddPermissionAsync();
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            }

            // Disable entitlement: should deny immediately with the same token.
            await DisableEntitlementAsync(factory, tenantId, "orders");

            {
                var res = await GetPermissionsAsync();
                Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
                var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
                Assert.NotNull(body);
                Assert.False(body!.Success);
                Assert.Equal("product_not_enabled", body.Error?.Code);
            }

            {
                var res = await AddPermissionAsync();
                Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
                var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
                Assert.NotNull(body);
                Assert.False(body!.Success);
                Assert.Equal("product_not_enabled", body.Error?.Code);
            }
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();

            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }
}
