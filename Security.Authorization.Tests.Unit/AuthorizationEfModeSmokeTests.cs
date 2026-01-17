namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Contracts.Authz;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

public sealed class AuthorizationEfModeSmokeTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static void TryDeleteFile(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        for (var i = 0; i < 5; i++)
        {
            try
            {
                File.Delete(path);
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(50);
            }
            catch (UnauthorizedAccessException)
            {
                Thread.Sleep(50);
            }
        }
    }

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
            ExtraConfiguration = new Dictionary<string, string?>
            {
                ["TestEndpoints:Enabled"] = "true",
            },
        });
    }

    private static async Task EnsureDbCreatedAsync(AuthorizationApiFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
        await db.Database.EnsureCreatedAsync();
    }

    private static string IssueTenantToken(
        string issuer,
        string audience,
        string symmetricKey,
        Guid tenantId,
        Guid ourSubject,
        bool includeAdminScope)
    {
        var claims = new List<Claim>
        {
            new Claim("sub", ourSubject.ToString()),
            new Claim(SecurityClaimTypes.TenantId, tenantId.ToString()),
            new Claim(SecurityClaimTypes.TokenType, "access"),
            new Claim(SecurityClaimTypes.TokenPlane, "tenant"),
        };

        if (includeAdminScope)
        {
            claims.Add(new Claim(SecurityClaimTypes.Scope, "security.admin"));
        }

        var creds = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(symmetricKey)),
            SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(10),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static async Task SeedTenantSubjectAndOrdersPermissionAsync(
        AuthorizationApiFactory factory,
        Guid tenantId,
        Guid ourSubject)
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

    private static async Task SeedTenantAndSubjectAsync(
        AuthorizationApiFactory factory,
        Guid tenantId,
        Guid ourSubject)
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

        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task AdminOnlyEndpoint_EfMode_When_MissingAdminScope_Returns_403()
    {
        var dbPath = CreateTempSqliteDbPath();
        AuthorizationApiFactory? factory = null;
        HttpClient? client = null;

        try
        {
            factory = CreateEfFactory(dbPath);
            client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });

            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            await SeedTenantAndSubjectAsync(factory, tenantId, ourSubject);

            var token = IssueTenantToken(
                issuer: "https://security.authz.test",
                audience: "service",
                symmetricKey: "integration-test-signing-key-12345678901234567890",
                tenantId: tenantId,
                ourSubject: ourSubject,
                includeAdminScope: false);

            using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/test/admin-only");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    [Fact]
    public async Task AdminOnlyEndpoint_EfMode_When_HasAdminScope_Returns_200()
    {
        var dbPath = CreateTempSqliteDbPath();
        AuthorizationApiFactory? factory = null;
        HttpClient? client = null;

        try
        {
            factory = CreateEfFactory(dbPath);
            client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });

            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            await SeedTenantAndSubjectAsync(factory, tenantId, ourSubject);

            var token = IssueTenantToken(
                issuer: "https://security.authz.test",
                audience: "service",
                symmetricKey: "integration-test-signing-key-12345678901234567890",
                tenantId: tenantId,
                ourSubject: ourSubject,
                includeAdminScope: true);

            using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/test/admin-only");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.True(body!.Success);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    [Fact]
    public async Task SetSubjectGrants_EfMode_Persists_And_AuthzCheck_Allows()
    {
        var dbPath = CreateTempSqliteDbPath();
        AuthorizationApiFactory? factory = null;
        HttpClient? client = null;

        try
        {
            factory = CreateEfFactory(dbPath);
            client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });

            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            await SeedTenantSubjectAndOrdersPermissionAsync(factory, tenantId, ourSubject);

            using (var scope = factory.Services.CreateScope())
            {
                var admin = scope.ServiceProvider.GetRequiredService<IAuthorizationAdminStore>();
                await admin.SetSubjectGrantsAsync(
                    tenantId,
                    ourSubject,
                    new AuthorizationGrants(
                        Roles: Array.Empty<string>(),
                        Scopes: Array.Empty<string>(),
                        Permissions: new[] { "orders:read" }),
                    reason: "test");
            }

            var token = IssueTenantToken(
                issuer: "https://security.authz.test",
                audience: "service",
                symmetricKey: "integration-test-signing-key-12345678901234567890",
                tenantId: tenantId,
                ourSubject: ourSubject,
                includeAdminScope: false);

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
            Assert.True(body.Data!.Allowed);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }
}
