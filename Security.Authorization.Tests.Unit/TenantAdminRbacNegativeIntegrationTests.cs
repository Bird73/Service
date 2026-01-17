namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Infrastructure.Logging.Abstractions;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
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

public sealed class TenantAdminRbacNegativeIntegrationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static string CreateTempSqliteDbPath()
    {
        var dir = Path.Combine(Path.GetTempPath(), "Birdsoft.Security.Authorization.Tests");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, $"security-{Guid.NewGuid():N}.db");
    }

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

    private static string IssueTenantTokenWithoutAdminScope(Guid tenantId, Guid ourSubject)
    {
        var claims = new List<Claim>
        {
            new Claim("sub", ourSubject.ToString()),
            new Claim(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TenantId, tenantId.ToString()),
            new Claim(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TokenType, "access"),
            new Claim(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TokenPlane, "tenant"),
            // Intentionally NO security.admin scope/role/perms.
        };

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

    private static async Task EnsureDbCreatedAndSeedActiveTenantSubjectAsync(AuthorizationApiFactory factory, Guid tenantId, Guid ourSubject)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
        await db.Database.EnsureCreatedAsync();

        var now = DateTimeOffset.UtcNow;
        db.Tenants.Add(new TenantEntity { TenantId = tenantId, Name = "t", Status = 0, TokenVersion = 1, CreatedAt = now, UpdatedAt = now });
        db.Subjects.Add(new SubjectEntity { TenantId = tenantId, OurSubject = ourSubject, DisplayName = "u", Status = 0, TokenVersion = 1, CreatedAt = now, UpdatedAt = now });
        await db.SaveChangesAsync();
    }

    private sealed class ThrowingAppLogger<T> : IAppLogger<T>
    {
        public bool IsEnabled(LogLevel level) => true;
        public void Log(LogLevel level, Exception? exception, string messageTemplate, params object?[] args)
            => throw new InvalidOperationException("boom: logger");
    }

    [Fact]
    public async Task TenantPermissions_When_MissingSecurityAdminScope_Returns_403_InsufficientScope()
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

            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            await EnsureDbCreatedAndSeedActiveTenantSubjectAsync(factory, tenantId, ourSubject);

            var token = IssueTenantTokenWithoutAdminScope(tenantId, ourSubject);

            using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/permissions");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("insufficient_scope", body.Error!.Code);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    [Fact]
    public async Task TenantUserPermissionsPost_When_MissingSecurityAdminScope_Returns_403_InsufficientScope()
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

            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            await EnsureDbCreatedAndSeedActiveTenantSubjectAsync(factory, tenantId, ourSubject);

            var token = IssueTenantTokenWithoutAdminScope(tenantId, ourSubject);

            using var req = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/tenant/users/{ourSubject}/permissions");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Content = JsonContent.Create(new { permissionKey = "orders:read", reason = (string?)null }, options: JsonOptions);

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("insufficient_scope", body.Error!.Code);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    [Fact]
    public async Task TenantPermissions_When_LoggerThrows_And_MissingScope_Still_Returns_403_InsufficientScope()
    {
        var dbPath = CreateTempSqliteDbPath();
        AuthorizationApiFactory? baseFactory = null;
        WebApplicationFactory<Program>? factory = null;
        HttpClient? client = null;

        try
        {
            baseFactory = CreateEfFactory(dbPath);
            factory = baseFactory.WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices(services =>
                {
                    services.RemoveAll(typeof(IAppLogger<>));
                    services.AddTransient(typeof(IAppLogger<>), typeof(ThrowingAppLogger<>));
                });
            });

            client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });

            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            await EnsureDbCreatedAndSeedActiveTenantSubjectAsync(baseFactory, tenantId, ourSubject);

            var token = IssueTenantTokenWithoutAdminScope(tenantId, ourSubject);

            using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/permissions");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("insufficient_scope", body.Error!.Code);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            baseFactory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }
}
