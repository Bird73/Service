namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Contracts.Authz;
using Birdsoft.Security.Abstractions.Contracts.Common;
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

public sealed class EntitlementLiveGatingIntegrationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static string? TryReadLastAuthErrorLogLine(string directory)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            {
                return null;
            }

            var latest = new DirectoryInfo(directory)
                .EnumerateFiles("auth-error-*.jsonl", SearchOption.TopDirectoryOnly)
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .FirstOrDefault();

            if (latest is null)
            {
                return null;
            }

            // File is jsonl; read last non-empty line.
            var last = File.ReadLines(latest.FullName)
                .Reverse()
                .FirstOrDefault(l => !string.IsNullOrWhiteSpace(l));

            return last;
        }
        catch
        {
            return null;
        }
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

    private static string IssueTenantToken(
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
            new Claim(SecurityClaimTypes.TokenType, "access"),
            new Claim(SecurityClaimTypes.TokenPlane, "tenant"),
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

        var permId = Guid.NewGuid();
        db.Permissions.Add(new PermissionEntity
        {
            PermId = permId,
            PermKey = "orders:read",
            ProductKey = "orders",
            Description = null,
            CreatedAt = now,
            UpdatedAt = now,
        });

        db.SubjectPermissions.Add(new SubjectPermissionEntity
        {
            TenantId = tenantId,
            OurSubject = ourSubject,
            PermId = permId,
            AssignedAt = now,
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
    public async Task DisableEntitlement_DeniesImmediately_WithSameToken()
    {
        var dbPath = CreateTempSqliteDbPath();
        AuthorizationApiFactory? factory = null;
        HttpClient? client = null;

        try
        {
            factory = CreateEfFactory(dbPath);
            client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
            {
                // Avoid UseHttpsRedirection-triggered redirects that drop Authorization headers.
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });

            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            await SeedAsync(factory, tenantId, ourSubject);

            var token = IssueTenantToken(
                issuer: "https://security.authz.test",
                audience: "service",
                symmetricKey: "integration-test-signing-key-12345678901234567890",
                tenantId: tenantId,
                ourSubject: ourSubject);

            async Task<(HttpStatusCode Status, ApiResponse<AuthzCheckResponse>? Body)> CheckAsync()
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/authz/check");
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                req.Headers.Add("X-Tenant-Id", tenantId.ToString());
                req.Content = JsonContent.Create(new AuthzCheckRequest(ourSubject, "orders", "read", Context: null), options: JsonOptions);

                var res = await client!.SendAsync(req);
                ApiResponse<AuthzCheckResponse>? body = null;
                try
                {
                    body = await res.Content.ReadFromJsonAsync<ApiResponse<AuthzCheckResponse>>(JsonOptions);
                }
                catch
                {
                    // Intentionally ignore; the assertions below will surface status/behavior.
                }

                if (res.StatusCode != HttpStatusCode.OK)
                {
                    var raw = await res.Content.ReadAsStringAsync();
                    var capture = factory!.Services.GetRequiredService<UnhandledExceptionCapture>();
                    var exText = capture.LastException?.ToString();
                    var lastLog = TryReadLastAuthErrorLogLine(factory!.AuthErrorLogRootDirectory);
                    throw new InvalidOperationException(
                        $"Unexpected status {(int)res.StatusCode} {res.StatusCode}. Body={raw}\n" +
                        $"CapturedException={exText}\n" +
                        $"AuthErrorLogRootDirectory={factory!.AuthErrorLogRootDirectory}\n" +
                        $"LastAuthErrorLogLine={lastLog}");
                }
                return (res.StatusCode, body);
            }

            var first = await CheckAsync();
            Assert.Equal(HttpStatusCode.OK, first.Status);
            Assert.NotNull(first.Body);
            Assert.True(first.Body!.Success);
            Assert.NotNull(first.Body.Data);
            Assert.True(first.Body.Data!.Allowed);

            await DisableEntitlementAsync(factory, tenantId, "orders");

            var second = await CheckAsync();
            Assert.Equal(HttpStatusCode.OK, second.Status);
            Assert.NotNull(second.Body);
            Assert.True(second.Body!.Success);
            Assert.NotNull(second.Body.Data);
            Assert.False(second.Body.Data!.Allowed);
            Assert.Equal("entitlement_missing_or_disabled", second.Body.Data.Reason);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }
}
