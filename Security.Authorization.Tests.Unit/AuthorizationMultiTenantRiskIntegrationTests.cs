namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Contracts.Authz;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Stores;
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

public sealed class AuthorizationMultiTenantRiskIntegrationTests
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

    private static AuthorizationApiFactory CreateEfFactory(string dbPath, AuthorizationApiFactory.Overrides? overrides = null)
    {
        var cs = $"Data Source={dbPath}";
        return new AuthorizationApiFactory(overrides ?? new AuthorizationApiFactory.Overrides
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

    private static string IssueTenantToken(string issuer, string audience, string symmetricKey, Guid tenantId, Guid ourSubject, DateTimeOffset? now = null)
    {
        var clock = now ?? DateTimeOffset.UtcNow;

        var claims = new List<Claim>
        {
            new Claim("sub", ourSubject.ToString()),
            new Claim(SecurityClaimTypes.TenantId, tenantId.ToString()),
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

    private static async Task SeedMultiTenantPermissionsAsync(AuthorizationApiFactory factory, Guid tenantA, Guid subjectA, Guid tenantB, Guid subjectB)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();

        var now = DateTimeOffset.UtcNow;

        db.Tenants.AddRange(
            new TenantEntity { TenantId = tenantA, Name = "A", Status = 0, TokenVersion = 1, CreatedAt = now, UpdatedAt = now },
            new TenantEntity { TenantId = tenantB, Name = "B", Status = 0, TokenVersion = 1, CreatedAt = now, UpdatedAt = now });

        db.Subjects.AddRange(
            new SubjectEntity { TenantId = tenantA, OurSubject = subjectA, DisplayName = "A", Status = 0, TokenVersion = 1, CreatedAt = now, UpdatedAt = now },
            new SubjectEntity { TenantId = tenantB, OurSubject = subjectB, DisplayName = "B", Status = 0, TokenVersion = 1, CreatedAt = now, UpdatedAt = now });

        db.Products.Add(new ProductEntity
        {
            ProductId = Guid.NewGuid(),
            ProductKey = "orders",
            DisplayName = "Orders",
            Description = null,
            Status = 1,
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

        // Grant only to tenant A.
        db.SubjectPermissions.Add(new SubjectPermissionEntity
        {
            TenantId = tenantA,
            OurSubject = subjectA,
            PermId = permId,
            AssignedAt = now,
        });

        db.TenantProducts.AddRange(
            new TenantProductEntity
            {
                TenantId = tenantA,
                ProductKey = "orders",
                Status = 1,
                StartAt = now.AddMinutes(-5),
                EndAt = null,
                PlanJson = null,
                CreatedAt = now,
                UpdatedAt = now,
            },
            new TenantProductEntity
            {
                TenantId = tenantB,
                ProductKey = "orders",
                Status = 1,
                StartAt = now.AddMinutes(-5),
                EndAt = null,
                PlanJson = null,
                CreatedAt = now,
                UpdatedAt = now,
            });

        await db.SaveChangesAsync();
    }

    private sealed class ThrowingAuthEventStore : IAuthEventStore
    {
        public Task AppendAsync(Birdsoft.Security.Abstractions.Models.AuthEvent ev, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("boom: auth event store");

        public Task<IReadOnlyList<Birdsoft.Security.Abstractions.Models.AuthEvent>> QueryAsync(Birdsoft.Security.Abstractions.Models.AuthEventQuery query, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("boom: auth event store");
    }

    [Fact]
    public async Task AuthzCheck_When_HeaderTenantMismatch_Returns_403_TenantMismatch()
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

            var tenantA = Guid.NewGuid();
            var tenantB = Guid.NewGuid();
            var subject = Guid.NewGuid();

            // Seed tenant/subject only for tenantA; mismatch should short-circuit before evaluator anyway.
            await SeedMultiTenantPermissionsAsync(factory, tenantA, subject, tenantB, Guid.NewGuid());

            var token = IssueTenantToken(
                issuer: "https://security.authz.test",
                audience: "service",
                symmetricKey: "integration-test-signing-key-12345678901234567890",
                tenantId: tenantA,
                ourSubject: subject);

            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/authz/check");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Headers.Add("X-Tenant-Id", tenantB.ToString());
            req.Content = JsonContent.Create(new AuthzCheckRequest(subject, "orders", "read", Context: null), options: JsonOptions);

            var res = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal(AuthErrorCodes.TenantMismatch, body.Error!.Code);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    [Fact]
    public async Task AuthzCheck_Permissions_Are_TenantScoped()
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

            var tenantA = Guid.NewGuid();
            var tenantB = Guid.NewGuid();
            var subjectA = Guid.NewGuid();
            var subjectB = Guid.NewGuid();
            await SeedMultiTenantPermissionsAsync(factory, tenantA, subjectA, tenantB, subjectB);

            async Task<bool> CheckAsync(Guid tenantId, Guid ourSubject)
            {
                var token = IssueTenantToken(
                    issuer: "https://security.authz.test",
                    audience: "service",
                    symmetricKey: "integration-test-signing-key-12345678901234567890",
                    tenantId: tenantId,
                    ourSubject: ourSubject);

                using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/authz/check");
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                req.Headers.Add("X-Tenant-Id", tenantId.ToString());
                req.Content = JsonContent.Create(new AuthzCheckRequest(ourSubject, "orders", "read", Context: null), options: JsonOptions);

                var res = await client!.SendAsync(req);
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);

                var body = await res.Content.ReadFromJsonAsync<ApiResponse<AuthzCheckResponse>>(JsonOptions);
                Assert.NotNull(body);
                Assert.True(body!.Success);
                Assert.NotNull(body.Data);
                return body.Data!.Allowed;
            }

            var allowedA = await CheckAsync(tenantA, subjectA);
            var allowedB = await CheckAsync(tenantB, subjectB);

            Assert.True(allowedA);
            Assert.False(allowedB);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    [Fact]
    public async Task AuthzCheck_When_AuditStore_Throws_Still_Returns_200()
    {
        var dbPath = CreateTempSqliteDbPath();
        AuthorizationApiFactory? factory = null;
        HttpClient? client = null;

        try
        {
            factory = CreateEfFactory(dbPath, new AuthorizationApiFactory.Overrides
            {
                SecurityDbConnectionString = $"Data Source={dbPath}",
                AuthEvents = new ThrowingAuthEventStore(),
                SafetyEnabled = false,
                JwtSigningAlgorithm = "HS256",
                JwtSigningKey = "integration-test-signing-key-12345678901234567890",
                JwtIssuer = "https://security.authz.test",
                JwtAudience = "service",
            });

            client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });

            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            var ourSubject = Guid.NewGuid();
            await SeedMultiTenantPermissionsAsync(factory, tenantId, ourSubject, Guid.NewGuid(), Guid.NewGuid());

            var token = IssueTenantToken(
                issuer: "https://security.authz.test",
                audience: "service",
                symmetricKey: "integration-test-signing-key-12345678901234567890",
                tenantId: tenantId,
                ourSubject: ourSubject);

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
