namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Contracts.Common;
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

public sealed class JwtNegativeValidationIntegrationTests
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

    private static string IssueSignedToken(IEnumerable<Claim> claims)
    {
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

    private static string TamperPayload(string jwt)
    {
        var parts = jwt.Split('.');
        Assert.True(parts.Length >= 3);

        var header = parts[0];
        var signature = parts[2];

        // Replace payload with a different JSON object (do not re-sign).
        var newPayloadJson = "{\"sub\":\"00000000-0000-0000-0000-000000000000\"}";
        var newPayload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(newPayloadJson));

        return string.Join('.', header, newPayload, signature);
    }

    private static string CreateAlgNoneToken(Guid tenantId, Guid ourSubject)
    {
        var headerJson = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
        var payloadJson = "{" +
            "\"iss\":\"https://security.authz.test\"," +
            "\"aud\":\"service\"," +
            $"\"sub\":\"{ourSubject}\"," +
            $"\"tenant_id\":\"{tenantId}\"," +
            $"\"nbf\":{DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds()}," +
            $"\"exp\":{DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds()}" +
            "}";

        var header = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(headerJson));
        var payload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson));

        // alg=none unsigned token.
        return $"{header}.{payload}.";
    }

    private static async Task<(HttpStatusCode Status, ApiResponse<object>? Body)> CallTenantPermissionsAsync(HttpClient client, string token)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/tenant/permissions");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var res = await client.SendAsync(req);
        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        return (res.StatusCode, body);
    }

    [Fact]
    public async Task Jwt_When_MissingTenantIdClaim_Returns_401_InvalidToken()
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

            var token = IssueSignedToken(new[]
            {
                new Claim("sub", ourSubject.ToString()),
                // intentionally no tenant_id
            });

            var (status, body) = await CallTenantPermissionsAsync(client, token);
            Assert.Equal(HttpStatusCode.Unauthorized, status);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_token", body.Error!.Code);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    [Fact]
    public async Task Jwt_When_TenantIdNotGuid_Returns_401_InvalidToken()
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

            var token = IssueSignedToken(new[]
            {
                new Claim("sub", ourSubject.ToString()),
                new Claim(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TenantId, "not-a-guid"),
            });

            var (status, body) = await CallTenantPermissionsAsync(client, token);
            Assert.Equal(HttpStatusCode.Unauthorized, status);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_token", body.Error!.Code);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    [Fact]
    public async Task Jwt_When_PayloadTamperedWithoutResign_Returns_401_InvalidToken()
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

            var good = IssueSignedToken(new[]
            {
                new Claim("sub", ourSubject.ToString()),
                new Claim(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TenantId, tenantId.ToString()),
                new Claim(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scope, "security.admin"),
            });

            var tampered = TamperPayload(good);

            var (status, body) = await CallTenantPermissionsAsync(client, tampered);
            Assert.Equal(HttpStatusCode.Unauthorized, status);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_token", body.Error!.Code);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    [Fact]
    public async Task Jwt_When_AlgNone_Returns_401_InvalidToken()
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

            var token = CreateAlgNoneToken(tenantId, ourSubject);

            var (status, body) = await CallTenantPermissionsAsync(client, token);
            Assert.Equal(HttpStatusCode.Unauthorized, status);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_token", body.Error!.Code);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }
}
