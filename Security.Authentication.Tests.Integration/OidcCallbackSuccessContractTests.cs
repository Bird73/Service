namespace Birdsoft.Security.Authentication.Tests.Integration;

using Birdsoft.Security.Abstractions.Contracts.Auth;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

public sealed class OidcCallbackSuccessContractTests
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

    private static async Task WithTempDbAsync(Func<AuthenticationApiFactory, HttpClient, Task> run)
    {
        var dbPath = CreateTempSqliteDbPath();
        AuthenticationApiFactory? factory = null;
        HttpClient? client = null;

        try
        {
            factory = CreateEfFactory(dbPath);
            client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                // Avoid UseHttpsRedirection-triggered redirects that drop Authorization headers.
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
            });
            await run(factory, client);
        }
        finally
        {
            client?.Dispose();
            factory?.Dispose();
            TryDeleteFile(dbPath);
        }
    }

    private static string CreateTempSqliteDbPath()
    {
        var dir = Path.Combine(Path.GetTempPath(), "Birdsoft.Security.Authentication.Tests");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, $"security-{Guid.NewGuid():N}.db");
    }

    private static AuthenticationApiFactory CreateEfFactory(string dbPath)
    {
        var cs = $"Data Source={dbPath}";
        return new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            SecurityDbConnectionString = cs,
            EnableTestEndpoints = true,
        });
    }

    private static async Task EnsureDbCreatedAsync(AuthenticationApiFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
        await db.Database.EnsureCreatedAsync();
    }

    private static async Task SeedProviderAsync(AuthenticationApiFactory factory, Guid tenantId, string provider, bool enabled, string? issuer = null)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();

        var entity = await db.OidcProviders.FirstOrDefaultAsync(x => x.TenantId == tenantId && x.Provider == provider);
        if (entity is null)
        {
            entity = new OidcProviderConfigEntity
            {
                TenantId = tenantId,
                Provider = provider,
                Enabled = enabled,
                Authority = issuer,
                Issuer = issuer,
                ClientId = "client",
                ClientSecret = "secret",
                CallbackPath = $"/api/v1/auth/oidc/{provider}/callback",
                ScopesJson = "[\"openid\",\"profile\",\"email\"]",
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            };
            db.OidcProviders.Add(entity);
        }
        else
        {
            entity.Enabled = enabled;
            entity.Issuer = issuer;
            entity.Authority = issuer;
            entity.UpdatedAt = DateTimeOffset.UtcNow;
        }

        await db.SaveChangesAsync();
    }

    private static async Task<string> CreateStateAsync(AuthenticationApiFactory factory, Guid tenantId, string provider, string codeVerifier, string nonce)
    {
        using var scope = factory.Services.CreateScope();
        var authState = scope.ServiceProvider.GetRequiredService<IAuthStateService>();
        var stateInfo = await authState.CreateStateAsync(tenantId);
        await authState.TryAttachOidcContextAsync(stateInfo.State, provider, codeVerifier, nonce);
        return stateInfo.State;
    }

    private static Task<HttpResponseMessage> GetCallbackAsync(HttpClient client, Guid tenantId, string provider, string code, string state)
    {
        var url = $"/api/v1/auth/oidc/{Uri.EscapeDataString(provider)}/callback?code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(state)}";
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Add("X-Tenant-Id", tenantId.ToString());
        return client.SendAsync(req);
    }

    private static string ReadSub(string accessToken)
    {
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);
        return jwt.Claims.First(c => string.Equals(c.Type, "sub", StringComparison.Ordinal)).Value;
    }

    [Fact]
    public async Task OidcCallback_Success_Returns_200_And_Issued_AccessToken_Can_Call_ProtectedEndpoint()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            await SeedProviderAsync(factory, tenantId, provider: "stub", enabled: true, issuer: "https://issuer.test");

            var state = await CreateStateAsync(factory, tenantId, provider: "stub", codeVerifier: "cv", nonce: "nonce");

            var res = await GetCallbackAsync(client, tenantId, provider: "stub", code: "external-sub-1", state);
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(body);
            Assert.True(body!.Success);
            Assert.NotNull(body.Data);
            Assert.NotNull(body.Data!.Tokens);
            Assert.False(string.IsNullOrWhiteSpace(body.Data.Tokens!.AccessToken));

            using var protectedReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/test/protected");
            protectedReq.Headers.Add("X-Tenant-Id", tenantId.ToString());
            protectedReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", body.Data.Tokens.AccessToken);

            var protectedRes = await client.SendAsync(protectedReq);
            Assert.Equal(HttpStatusCode.OK, protectedRes.StatusCode);
        });
    }

    [Fact]
    public async Task OidcCallback_RepeatLogin_Reuses_Subject_And_DoesNotDuplicate_ExternalIdentity_Mapping()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            await SeedProviderAsync(factory, tenantId, provider: "stub", enabled: true, issuer: "https://issuer.test");

            var state1 = await CreateStateAsync(factory, tenantId, provider: "stub", codeVerifier: "cv", nonce: "nonce");
            var res1 = await GetCallbackAsync(client, tenantId, provider: "stub", code: "external-sub-1", state1);
            Assert.Equal(HttpStatusCode.OK, res1.StatusCode);

            var body1 = await res1.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(body1);
            Assert.True(body1!.Success);
            Assert.NotNull(body1.Data?.Tokens);

            var state2 = await CreateStateAsync(factory, tenantId, provider: "stub", codeVerifier: "cv", nonce: "nonce");
            var res2 = await GetCallbackAsync(client, tenantId, provider: "stub", code: "external-sub-1", state2);
            Assert.Equal(HttpStatusCode.OK, res2.StatusCode);

            var body2 = await res2.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(body2);
            Assert.True(body2!.Success);
            Assert.NotNull(body2.Data?.Tokens);

            var sub1 = ReadSub(body1.Data!.Tokens!.AccessToken);
            var sub2 = ReadSub(body2.Data!.Tokens!.AccessToken);
            Assert.Equal(sub1, sub2);

            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();

            var mappingCount = await db.ExternalIdentities.AsNoTracking().CountAsync(x => x.TenantId == tenantId && x.Provider == "stub" && x.ProviderSub == "external-sub-1");
            Assert.Equal(1, mappingCount);
        });
    }

    [Fact]
    public async Task OidcCallback_SameExternalIdentityAcrossTenants_Produces_Different_Subjects_And_Is_TenantScoped()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            await EnsureDbCreatedAsync(factory);

            var tenantA = Guid.NewGuid();
            var tenantB = Guid.NewGuid();
            await SeedProviderAsync(factory, tenantA, provider: "stub", enabled: true, issuer: "https://issuer.test");
            await SeedProviderAsync(factory, tenantB, provider: "stub", enabled: true, issuer: "https://issuer.test");

            var stateA = await CreateStateAsync(factory, tenantA, provider: "stub", codeVerifier: "cv", nonce: "nonce");
            var stateB = await CreateStateAsync(factory, tenantB, provider: "stub", codeVerifier: "cv", nonce: "nonce");

            var resA = await GetCallbackAsync(client, tenantA, provider: "stub", code: "external-sub-1", stateA);
            var resB = await GetCallbackAsync(client, tenantB, provider: "stub", code: "external-sub-1", stateB);
            Assert.Equal(HttpStatusCode.OK, resA.StatusCode);
            Assert.Equal(HttpStatusCode.OK, resB.StatusCode);

            var bodyA = await resA.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            var bodyB = await resB.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(bodyA);
            Assert.NotNull(bodyB);
            Assert.True(bodyA!.Success);
            Assert.True(bodyB!.Success);
            Assert.NotNull(bodyA.Data?.Tokens);
            Assert.NotNull(bodyB.Data?.Tokens);

            var subA = ReadSub(bodyA.Data!.Tokens!.AccessToken);
            var subB = ReadSub(bodyB.Data!.Tokens!.AccessToken);
            Assert.NotEqual(subA, subB);

            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();

            var count = await db.ExternalIdentities.AsNoTracking().CountAsync(x => x.Provider == "stub" && x.ProviderSub == "external-sub-1");
            Assert.Equal(2, count);
        });
    }

    [Fact]
    public async Task OidcCallback_SameProviderSub_WithDifferentIssuer_DoesNotReuseMapping()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            await SeedProviderAsync(factory, tenantId, provider: "stub", enabled: true, issuer: "https://issuer-a.test");

            var stateA = await CreateStateAsync(factory, tenantId, provider: "stub", codeVerifier: "cv", nonce: "nonce");
            var resA = await GetCallbackAsync(client, tenantId, provider: "stub", code: "external-sub-1", stateA);
            Assert.Equal(HttpStatusCode.OK, resA.StatusCode);

            var bodyA = await resA.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(bodyA);
            Assert.True(bodyA!.Success);
            var subA = ReadSub(bodyA.Data!.Tokens!.AccessToken);

            // Change issuer for the same provider and re-login with the same providerSub.
            await SeedProviderAsync(factory, tenantId, provider: "stub", enabled: true, issuer: "https://issuer-b.test");

            var stateB = await CreateStateAsync(factory, tenantId, provider: "stub", codeVerifier: "cv", nonce: "nonce");
            var resB = await GetCallbackAsync(client, tenantId, provider: "stub", code: "external-sub-1", stateB);
            Assert.Equal(HttpStatusCode.OK, resB.StatusCode);

            var bodyB = await resB.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
            Assert.NotNull(bodyB);
            Assert.True(bodyB!.Success);
            var subB = ReadSub(bodyB.Data!.Tokens!.AccessToken);

            Assert.NotEqual(subA, subB);

            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();

            var issuerA = "https://issuer-a.test";
            var issuerB = "https://issuer-b.test";

            var count = await db.ExternalIdentities.AsNoTracking()
                .CountAsync(x => x.TenantId == tenantId && x.Provider == "stub" && x.ProviderSub == "external-sub-1");
            Assert.Equal(2, count);

            var mappingA = await db.ExternalIdentities.AsNoTracking()
                .FirstOrDefaultAsync(x => x.TenantId == tenantId && x.Provider == "stub" && x.Issuer == issuerA && x.ProviderSub == "external-sub-1");
            var mappingB = await db.ExternalIdentities.AsNoTracking()
                .FirstOrDefaultAsync(x => x.TenantId == tenantId && x.Provider == "stub" && x.Issuer == issuerB && x.ProviderSub == "external-sub-1");

            Assert.NotNull(mappingA);
            Assert.NotNull(mappingB);
            Assert.NotEqual(mappingA!.OurSubject, mappingB!.OurSubject);
        });
    }
}
