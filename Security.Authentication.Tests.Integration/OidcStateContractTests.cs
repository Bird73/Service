namespace Birdsoft.Security.Authentication.Tests.Integration;

using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Identity;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

public sealed class OidcStateContractTests
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
            client = factory.CreateClient();
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

    private static Task<HttpResponseMessage> GetCallbackAsync(HttpClient client, Guid tenantId, string provider, string code, string state)
    {
        var url = $"/api/v1/auth/oidc/{Uri.EscapeDataString(provider)}/callback?code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(state)}";
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Add("X-Tenant-Id", tenantId.ToString());
        return client.SendAsync(req);
    }

    [Fact]
    public async Task State_Is_OneTime_Reused_State_Returns_400_InvalidState()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            await SeedProviderAsync(factory, tenantId, provider: "stub", enabled: true, issuer: "https://issuer.test");

            string state;
            using (var scope = factory.Services.CreateScope())
            {
                var authState = scope.ServiceProvider.GetRequiredService<IAuthStateService>();
                var stateInfo = await authState.CreateStateAsync(tenantId);
                await authState.TryAttachOidcContextAsync(stateInfo.State, codeVerifier: "cv", nonce: "nonce");
                state = stateInfo.State;
            }

            var first = await GetCallbackAsync(client, tenantId, provider: "stub", code: "external-sub-1", state);
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);

            var second = await GetCallbackAsync(client, tenantId, provider: "stub", code: "external-sub-1", state);
            Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);

            var body = await second.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_state", body.Error!.Code);
        });
    }

    [Fact]
    public async Task State_TTL_Expired_Returns_400_InvalidState()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            var expiredState = "expired-state-" + Guid.NewGuid().ToString("N");

            using (var scope = factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
                db.AuthStates.Add(new AuthStateEntity
                {
                    State = expiredState,
                    TenantId = tenantId,
                    CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-10),
                    ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1),
                    UsedAt = null,
                    CodeVerifier = "cv",
                    Nonce = "nonce",
                });
                await db.SaveChangesAsync();
            }

            var res = await GetCallbackAsync(client, tenantId, provider: "stub", code: "external-sub-1", expiredState);
            Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("invalid_state", body.Error!.Code);
        });
    }

    [Fact]
    public async Task Cleanup_ExpiredOrUsed_Can_Remove_States()
    {
        await WithTempDbAsync(async (factory, _client) =>
        {
            await EnsureDbCreatedAsync(factory);

            var now = DateTimeOffset.UtcNow;
            var tenantId = Guid.NewGuid();

            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
            var authState = scope.ServiceProvider.GetRequiredService<IAuthStateService>();

            db.AuthStates.Add(new AuthStateEntity
            {
                State = "expired-" + Guid.NewGuid().ToString("N"),
                TenantId = tenantId,
                CreatedAt = now.AddMinutes(-10),
                ExpiresAt = now.AddMinutes(-1),
                UsedAt = null,
                CodeVerifier = "cv",
                Nonce = "nonce",
            });

            db.AuthStates.Add(new AuthStateEntity
            {
                State = "used-" + Guid.NewGuid().ToString("N"),
                TenantId = tenantId,
                CreatedAt = now.AddMinutes(-10),
                ExpiresAt = now.AddMinutes(10),
                UsedAt = now,
                CodeVerifier = "cv",
                Nonce = "nonce",
            });

            db.AuthStates.Add(new AuthStateEntity
            {
                State = "valid-" + Guid.NewGuid().ToString("N"),
                TenantId = tenantId,
                CreatedAt = now,
                ExpiresAt = now.AddMinutes(10),
                UsedAt = null,
                CodeVerifier = "cv",
                Nonce = "nonce",
            });

            await db.SaveChangesAsync();

            var removed = await authState.CleanupExpiredStatesAsync(now);
            Assert.Equal(2, removed);

            var remaining = await db.AuthStates.AsNoTracking().CountAsync();
            Assert.Equal(1, remaining);
        });
    }

    [Fact]
    public async Task Provider_Disabled_Returns_403_ProviderNotEnabled()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            await SeedProviderAsync(factory, tenantId, provider: "stub", enabled: false, issuer: "https://issuer.test");

            string state;
            using (var scope = factory.Services.CreateScope())
            {
                var authState = scope.ServiceProvider.GetRequiredService<IAuthStateService>();
                var stateInfo = await authState.CreateStateAsync(tenantId);
                await authState.TryAttachOidcContextAsync(stateInfo.State, codeVerifier: "cv", nonce: "nonce");
                state = stateInfo.State;
            }

            var res = await GetCallbackAsync(client, tenantId, provider: "stub", code: "external-sub-1", state);
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("provider_not_enabled", body.Error!.Code);
        });
    }

    [Fact]
    public async Task ExternalIdentity_Disabled_Returns_403_ExternalIdentityDisabled()
    {
        await WithTempDbAsync(async (factory, client) =>
        {
            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();
            var issuer = "https://issuer.test";
            await SeedProviderAsync(factory, tenantId, provider: "stub", enabled: true, issuer);

            var code = "external-sub-disabled";
            string state;

            using (var scope = factory.Services.CreateScope())
            {
                var authState = scope.ServiceProvider.GetRequiredService<IAuthStateService>();
                var externalStore = scope.ServiceProvider.GetRequiredService<IExternalIdentityStore>();

                var stateInfo = await authState.CreateStateAsync(tenantId);
                await authState.TryAttachOidcContextAsync(stateInfo.State, codeVerifier: "cv", nonce: "nonce");
                state = stateInfo.State;

                var mapping = new ExternalIdentityMapping(
                    TenantId: tenantId,
                    OurSubject: Guid.NewGuid(),
                    Provider: "stub",
                    Issuer: issuer,
                    ProviderSubject: code,
                    CreatedAt: DateTimeOffset.UtcNow,
                    Enabled: true,
                    DisabledAt: null,
                    DisabledReason: null);

                _ = await externalStore.CreateMappingAsync(mapping);

                var key = new ExternalIdentityKey(tenantId, "stub", issuer, code);
                var disabled = await externalStore.DisableMappingAsync(key, disabledAt: DateTimeOffset.UtcNow, reason: "test");
                Assert.True(disabled);
            }

            var res = await GetCallbackAsync(client, tenantId, provider: "stub", code, state);
            Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

            var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
            Assert.NotNull(body);
            Assert.False(body!.Success);
            Assert.Equal("external_identity_disabled", body.Error!.Code);
        });
    }

    [Fact]
    public async Task PkceNonce_Binding_Attach_Is_SingleUse_And_Consume_Returns_Same_Values()
    {
        await WithTempDbAsync(async (factory, _client) =>
        {
            await EnsureDbCreatedAsync(factory);

            var tenantId = Guid.NewGuid();

            using var scope = factory.Services.CreateScope();
            var authState = scope.ServiceProvider.GetRequiredService<IAuthStateService>();

            var info = await authState.CreateStateAsync(tenantId);

            var attached = await authState.TryAttachOidcContextAsync(info.State, codeVerifier: "cv1", nonce: "nonce1");
            Assert.True(attached);

            var second = await authState.TryAttachOidcContextAsync(info.State, codeVerifier: "cv2", nonce: "nonce2");
            Assert.False(second);

            var ctx = await authState.ConsumeStateAsync(info.State);
            Assert.NotNull(ctx);
            Assert.Equal("cv1", ctx!.CodeVerifier);
            Assert.Equal("nonce1", ctx.Nonce);
        });
    }
}
