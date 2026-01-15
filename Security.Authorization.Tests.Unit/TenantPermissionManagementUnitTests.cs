namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authorization.Api;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

public sealed class TenantPermissionManagementUnitTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private sealed class FakeCatalogStore : IPermissionCatalogStore
    {
        private readonly string? _productKey;
        public FakeCatalogStore(string? productKey) => _productKey = productKey;
        public ValueTask<string?> GetProductKeyForPermissionAsync(string permissionKey, CancellationToken cancellationToken = default)
        {
            _ = permissionKey;
            _ = cancellationToken;
            return ValueTask.FromResult(_productKey);
        }
    }

    private sealed class FakeEntitlementStore : ITenantEntitlementStore
    {
        private readonly bool _enabled;
        public FakeEntitlementStore(bool enabled) => _enabled = enabled;
        public ValueTask<bool> IsProductEnabledAsync(Guid tenantId, string productKey, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            _ = tenantId;
            _ = productKey;
            _ = now;
            _ = cancellationToken;
            return ValueTask.FromResult(_enabled);
        }
    }

    private sealed class SpyAdminStore : IAuthorizationAdminStore
    {
        public bool WasCalled { get; private set; }

        public ValueTask<(AuthorizationGrants Grants, long TenantModelVersion, long SubjectGrantsVersion)?> GetSubjectGrantsAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
        {
            WasCalled = true;
            _ = tenantId;
            _ = ourSubject;
            _ = cancellationToken;
            return ValueTask.FromResult<(AuthorizationGrants, long, long)?>(null);
        }

        public ValueTask<AuthorizationChangeReceipt> SetSubjectGrantsAsync(Guid tenantId, Guid ourSubject, AuthorizationGrants grants, string? reason = null, CancellationToken cancellationToken = default)
        {
            WasCalled = true;
            _ = tenantId;
            _ = ourSubject;
            _ = grants;
            _ = reason;
            _ = cancellationToken;
            throw new InvalidOperationException("Admin store should not be called when entitlement is disabled.");
        }
    }

    private static DefaultHttpContext CreateHttp(Guid tenantId)
    {
        var ctx = new DefaultHttpContext();
        var identity = new ClaimsIdentity(new[]
        {
            new Claim(SecurityClaimTypes.TenantId, tenantId.ToString()),
        }, authenticationType: "test");
        ctx.User = new ClaimsPrincipal(identity);
        return ctx;
    }

    private static async Task<(int StatusCode, string Body)> ExecuteAsync(IResult result)
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();

        // JsonHttpResult requires RequestServices to resolve JsonOptions.
        var services = new ServiceCollection();
        services.AddOptions();
        services.AddLogging();
        services.Configure<JsonOptions>(o =>
        {
            o.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
            o.SerializerOptions.DictionaryKeyPolicy = JsonNamingPolicy.CamelCase;
            o.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        });
        ctx.RequestServices = services.BuildServiceProvider();

        await result.ExecuteAsync(ctx);

        ctx.Response.Body.Position = 0;
        using var reader = new StreamReader(ctx.Response.Body);
        var body = await reader.ReadToEndAsync();
        return (ctx.Response.StatusCode, body);
    }

    [Fact]
    public async Task AssignPermission_DisabledEntitlement_Returns403_AndSkipsAdminStore()
    {
        var tenantId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var http = CreateHttp(tenantId);

        // Db is unused because entitlement should short-circuit before querying grants.
        await using var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync();
        var options = new DbContextOptionsBuilder<SecurityDbContext>().UseSqlite(conn).Options;
        await using var db = new SecurityDbContext(options);
        await db.Database.EnsureCreatedAsync();

        var catalog = new FakeCatalogStore(productKey: "orders");
        var entitlements = new FakeEntitlementStore(enabled: false);
        var admin = new SpyAdminStore();

        var result = await TenantPermissionManagementEndpoints.AddUserPermissionAsync(
            http,
            db,
            userId,
            new TenantPermissionManagementEndpoints.TenantSetUserPermissionRequest("orders:read", Reason: null),
            catalog,
            entitlements,
            admin,
            now: DateTimeOffset.UtcNow,
            ct: CancellationToken.None);

        var (status, body) = await ExecuteAsync(result);
        Assert.Equal((int)HttpStatusCode.Forbidden, status);
        Assert.False(admin.WasCalled);

        var parsed = JsonSerializer.Deserialize<ApiResponse<object>>(body, JsonOptions);
        Assert.NotNull(parsed);
        Assert.False(parsed!.Success);
        Assert.Equal("product_not_enabled", parsed.Error?.Code);
    }

    [Fact]
    public async Task ListPermissions_ReturnsOnlyEnabledProductsPermissions()
    {
        var tenantId = Guid.NewGuid();
        var http = CreateHttp(tenantId);
        var now = DateTimeOffset.UtcNow;

        await using var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync();
        var options = new DbContextOptionsBuilder<SecurityDbContext>().UseSqlite(conn).Options;
        await using var db = new SecurityDbContext(options);
        await db.Database.EnsureCreatedAsync();

        db.Products.AddRange(
            new ProductEntity
            {
                ProductId = Guid.NewGuid(),
                ProductKey = "orders",
                DisplayName = "Orders",
                Description = null,
                Status = 1,
                CreatedAt = now,
                UpdatedAt = now,
            },
            new ProductEntity
            {
                ProductId = Guid.NewGuid(),
                ProductKey = "billing",
                DisplayName = "Billing",
                Description = null,
                Status = 1,
                CreatedAt = now,
                UpdatedAt = now,
            });

        db.TenantProducts.AddRange(
            new TenantProductEntity
            {
                TenantId = tenantId,
                ProductKey = "orders",
                Status = 1,
                StartAt = now.AddMinutes(-10),
                EndAt = null,
                PlanJson = null,
                CreatedAt = now,
                UpdatedAt = now,
            },
            new TenantProductEntity
            {
                TenantId = tenantId,
                ProductKey = "billing",
                Status = 0, // disabled
                StartAt = now.AddMinutes(-10),
                EndAt = null,
                PlanJson = null,
                CreatedAt = now,
                UpdatedAt = now,
            });

        db.Permissions.AddRange(
            new PermissionEntity
            {
                PermId = Guid.NewGuid(),
                PermKey = "orders:read",
                ProductKey = "orders",
                Description = null,
                CreatedAt = now,
                UpdatedAt = now,
            },
            new PermissionEntity
            {
                PermId = Guid.NewGuid(),
                PermKey = "billing:read",
                ProductKey = "billing",
                Description = null,
                CreatedAt = now,
                UpdatedAt = now,
            });

        await db.SaveChangesAsync();

        var entitlements = new FakeEntitlementStore(enabled: true);

        var result = await TenantPermissionManagementEndpoints.GetTenantPermissionsAsync(
            http,
            db,
            entitlements,
            productKey: null,
            now: now,
            ct: CancellationToken.None);

        var (status, body) = await ExecuteAsync(result);
        Assert.Equal((int)HttpStatusCode.OK, status);

        var parsed = JsonSerializer.Deserialize<ApiResponse<IReadOnlyList<TenantPermissionManagementEndpoints.TenantPermissionDto>>>(body, JsonOptions);
        Assert.NotNull(parsed);
        Assert.True(parsed!.Success);
        Assert.NotNull(parsed.Data);

        Assert.Single(parsed.Data!);
        Assert.Equal("orders:read", parsed.Data![0].PermissionKey);
        Assert.Equal("orders", parsed.Data![0].ProductKey);
    }
}
