namespace Birdsoft.Security.Authorization.Tests.Unit;

using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Security.Data.EfCore.Entities;
using Birdsoft.Security.Data.EfCore.Stores;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

public sealed class EfAuthorizationStoreSqliteContractTests
{
    [Fact]
    public async Task GetSubjectGrantsAsync_When_SubjectMissing_ReturnsNull()
    {
        await using var ctx = await CreateDbAsync();
        var store = new EfAuthorizationStore(ctx);

        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var result = await store.GetSubjectGrantsAsync(tenantId, ourSubject);
        Assert.Null(result);
    }

    [Fact]
    public async Task SetAndGetSubjectGrants_RoundTrips_DirectGrants_And_Versions()
    {
        await using var ctx = await CreateDbAsync();
        var store = new EfAuthorizationStore(ctx);

        var now = DateTimeOffset.UtcNow;
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        var roleId = Guid.NewGuid();
        var directPermId = Guid.NewGuid();
        var roleDerivedPermId = Guid.NewGuid();

        ctx.Tenants.Add(new TenantEntity
        {
            TenantId = tenantId,
            Name = "t",
            Status = 1,
            TokenVersion = 0,
            CreatedAt = now,
            UpdatedAt = now,
        });

        ctx.Subjects.Add(new SubjectEntity
        {
            TenantId = tenantId,
            OurSubject = ourSubject,
            DisplayName = "u",
            Status = 1,
            TokenVersion = 0,
            CreatedAt = now,
            UpdatedAt = now,
        });

        ctx.Roles.Add(new RoleEntity
        {
            TenantId = tenantId,
            RoleId = roleId,
            RoleName = "security_admin",
            Description = null,
            CreatedAt = now,
            UpdatedAt = now,
        });

        ctx.Permissions.AddRange(
            new PermissionEntity
            {
                PermId = directPermId,
                PermKey = "perm.direct",
                ProductKey = null,
                Description = null,
                CreatedAt = now,
                UpdatedAt = now,
            },
            new PermissionEntity
            {
                PermId = roleDerivedPermId,
                PermKey = "perm.fromRole",
                ProductKey = null,
                Description = null,
                CreatedAt = now,
                UpdatedAt = now,
            });

        ctx.RolePermissions.Add(new RolePermissionEntity
        {
            TenantId = tenantId,
            RoleId = roleId,
            PermId = roleDerivedPermId,
            AssignedAt = now,
        });

        await ctx.SaveChangesAsync();

        var receipt = await store.SetSubjectGrantsAsync(
            tenantId,
            ourSubject,
            new AuthorizationGrants(
                Roles: ["security_admin"],
                Scopes: ["security.admin"],
                Permissions: ["perm.direct"]));

        Assert.Equal(1, receipt.TenantModelVersion);
        Assert.Equal(1, receipt.SubjectGrantsVersion);

        var grants = await store.GetSubjectGrantsAsync(tenantId, ourSubject);
        Assert.NotNull(grants);

        Assert.Equal(1, grants.Value.TenantModelVersion);
        Assert.Equal(1, grants.Value.SubjectGrantsVersion);

        Assert.Contains("security_admin", grants.Value.Grants.Roles);
        Assert.Contains("security.admin", grants.Value.Grants.Scopes);

        // Admin surface returns DIRECT permissions only.
        Assert.Contains("perm.direct", grants.Value.Grants.Permissions);
        Assert.DoesNotContain("perm.fromRole", grants.Value.Grants.Permissions);

        // Read-side surface returns effective permissions (role-derived + direct).
        var effectivePerms = await store.GetPermissionsAsync(tenantId, ourSubject);
        Assert.Contains("perm.direct", effectivePerms);
        Assert.Contains("perm.fromRole", effectivePerms);
    }

    [Fact]
    public async Task SetSubjectGrants_Ignores_Unknown_Roles_And_Permissions_But_Persists_Scopes()
    {
        await using var ctx = await CreateDbAsync();
        var store = new EfAuthorizationStore(ctx);

        var now = DateTimeOffset.UtcNow;
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        ctx.Tenants.Add(new TenantEntity
        {
            TenantId = tenantId,
            Name = "t",
            Status = 1,
            TokenVersion = 0,
            CreatedAt = now,
            UpdatedAt = now,
        });

        ctx.Subjects.Add(new SubjectEntity
        {
            TenantId = tenantId,
            OurSubject = ourSubject,
            DisplayName = "u",
            Status = 1,
            TokenVersion = 7,
            CreatedAt = now,
            UpdatedAt = now,
        });

        await ctx.SaveChangesAsync();

        var receipt = await store.SetSubjectGrantsAsync(
            tenantId,
            ourSubject,
            new AuthorizationGrants(
                Roles: ["does_not_exist"],
                Scopes: ["  security.admin  ", "security.admin"],
                Permissions: ["perm.missing"]));

        Assert.Equal(1, receipt.TenantModelVersion);
        Assert.Equal(8, receipt.SubjectGrantsVersion);

        var grants = await store.GetSubjectGrantsAsync(tenantId, ourSubject);
        Assert.NotNull(grants);

        Assert.Empty(grants.Value.Grants.Roles);
        Assert.Empty(grants.Value.Grants.Permissions);
        Assert.Contains("security.admin", grants.Value.Grants.Scopes);
    }

    private static async Task<SecurityDbContext> CreateDbAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        var options = new DbContextOptionsBuilder<SecurityDbContext>()
            .UseSqlite(connection)
            .EnableSensitiveDataLogging()
            .Options;

        var ctx = new SecurityDbContext(options);
        await ctx.Database.EnsureCreatedAsync();

        // Keep the connection open for the lifetime of the context.
        return ctx;
    }
}
