namespace Birdsoft.Security.Authorization.Tests.Integration;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Data.EfCore.Entities;

public sealed class PermissionProductIntegrityStartupTests
{
    [Fact]
    public void Startup_Fails_When_Permission_References_Missing_Product()
    {
        using var db = new SqliteTestDatabase();
        SeedMissingProduct(db);

        using var factory = new AuthorizationApiFactory(new AuthorizationApiFactory.Overrides
        {
            SecurityDbConnectionString = db.ConnectionString,
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("missing product", ex.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("orders", ex.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Startup_Fails_When_Permission_References_Disabled_Product()
    {
        using var db = new SqliteTestDatabase();
        SeedDisabledProduct(db);

        using var factory = new AuthorizationApiFactory(new AuthorizationApiFactory.Overrides
        {
            SecurityDbConnectionString = db.ConnectionString,
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("disabled product", ex.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("orders", ex.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Startup_Fails_When_RequiredPrefix_Permission_Has_No_Product()
    {
        using var db = new SqliteTestDatabase();
        SeedRequiredPrefixWithoutProduct(db);

        using var factory = new AuthorizationApiFactory(new AuthorizationApiFactory.Overrides
        {
            SecurityDbConnectionString = db.ConnectionString,
            RequiredProductPrefixes = ["orders:"],
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("requires product_key", ex.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("orders:read", ex.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    private static void SeedMissingProduct(SqliteTestDatabase db)
    {
        using var ctx = db.CreateDbContext();
        ctx.Database.EnsureDeleted();
        ctx.Database.EnsureCreated();

        ctx.Permissions.Add(new PermissionEntity
        {
            PermId = Guid.NewGuid(),
            PermKey = "orders:read",
            ProductKey = "orders",
            Description = "test",
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        });

        ctx.SaveChanges();
    }

    private static void SeedDisabledProduct(SqliteTestDatabase db)
    {
        using var ctx = db.CreateDbContext();
        ctx.Database.EnsureDeleted();
        ctx.Database.EnsureCreated();

        ctx.Products.Add(new ProductEntity
        {
            ProductId = Guid.NewGuid(),
            ProductKey = "orders",
            DisplayName = "Orders",
            Description = "test",
            Status = (int)ProductStatus.Disabled,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        });

        ctx.Permissions.Add(new PermissionEntity
        {
            PermId = Guid.NewGuid(),
            PermKey = "orders:read",
            ProductKey = "orders",
            Description = "test",
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        });

        ctx.SaveChanges();
    }

    private static void SeedRequiredPrefixWithoutProduct(SqliteTestDatabase db)
    {
        using var ctx = db.CreateDbContext();
        ctx.Database.EnsureDeleted();
        ctx.Database.EnsureCreated();

        ctx.Permissions.Add(new PermissionEntity
        {
            PermId = Guid.NewGuid(),
            PermKey = "orders:read",
            ProductKey = null,
            Description = "test",
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        });

        ctx.SaveChanges();
    }
}
