namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class EfPlatformTokenVersionStore : IPlatformTokenVersionStore
{
    private const string GlobalId = "global";
    private readonly SecurityDbContext _db;

    public EfPlatformTokenVersionStore(SecurityDbContext db)
    {
        _db = db;
    }

    public async ValueTask<long> GetCurrentAsync(CancellationToken cancellationToken = default)
    {
        var row = await _db.PlatformTokenVersions.FirstOrDefaultAsync(x => x.Id == GlobalId, cancellationToken);
        if (row is not null)
        {
            return row.TokenVersion;
        }

        var now = DateTimeOffset.UtcNow;
        var created = new PlatformTokenVersionEntity
        {
            Id = GlobalId,
            TokenVersion = 1,
            UpdatedAt = now,
        };

        _db.PlatformTokenVersions.Add(created);
        await _db.SaveChangesAsync(cancellationToken);
        return created.TokenVersion;
    }

    public async ValueTask<long> BumpAsync(string? reason = null, CancellationToken cancellationToken = default)
    {
        var row = await _db.PlatformTokenVersions.FirstOrDefaultAsync(x => x.Id == GlobalId, cancellationToken);
        if (row is null)
        {
            // If the row does not exist yet, create it at version 2 so that any concurrently issued
            // tokens at implicit version 1 will be invalid.
            var now = DateTimeOffset.UtcNow;
            var created = new PlatformTokenVersionEntity
            {
                Id = GlobalId,
                TokenVersion = 2,
                UpdatedAt = now,
            };

            _db.PlatformTokenVersions.Add(created);
            await _db.SaveChangesAsync(cancellationToken);
            return created.TokenVersion;
        }

        row.TokenVersion += 1;
        row.UpdatedAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(cancellationToken);
        return row.TokenVersion;
    }
}
