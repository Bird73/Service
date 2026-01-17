namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class EfPlatformAdminStore : IPlatformAdminStore
{
    private readonly SecurityDbContext _db;

    public EfPlatformAdminStore(SecurityDbContext db)
    {
        _db = db;
    }

    public async ValueTask<PlatformAdminRecord?> FindAsync(Guid ourSubject, CancellationToken cancellationToken = default)
    {
        var row = await _db.PlatformAdmins.AsNoTracking()
            .FirstOrDefaultAsync(x => x.OurSubject == ourSubject, cancellationToken);

        return row is null
            ? null
            : new PlatformAdminRecord(
                row.OurSubject,
                row.Role,
                (PlatformAdminStatus)row.Status,
                row.TokenVersion,
                row.CreatedAt,
                row.UpdatedAt);
    }

    public async Task<IReadOnlyList<PlatformAdminRecord>> ListAsync(int skip, int take, CancellationToken cancellationToken = default)
    {
        var s = Math.Max(0, skip);
        var t = Math.Clamp(take, 1, 200);

        var rows = await _db.PlatformAdmins.AsNoTracking()
            .OrderBy(x => x.OurSubject)
            .Skip(s)
            .Take(t)
            .ToListAsync(cancellationToken);

        return rows
            .Select(row => new PlatformAdminRecord(
                row.OurSubject,
                row.Role,
                (PlatformAdminStatus)row.Status,
                row.TokenVersion,
                row.CreatedAt,
                row.UpdatedAt))
            .ToList();
    }

    public async Task<PlatformAdminRecord> CreateAsync(Guid ourSubject, string role, string? reason = null, CancellationToken cancellationToken = default)
    {
        _ = reason;

        if (!IsValidRole(role))
        {
            throw new InvalidOperationException("invalid_platform_role");
        }

        var existing = await _db.PlatformAdmins.AsNoTracking().AnyAsync(x => x.OurSubject == ourSubject, cancellationToken);
        if (existing)
        {
            throw new InvalidOperationException("platform_admin_exists");
        }

        var now = DateTimeOffset.UtcNow;
        var entity = new PlatformAdminEntity
        {
            OurSubject = ourSubject,
            Role = role,
            Status = (int)PlatformAdminStatus.Active,
            TokenVersion = 1,
            CreatedAt = now,
            UpdatedAt = now,
            DisabledAt = null,
        };

        _db.PlatformAdmins.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);

        return new PlatformAdminRecord(entity.OurSubject, entity.Role, PlatformAdminStatus.Active, entity.TokenVersion, entity.CreatedAt, entity.UpdatedAt);
    }

    public async Task<PlatformAdminRecord?> SetRoleAsync(Guid ourSubject, string role, string? reason = null, CancellationToken cancellationToken = default)
    {
        _ = reason;

        if (!IsValidRole(role))
        {
            throw new InvalidOperationException("invalid_platform_role");
        }

        var row = await _db.PlatformAdmins.FirstOrDefaultAsync(x => x.OurSubject == ourSubject, cancellationToken);
        if (row is null)
        {
            return null;
        }

        if (!string.Equals(row.Role, role, StringComparison.OrdinalIgnoreCase))
        {
            row.Role = role;
            row.TokenVersion = Math.Max(1, row.TokenVersion + 1);
            row.UpdatedAt = DateTimeOffset.UtcNow;
            await _db.SaveChangesAsync(cancellationToken);
        }

        return new PlatformAdminRecord(row.OurSubject, row.Role, (PlatformAdminStatus)row.Status, row.TokenVersion, row.CreatedAt, row.UpdatedAt);
    }

    public async Task<PlatformAdminRecord?> SetStatusAsync(Guid ourSubject, PlatformAdminStatus status, string? reason = null, CancellationToken cancellationToken = default)
    {
        _ = reason;

        var row = await _db.PlatformAdmins.FirstOrDefaultAsync(x => x.OurSubject == ourSubject, cancellationToken);
        if (row is null)
        {
            return null;
        }

        if (row.Status != (int)status)
        {
            row.Status = (int)status;
            row.TokenVersion = Math.Max(1, row.TokenVersion + 1);
            row.UpdatedAt = DateTimeOffset.UtcNow;
            row.DisabledAt = status == PlatformAdminStatus.Disabled ? DateTimeOffset.UtcNow : null;
            await _db.SaveChangesAsync(cancellationToken);
        }

        return new PlatformAdminRecord(row.OurSubject, row.Role, (PlatformAdminStatus)row.Status, row.TokenVersion, row.CreatedAt, row.UpdatedAt);
    }

    private static bool IsValidRole(string role)
        => string.Equals(role, PlatformRoles.SuperAdmin, StringComparison.OrdinalIgnoreCase)
            || string.Equals(role, PlatformRoles.OpsAdmin, StringComparison.OrdinalIgnoreCase)
            || string.Equals(role, PlatformRoles.ReadonlyAdmin, StringComparison.OrdinalIgnoreCase);
}
