namespace Birdsoft.Security.Data.EfCore.Repositories;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

public sealed class EfSubjectRepository : ISubjectRepository
{
    private readonly SecurityDbContext _db;

    public EfSubjectRepository(SecurityDbContext db) => _db = db;

    public async Task<SubjectDto?> FindAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        var entity = await _db.Subjects.AsNoTracking()
            .FirstOrDefaultAsync(x => x.TenantId == tenantId && x.OurSubject == ourSubject, cancellationToken);

        return entity is null
            ? null
            : new SubjectDto
            {
                TenantId = entity.TenantId,
                OurSubject = entity.OurSubject,
                TokenVersion = entity.TokenVersion,
                CreatedAt = entity.CreatedAt,
            };
    }

    public async Task<SubjectDto> CreateAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var entity = new SubjectEntity
        {
            TenantId = tenantId,
            OurSubject = ourSubject,
            TokenVersion = 0,
            CreatedAt = now,
        };

        _db.Subjects.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);

        return new SubjectDto
        {
            TenantId = entity.TenantId,
            OurSubject = entity.OurSubject,
            TokenVersion = entity.TokenVersion,
            CreatedAt = entity.CreatedAt,
        };
    }

    public async Task<int> UpdateTokenVersionAsync(Guid tenantId, Guid ourSubject, int newVersion, CancellationToken cancellationToken = default)
    {
        return await _db.Subjects
            .Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.TokenVersion, newVersion), cancellationToken);
    }

    public async Task<int> IncrementTokenVersionAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        return await _db.Subjects
            .Where(x => x.TenantId == tenantId && x.OurSubject == ourSubject)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.TokenVersion, x => x.TokenVersion + 1), cancellationToken);
    }
}
