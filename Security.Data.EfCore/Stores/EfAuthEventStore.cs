namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore.Entities;

public sealed class EfAuthEventStore : IAuthEventStore
{
    private readonly SecurityDbContext _db;

    public EfAuthEventStore(SecurityDbContext db) => _db = db;

    public async Task AppendAsync(AuthEvent ev, CancellationToken cancellationToken = default)
    {
        var entity = new AuthEventEntity
        {
            Id = ev.Id,
            OccurredAt = ev.OccurredAt,
            TenantId = ev.TenantId,
            OurSubject = ev.OurSubject,
            SessionId = ev.SessionId,
            Type = (int)ev.Type,
            Outcome = ev.Outcome,
            Detail = ev.Detail,
        };

        _db.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);
    }
}
