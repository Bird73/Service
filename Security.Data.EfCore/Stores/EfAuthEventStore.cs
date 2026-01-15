namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;

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
            Provider = ev.Provider,
            Issuer = ev.Issuer,
            ErrorCode = ev.ErrorCode,
            Code = ev.Code,
            Detail = ev.Detail,
            CorrelationId = ev.CorrelationId,
            TraceId = ev.TraceId,
            Ip = ev.Ip,
            UserAgent = ev.UserAgent,
            MetaJson = ev.MetaJson,
        };

        _db.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<AuthEvent>> QueryAsync(AuthEventQuery query, CancellationToken cancellationToken = default)
    {
        if (query.TenantId is null)
        {
            throw new ArgumentException("tenantId is required for audit log queries", nameof(query));
        }

        var q = _db.AuthEvents.AsNoTracking().AsQueryable();

        var tenantId = query.TenantId.Value;
        q = q.Where(x => x.TenantId == tenantId);

        if (query.OurSubject is Guid subject)
        {
            q = q.Where(x => x.OurSubject == subject);
        }

        if (query.From is DateTimeOffset from)
        {
            q = q.Where(x => x.OccurredAt >= from);
        }

        if (query.To is DateTimeOffset to)
        {
            q = q.Where(x => x.OccurredAt <= to);
        }

        q = q.OrderByDescending(x => x.OccurredAt);

        if (query.Skip > 0)
        {
            q = q.Skip(query.Skip);
        }

        q = q.Take(Math.Clamp(query.Take, 1, 1000));

        var rows = await q.ToListAsync(cancellationToken);
        return rows.Select(x => new AuthEvent
        {
            Id = x.Id,
            OccurredAt = x.OccurredAt,
            TenantId = x.TenantId,
            OurSubject = x.OurSubject,
            SessionId = x.SessionId,
            Type = (AuthEventType)x.Type,
            Outcome = x.Outcome,
            Provider = x.Provider,
            Issuer = x.Issuer,
            ErrorCode = x.ErrorCode,
            Code = x.Code,
            Detail = x.Detail,
            CorrelationId = x.CorrelationId,
            TraceId = x.TraceId,
            Ip = x.Ip,
            UserAgent = x.UserAgent,
            MetaJson = x.MetaJson,
        }).ToList();
    }
}
