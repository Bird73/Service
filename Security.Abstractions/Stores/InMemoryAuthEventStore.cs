namespace Birdsoft.Security.Abstractions.Stores;

using Birdsoft.Security.Abstractions.Models;

public sealed class InMemoryAuthEventStore : IAuthEventStore
{
    private readonly object _gate = new();
    private readonly int _capacity;
    private readonly List<AuthEvent> _events;

    public InMemoryAuthEventStore(int capacity = 10_000)
    {
        _capacity = Math.Clamp(capacity, 100, 1_000_000);
        _events = new List<AuthEvent>(_capacity);
    }

    public Task AppendAsync(AuthEvent ev, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        lock (_gate)
        {
            _events.Add(ev);
            if (_events.Count > _capacity)
            {
                _events.RemoveRange(0, Math.Max(1, _events.Count - _capacity));
            }
        }
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuthEvent>> QueryAsync(AuthEventQuery query, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (query.TenantId is null)
        {
            throw new ArgumentException("tenantId is required for audit log queries", nameof(query));
        }

        List<AuthEvent> snapshot;
        lock (_gate)
        {
            snapshot = _events.ToList();
        }

        IEnumerable<AuthEvent> q = snapshot;

        var tenantId = query.TenantId.Value;
        q = q.Where(x => x.TenantId == tenantId);

        if (query.OurSubject is Guid ourSubject)
        {
            q = q.Where(x => x.OurSubject == ourSubject);
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
        return Task.FromResult<IReadOnlyList<AuthEvent>>(q.ToList());
    }
}
