namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using System.Collections.Concurrent;

public sealed class InMemoryTenantRepository : ITenantRepository
{
    private sealed record TenantRecord(Guid TenantId, string Name, TenantStatus Status, int TokenVersion, DateTimeOffset CreatedAt);

    private readonly ConcurrentDictionary<Guid, TenantRecord> _tenants = new();

    public Task<TenantDto?> FindAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (_tenants.TryGetValue(tenantId, out var rec))
        {
            return Task.FromResult<TenantDto?>(new TenantDto { TenantId = rec.TenantId, Name = rec.Name, Status = rec.Status, TokenVersion = rec.TokenVersion, CreatedAt = rec.CreatedAt });
        }

        // Dev-mode default: treat unknown tenant as Active.
        var now = DateTimeOffset.UtcNow;
        return Task.FromResult<TenantDto?>(new TenantDto { TenantId = tenantId, Name = $"tenant-{tenantId:N}", Status = TenantStatus.Active, TokenVersion = 0, CreatedAt = now });
    }

    public Task<TenantDto> CreateAsync(Guid tenantId, string name, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var now = DateTimeOffset.UtcNow;
        var rec = new TenantRecord(tenantId, name, TenantStatus.Active, TokenVersion: 0, CreatedAt: now);
        _tenants[tenantId] = rec;
        return Task.FromResult(new TenantDto { TenantId = rec.TenantId, Name = rec.Name, Status = rec.Status, TokenVersion = rec.TokenVersion, CreatedAt = rec.CreatedAt });
    }

    public Task<int> IncrementTokenVersionAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (!_tenants.TryGetValue(tenantId, out var rec))
        {
            return Task.FromResult(0);
        }

        _tenants[tenantId] = rec with { TokenVersion = rec.TokenVersion + 1 };
        return Task.FromResult(1);
    }

    public Task<int> UpdateStatusAsync(Guid tenantId, TenantStatus status, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (!_tenants.TryGetValue(tenantId, out var rec))
        {
            return Task.FromResult(0);
        }

        _tenants[tenantId] = rec with { Status = status };
        return Task.FromResult(1);
    }
}
