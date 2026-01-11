namespace Birdsoft.Security.Authorization.Api.Auth;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using System.Collections.Concurrent;

public sealed class InMemorySubjectRepository : ISubjectRepository
{
    private sealed record SubjectRecord(Guid TenantId, Guid OurSubject, UserStatus Status, int TokenVersion, DateTimeOffset CreatedAt);

    private readonly ConcurrentDictionary<(Guid TenantId, Guid OurSubject), SubjectRecord> _subjects = new();

    public Task<SubjectDto?> FindAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (_subjects.TryGetValue((tenantId, ourSubject), out var rec))
        {
            return Task.FromResult<SubjectDto?>(new SubjectDto { TenantId = rec.TenantId, OurSubject = rec.OurSubject, Status = rec.Status, TokenVersion = rec.TokenVersion, CreatedAt = rec.CreatedAt });
        }

        var now = DateTimeOffset.UtcNow;
        return Task.FromResult<SubjectDto?>(new SubjectDto { TenantId = tenantId, OurSubject = ourSubject, Status = UserStatus.Active, TokenVersion = 0, CreatedAt = now });
    }

    public Task<SubjectDto> CreateAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var now = DateTimeOffset.UtcNow;
        var rec = new SubjectRecord(tenantId, ourSubject, UserStatus.Active, TokenVersion: 0, CreatedAt: now);
        _subjects[(tenantId, ourSubject)] = rec;
        return Task.FromResult(new SubjectDto { TenantId = rec.TenantId, OurSubject = rec.OurSubject, Status = rec.Status, TokenVersion = rec.TokenVersion, CreatedAt = rec.CreatedAt });
    }

    public Task<int> UpdateTokenVersionAsync(Guid tenantId, Guid ourSubject, int newVersion, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (!_subjects.TryGetValue((tenantId, ourSubject), out var rec))
        {
            return Task.FromResult(0);
        }

        _subjects[(tenantId, ourSubject)] = rec with { TokenVersion = newVersion };
        return Task.FromResult(1);
    }

    public Task<int> IncrementTokenVersionAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (!_subjects.TryGetValue((tenantId, ourSubject), out var rec))
        {
            return Task.FromResult(0);
        }

        _subjects[(tenantId, ourSubject)] = rec with { TokenVersion = rec.TokenVersion + 1 };
        return Task.FromResult(1);
    }

    public Task<int> UpdateStatusAsync(Guid tenantId, Guid ourSubject, UserStatus status, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (!_subjects.TryGetValue((tenantId, ourSubject), out var rec))
        {
            return Task.FromResult(0);
        }

        _subjects[(tenantId, ourSubject)] = rec with { Status = status };
        return Task.FromResult(1);
    }
}
