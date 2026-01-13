namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Services;
using System.Collections.Concurrent;
using System.Security.Cryptography;

public sealed class InMemoryAuthStateService : IAuthStateService
{
    private sealed record StateRecord(
        Guid TenantId,
        DateTimeOffset ExpiresAt,
        DateTimeOffset? UsedAt,
        string? Provider,
        string? CodeVerifier,
        string? Nonce);

    private readonly ConcurrentDictionary<string, StateRecord> _states = new(StringComparer.Ordinal);

    public Task<AuthStateInfo> CreateStateAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var state = Base64Url.Encode(RandomNumberGenerator.GetBytes(24));
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
        _states[state] = new StateRecord(tenantId, expiresAt, UsedAt: null, Provider: null, CodeVerifier: null, Nonce: null);
        return Task.FromResult(new AuthStateInfo { State = state, ExpiresAt = expiresAt });
    }

    public Task<Guid?> ValidateAndGetTenantAsync(string state, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        if (!_states.TryGetValue(state, out var rec))
        {
            return Task.FromResult<Guid?>(null);
        }

        if (rec.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return Task.FromResult<Guid?>(null);
        }

        return Task.FromResult<Guid?>(rec.TenantId);
    }

    public Task<bool> TryAttachOidcContextAsync(
        string state,
        string provider,
        string codeVerifier,
        string nonce,
        CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;

        while (true)
        {
            if (!_states.TryGetValue(state, out var rec))
            {
                return Task.FromResult(false);
            }

            if (rec.ExpiresAt <= DateTimeOffset.UtcNow || rec.UsedAt is not null)
            {
                return Task.FromResult(false);
            }

            if (rec.Provider is not null || rec.CodeVerifier is not null || rec.Nonce is not null)
            {
                return Task.FromResult(false);
            }

            var updated = rec with { Provider = provider, CodeVerifier = codeVerifier, Nonce = nonce };
            if (_states.TryUpdate(state, updated, rec))
            {
                return Task.FromResult(true);
            }
        }
    }

    public Task<AuthStateContext?> ConsumeStateAsync(string state, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;

        while (true)
        {
            if (!_states.TryGetValue(state, out var rec))
            {
                return Task.FromResult<AuthStateContext?>(null);
            }

            if (rec.ExpiresAt <= DateTimeOffset.UtcNow || rec.UsedAt is not null)
            {
                return Task.FromResult<AuthStateContext?>(null);
            }

            if (string.IsNullOrWhiteSpace(rec.Provider)
                || string.IsNullOrWhiteSpace(rec.CodeVerifier)
                || string.IsNullOrWhiteSpace(rec.Nonce))
            {
                return Task.FromResult<AuthStateContext?>(null);
            }

            var updated = rec with { UsedAt = DateTimeOffset.UtcNow };
            if (_states.TryUpdate(state, updated, rec))
            {
                var ctx = new AuthStateContext
                {
                    TenantId = rec.TenantId,
                    Provider = rec.Provider!,
                    CodeVerifier = rec.CodeVerifier!,
                    Nonce = rec.Nonce!,
                    ExpiresAt = rec.ExpiresAt,
                };

                _states.TryRemove(state, out _);
                return Task.FromResult<AuthStateContext?>(ctx);
            }
        }
    }

    public Task<int> CleanupExpiredStatesAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        var removed = 0;
        foreach (var (key, rec) in _states)
        {
            if (rec.ExpiresAt <= now || rec.UsedAt is not null)
            {
                if (_states.TryRemove(key, out _))
                {
                    removed++;
                }
            }
        }

        return Task.FromResult(removed);
    }
}
