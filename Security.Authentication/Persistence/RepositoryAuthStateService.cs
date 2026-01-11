namespace Birdsoft.Security.Authentication.Persistence;

using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using System.Security.Cryptography;

public sealed class RepositoryAuthStateService : IAuthStateService
{
    private static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(5);

    private readonly IAuthStateRepository _repo;

    public RepositoryAuthStateService(IAuthStateRepository repo)
    {
        _repo = repo;
    }

    public async Task<AuthStateInfo> CreateStateAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        var state = Base64Url.Encode(RandomNumberGenerator.GetBytes(24));
        var expiresAt = DateTimeOffset.UtcNow.Add(DefaultTtl);

        await _repo.CreateAsync(state, tenantId, expiresAt, cancellationToken);

        return new AuthStateInfo
        {
            State = state,
            ExpiresAt = expiresAt,
        };
    }

    public async Task<Guid?> ValidateAndGetTenantAsync(string state, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(state))
        {
            return null;
        }

        var dto = await _repo.FindAsync(state, cancellationToken);
        if (dto is null)
        {
            return null;
        }

        var now = DateTimeOffset.UtcNow;
        if (dto.UsedAt is not null || dto.ExpiresAt <= now)
        {
            return null;
        }

        return dto.TenantId;
    }

    public Task<bool> TryAttachOidcContextAsync(string state, string codeVerifier, string nonce, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(state) || string.IsNullOrWhiteSpace(codeVerifier) || string.IsNullOrWhiteSpace(nonce))
        {
            return Task.FromResult(false);
        }

        return _repo.TryAttachOidcContextAsync(state, codeVerifier, nonce, cancellationToken);
    }

    public async Task<AuthStateContext?> ConsumeStateAsync(string state, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(state))
        {
            return null;
        }

        var dto = await _repo.TryConsumeAndGetAsync(state, DateTimeOffset.UtcNow, cancellationToken);
        if (dto is null)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(dto.CodeVerifier) || string.IsNullOrWhiteSpace(dto.Nonce))
        {
            return null;
        }

        return new AuthStateContext
        {
            TenantId = dto.TenantId,
            CodeVerifier = dto.CodeVerifier,
            Nonce = dto.Nonce,
            ExpiresAt = dto.ExpiresAt,
        };
    }

    public Task<int> CleanupExpiredStatesAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
        => _repo.DeleteExpiredOrUsedAsync(now, cancellationToken);
}
