namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

public sealed class EfBootstrapKeyStore : IBootstrapKeyStore
{
    private readonly SecurityDbContext _db;
    private readonly IOptionsMonitor<BootstrapKeyHashingOptions> _hashing;

    public EfBootstrapKeyStore(SecurityDbContext db, IOptionsMonitor<BootstrapKeyHashingOptions> hashing)
    {
        _db = db;
        _hashing = hashing;
    }

    public async Task<IReadOnlyList<BootstrapKeyRecord>> ListAsync(bool includeRevoked = false, CancellationToken cancellationToken = default)
    {
        var q = _db.Set<BootstrapKeyEntity>().AsNoTracking().AsQueryable();
        if (!includeRevoked)
        {
            q = q.Where(x => x.Status == (int)BootstrapKeyStatus.Active);
        }

        var rows = await q.OrderByDescending(x => x.CreatedAt).ToListAsync(cancellationToken);
        return rows.Select(ToRecord).ToList();
    }

    public Task<bool> HasAnyAsync(CancellationToken cancellationToken = default)
        => _db.Set<BootstrapKeyEntity>().AsNoTracking().AnyAsync(cancellationToken);

    public async Task<BootstrapKeyCreateResult> CreateAsync(string? label = null, DateTimeOffset? expiresAt = null, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var id = Guid.NewGuid();
        var plaintext = GenerateKey();

        var (hash, lookup) = ComputeHash(plaintext, _hashing.CurrentValue.Pepper);

        var entity = new BootstrapKeyEntity
        {
            Id = id,
            Label = string.IsNullOrWhiteSpace(label) ? "bootstrap" : label.Trim(),
            KeyHash = hash,
            KeyLookup = lookup,
            Status = (int)BootstrapKeyStatus.Active,
            CreatedAt = now,
            UpdatedAt = now,
            ExpiresAt = expiresAt,
        };

        _db.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);

        return new BootstrapKeyCreateResult(ToRecord(entity), plaintext);
    }

    public async Task<bool> ValidateAsync(string providedKey, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(providedKey))
        {
            return false;
        }

        var pepper = _hashing.CurrentValue.Pepper;
        var (hash, lookup) = ComputeHash(providedKey.Trim(), pepper);

        var candidates = await _db.Set<BootstrapKeyEntity>()
            .Where(x => x.KeyLookup == lookup)
            .ToListAsync(cancellationToken);

        BootstrapKeyEntity? match = null;
        foreach (var c in candidates)
        {
            if (ConstantTimeEquals(c.KeyHash, hash))
            {
                match = c;
                break;
            }
        }

        if (match is null)
        {
            return false;
        }

        // Evaluate expiry/revocation.
        if (match.RevokedAt is not null || match.Status == (int)BootstrapKeyStatus.Revoked)
        {
            return false;
        }

        if (match.ExpiresAt is DateTimeOffset exp && exp <= now)
        {
            match.Status = (int)BootstrapKeyStatus.Expired;
            match.UpdatedAt = now;
            await _db.SaveChangesAsync(cancellationToken);
            return false;
        }

        match.LastUsedAt = now;
        match.UpdatedAt = now;
        if (match.Status != (int)BootstrapKeyStatus.Active)
        {
            match.Status = (int)BootstrapKeyStatus.Active;
        }

        await _db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<BootstrapKeyRecord?> RevokeAsync(Guid id, string? reason = null, CancellationToken cancellationToken = default)
    {
        var entity = await _db.Set<BootstrapKeyEntity>().FirstOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (entity is null)
        {
            return null;
        }

        var now = DateTimeOffset.UtcNow;
        entity.Status = (int)BootstrapKeyStatus.Revoked;
        entity.RevokedAt = now;
        entity.RevocationReason = string.IsNullOrWhiteSpace(reason) ? entity.RevocationReason : reason;
        entity.UpdatedAt = now;

        await _db.SaveChangesAsync(cancellationToken);
        return ToRecord(entity);
    }

    private static BootstrapKeyRecord ToRecord(BootstrapKeyEntity e)
        => new(
            e.Id,
            e.Label,
            (BootstrapKeyStatus)e.Status,
            e.CreatedAt,
            e.UpdatedAt,
            e.ExpiresAt,
            e.LastUsedAt,
            e.RevokedAt,
            e.RevocationReason);

    private static string GenerateKey()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncode(bytes);
    }

    private static (string hash, string lookup) ComputeHash(string plaintext, string pepper)
    {
        if (string.IsNullOrWhiteSpace(pepper))
        {
            throw new InvalidOperationException($"{BootstrapKeyHashingOptions.SectionName}:Pepper is required when using DB-backed bootstrap keys.");
        }

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(pepper));
        var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(plaintext));
        var hash = Base64UrlEncode(hashBytes);
        var lookup = hash.Length <= 16 ? hash : hash[..16];
        return (hash, lookup);
    }

    private static bool ConstantTimeEquals(string a, string b)
    {
        var aBytes = Encoding.UTF8.GetBytes(a);
        var bBytes = Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes)
    {
        var s = Convert.ToBase64String(bytes);
        return s.TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
