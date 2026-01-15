namespace Birdsoft.Security.Data.EfCore.Repositories;

using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

public sealed class EfLocalAccountRepository : ILocalAccountRepository
{
    private const int DefaultIterations = 100_000;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    private readonly SecurityDbContext _db;

    public EfLocalAccountRepository(SecurityDbContext db) => _db = db;

    public async Task<LocalAccountProfileDto?> FindByUsernameAsync(Guid tenantId, string usernameOrEmail, CancellationToken cancellationToken = default)
    {
        var normalized = Normalize(usernameOrEmail);
        var entity = await _db.SubjectCredentials.AsNoTracking()
            .FirstOrDefaultAsync(x => x.TenantId == tenantId && x.UsernameOrEmail == normalized, cancellationToken);

        return entity is null
            ? null
            : new LocalAccountProfileDto
            {
                TenantId = entity.TenantId,
                OurSubject = entity.OurSubject,
                UsernameOrEmail = entity.UsernameOrEmail,
            };
    }

    public async Task<LocalAccountProfileDto> CreateAsync(Guid tenantId, Guid ourSubject, string usernameOrEmail, string password, CancellationToken cancellationToken = default)
    {
        var normalized = Normalize(usernameOrEmail);
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var iterations = DefaultIterations;
        var hash = HashPassword(password, salt, iterations);

        var now = DateTimeOffset.UtcNow;

        var entity = new LocalAccountEntity
        {
            Id = Guid.NewGuid(),
            TenantId = tenantId,
            OurSubject = ourSubject,
            UsernameOrEmail = normalized,
            PasswordSalt = Convert.ToBase64String(salt),
            PasswordIterations = iterations,
            PasswordHash = Convert.ToBase64String(hash),
            HashVersion = 1,
            LastPasswordChangeAt = now,
            FailedAccessCount = 0,
            LockedUntil = null,
            CreatedAt = now,
            UpdatedAt = now,
        };

        _db.SubjectCredentials.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);

        return new LocalAccountProfileDto
        {
            TenantId = entity.TenantId,
            OurSubject = entity.OurSubject,
            UsernameOrEmail = entity.UsernameOrEmail,
        };
    }

    public async Task<Guid?> VerifyPasswordAsync(Guid tenantId, string usernameOrEmail, string password, CancellationToken cancellationToken = default)
    {
        var normalized = Normalize(usernameOrEmail);
        var entity = await _db.SubjectCredentials.AsNoTracking()
            .FirstOrDefaultAsync(x => x.TenantId == tenantId && x.UsernameOrEmail == normalized, cancellationToken);

        if (entity is null)
        {
            return null;
        }

        var iterations = entity.PasswordIterations > 0 ? entity.PasswordIterations : DefaultIterations;

        byte[] salt;
        byte[] storedHash;
        try
        {
            salt = Convert.FromBase64String(entity.PasswordSalt);
            storedHash = Convert.FromBase64String(entity.PasswordHash);
        }
        catch
        {
            return null;
        }

        var computed = HashPassword(password, salt, iterations);
        return CryptographicOperations.FixedTimeEquals(computed, storedHash) ? entity.OurSubject : null;
    }

    private static string Normalize(string value) => value.Trim().ToLowerInvariant();

    private static byte[] HashPassword(string password, byte[] salt, int iterations)
    {
        // PBKDF2-HMAC-SHA256
        return Rfc2898DeriveBytes.Pbkdf2(
            password: Encoding.UTF8.GetBytes(password),
            salt: salt,
            iterations: iterations,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: HashBytes);
    }
}
