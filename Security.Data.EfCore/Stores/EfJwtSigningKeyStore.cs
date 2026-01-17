namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

public sealed class EfJwtSigningKeyStore : IJwtSigningKeyStore
{
    private readonly SecurityDbContext _db;
    private readonly IKeyMaterialChangeSignal _signal;

    public EfJwtSigningKeyStore(SecurityDbContext db, IKeyMaterialChangeSignal signal)
    {
        _db = db;
        _signal = signal;
    }

    public async Task<IReadOnlyList<JwtSigningKeyRecord>> ListAsync(bool includeDisabled = false, CancellationToken cancellationToken = default)
    {
        var q = _db.Set<JwtSigningKeyEntity>().AsNoTracking().AsQueryable();
        if (!includeDisabled)
        {
            q = q.Where(x => x.Status != (int)JwtSigningKeyStatus.Disabled);
        }

        // SQLite provider does not support ORDER BY DateTimeOffset; order in-memory.
        var rows = await q.ToListAsync(cancellationToken);
        return rows
            .OrderByDescending(x => x.CreatedAt)
            .Select(ToRecord)
            .ToList();
    }

    public Task<bool> HasAnyAsync(CancellationToken cancellationToken = default)
        => _db.Set<JwtSigningKeyEntity>().AsNoTracking().AnyAsync(cancellationToken);

    public async Task<JwtSigningKeyRecord?> FindAsync(string kid, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(kid))
        {
            return null;
        }

        var row = await _db.Set<JwtSigningKeyEntity>().AsNoTracking().FirstOrDefaultAsync(x => x.Kid == kid, cancellationToken);
        return row is null ? null : ToRecord(row);
    }

    public async Task<JwtSigningKeyRecord?> GetActiveAsync(CancellationToken cancellationToken = default)
    {
        // SQLite provider does not support ORDER BY DateTimeOffset; choose most recently updated in-memory.
        var rows = await _db.Set<JwtSigningKeyEntity>().AsNoTracking()
            .Where(x => x.Status == (int)JwtSigningKeyStatus.Active)
            .ToListAsync(cancellationToken);

        var row = rows.OrderByDescending(x => x.UpdatedAt).FirstOrDefault();
        return row is null ? null : ToRecord(row);
    }

    public async Task<JwtSigningKeySigningMaterial?> GetActiveSigningMaterialAsync(CancellationToken cancellationToken = default)
    {
        // SQLite provider does not support ORDER BY DateTimeOffset; choose most recently updated in-memory.
        var rows = await _db.Set<JwtSigningKeyEntity>().AsNoTracking()
            .Where(x => x.Status == (int)JwtSigningKeyStatus.Active)
            .ToListAsync(cancellationToken);

        var row = rows.OrderByDescending(x => x.UpdatedAt).FirstOrDefault();

        return row is null
            ? null
            : new JwtSigningKeySigningMaterial(row.Kid, row.Algorithm, row.PrivateKeyPem, row.SymmetricKey);
    }

    public async Task<IReadOnlyList<JwtSigningKeyVerificationMaterial>> GetVerificationKeysAsync(CancellationToken cancellationToken = default)
    {
        var rows = await _db.Set<JwtSigningKeyEntity>().AsNoTracking()
            .Where(x => x.Status != (int)JwtSigningKeyStatus.Disabled)
            .ToListAsync(cancellationToken);

        // SQLite provider does not support ORDER BY DateTimeOffset; order in-memory.
        return rows
            .OrderByDescending(x => x.CreatedAt)
            .Select(x => new JwtSigningKeyVerificationMaterial(x.Kid, x.Algorithm, x.PublicKeyPem, x.SymmetricKey))
            .ToList();
    }

    public async Task<JwtSigningKeyRecord> CreateRsaAsync(string? kid = null, string? reason = null, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        // Ensure a single active key. If no active exists, create as Active; otherwise create as Inactive.
        var hasActive = await _db.Set<JwtSigningKeyEntity>().AsNoTracking().AnyAsync(x => x.Status == (int)JwtSigningKeyStatus.Active, cancellationToken);
        var status = hasActive ? JwtSigningKeyStatus.Inactive : JwtSigningKeyStatus.Active;

        using var rsa = RSA.Create(2048);
        var privPem = ExportPrivatePem(rsa);
        var pubPem = ExportPublicPem(rsa);
        var computedKid = string.IsNullOrWhiteSpace(kid) ? ComputeKidFromPublic(rsa) : kid.Trim();

        var entity = new JwtSigningKeyEntity
        {
            Kid = computedKid,
            Algorithm = "RS256",
            Status = (int)status,
            PrivateKeyPem = privPem,
            PublicKeyPem = pubPem,
            SymmetricKey = null,
            Reason = reason,
            CreatedAt = now,
            UpdatedAt = now,
        };

        _db.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);
        _signal.NotifyChanged();
        return ToRecord(entity);
    }

    public async Task<JwtSigningKeyRecord> RotateRsaAsync(string? reason = null, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        // SQLite provider does not support ORDER BY DateTimeOffset; choose most recently updated in-memory.
        var actives = await _db.Set<JwtSigningKeyEntity>()
            .Where(x => x.Status == (int)JwtSigningKeyStatus.Active)
            .ToListAsync(cancellationToken);
        var active = actives.OrderByDescending(x => x.UpdatedAt).FirstOrDefault();

        if (active is not null)
        {
            active.Status = (int)JwtSigningKeyStatus.Inactive;
            active.UpdatedAt = now;
            active.Reason = string.IsNullOrWhiteSpace(reason) ? active.Reason : reason;
        }

        using var rsa = RSA.Create(2048);
        var privPem = ExportPrivatePem(rsa);
        var pubPem = ExportPublicPem(rsa);
        var kid = ComputeKidFromPublic(rsa);

        var entity = new JwtSigningKeyEntity
        {
            Kid = kid,
            Algorithm = "RS256",
            Status = (int)JwtSigningKeyStatus.Active,
            PrivateKeyPem = privPem,
            PublicKeyPem = pubPem,
            SymmetricKey = null,
            Reason = reason,
            CreatedAt = now,
            UpdatedAt = now,
        };

        _db.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);
        _signal.NotifyChanged();
        return ToRecord(entity);
    }

    public async Task<JwtSigningKeyRecord> CreateHmacAsync(string? kid = null, int bytes = 32, string? reason = null, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        var hasActive = await _db.Set<JwtSigningKeyEntity>().AsNoTracking().AnyAsync(x => x.Status == (int)JwtSigningKeyStatus.Active, cancellationToken);
        var status = hasActive ? JwtSigningKeyStatus.Inactive : JwtSigningKeyStatus.Active;

        var key = GenerateSymmetricKey(bytes);
        var computedKid = string.IsNullOrWhiteSpace(kid) ? ComputeKidFromSymmetric(key) : kid.Trim();

        var entity = new JwtSigningKeyEntity
        {
            Kid = computedKid,
            Algorithm = "HS256",
            Status = (int)status,
            PrivateKeyPem = null,
            PublicKeyPem = null,
            SymmetricKey = key,
            Reason = reason,
            CreatedAt = now,
            UpdatedAt = now,
        };

        _db.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);
        _signal.NotifyChanged();
        return ToRecord(entity);
    }

    public async Task<JwtSigningKeyRecord> RotateHmacAsync(int bytes = 32, string? reason = null, CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;

        // SQLite provider does not support ORDER BY DateTimeOffset; choose most recently updated in-memory.
        var actives = await _db.Set<JwtSigningKeyEntity>()
            .Where(x => x.Status == (int)JwtSigningKeyStatus.Active)
            .ToListAsync(cancellationToken);
        var active = actives.OrderByDescending(x => x.UpdatedAt).FirstOrDefault();

        if (active is not null)
        {
            active.Status = (int)JwtSigningKeyStatus.Inactive;
            active.UpdatedAt = now;
            active.Reason = string.IsNullOrWhiteSpace(reason) ? active.Reason : reason;
        }

        var key = GenerateSymmetricKey(bytes);
        var kid = ComputeKidFromSymmetric(key);

        var entity = new JwtSigningKeyEntity
        {
            Kid = kid,
            Algorithm = "HS256",
            Status = (int)JwtSigningKeyStatus.Active,
            PrivateKeyPem = null,
            PublicKeyPem = null,
            SymmetricKey = key,
            Reason = reason,
            CreatedAt = now,
            UpdatedAt = now,
        };

        _db.Add(entity);
        await _db.SaveChangesAsync(cancellationToken);
        _signal.NotifyChanged();
        return ToRecord(entity);
    }

    public async Task<JwtSigningKeyRecord?> DisableAsync(string kid, string? reason = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(kid))
        {
            return null;
        }

        var now = DateTimeOffset.UtcNow;

        var entity = await _db.Set<JwtSigningKeyEntity>().FirstOrDefaultAsync(x => x.Kid == kid, cancellationToken);
        if (entity is null)
        {
            return null;
        }

        // Prevent disabling the last non-disabled key (keeps verification stable).
        var remaining = await _db.Set<JwtSigningKeyEntity>().AsNoTracking()
            .CountAsync(x => x.Status != (int)JwtSigningKeyStatus.Disabled && x.Kid != kid, cancellationToken);
        if (remaining <= 0)
        {
            throw new InvalidOperationException("Cannot disable the last signing key.");
        }

        entity.Status = (int)JwtSigningKeyStatus.Disabled;
        entity.DisabledAt = now;
        entity.UpdatedAt = now;
        entity.Reason = string.IsNullOrWhiteSpace(reason) ? entity.Reason : reason;

        await _db.SaveChangesAsync(cancellationToken);
        _signal.NotifyChanged();
        return ToRecord(entity);
    }

    private static JwtSigningKeyRecord ToRecord(JwtSigningKeyEntity e)
        => new(e.Kid, e.Algorithm, (JwtSigningKeyStatus)e.Status, e.CreatedAt, e.UpdatedAt);

    private static string ExportPrivatePem(RSA rsa)
        => rsa.ExportPkcs8PrivateKeyPem();

    private static string ExportPublicPem(RSA rsa)
        => rsa.ExportSubjectPublicKeyInfoPem();

    private static string ComputeKidFromPublic(RSA rsa)
    {
        var pub = rsa.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(pub);
        var b64 = Base64UrlEncode(hash);
        return b64.Length <= 16 ? b64 : b64[..16];
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        var s = Convert.ToBase64String(bytes);
        return s.TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string GenerateSymmetricKey(int bytes)
    {
        if (bytes < 16)
        {
            bytes = 16;
        }

        var b = new byte[bytes];
        RandomNumberGenerator.Fill(b);
        return Base64UrlEncode(b);
    }

    private static string ComputeKidFromSymmetric(string key)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        var b64 = Base64UrlEncode(hash);
        return b64.Length <= 16 ? b64 : b64[..16];
    }
}
