namespace Birdsoft.Security.Authentication.Persistence;

using Birdsoft.Security.Abstractions.Identity;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Data.EfCore;
using Microsoft.EntityFrameworkCore;

public sealed class RepositoryUserProvisioner : IUserProvisioner
{
    private readonly SecurityDbContext _db;
    private readonly ITenantRepository _tenants;
    private readonly ISubjectRepository _subjects;
    private readonly IExternalIdentityRepository _external;

    public RepositoryUserProvisioner(
        SecurityDbContext db,
        ITenantRepository tenants,
        ISubjectRepository subjects,
        IExternalIdentityRepository external)
    {
        _db = db;
        _tenants = tenants;
        _subjects = subjects;
        _external = external;
    }

    public async Task<Guid> ProvisionAsync(
        Guid tenantId,
        ExternalIdentityKey externalIdentity,
        Birdsoft.Security.Abstractions.OidcUserInfo? userInfo = null,
        CancellationToken cancellationToken = default)
    {
        _ = userInfo;

        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("tenantId is required", nameof(tenantId));
        }

        var trimmedProvider = externalIdentity.Provider?.Trim();
        var trimmedIssuer = externalIdentity.Issuer?.Trim();
        var trimmedProviderSubject = externalIdentity.ProviderSubject?.Trim();

        if (string.IsNullOrWhiteSpace(trimmedProvider)
            || string.IsNullOrWhiteSpace(trimmedIssuer)
            || string.IsNullOrWhiteSpace(trimmedProviderSubject))
        {
            throw new ArgumentException("externalIdentity is invalid", nameof(externalIdentity));
        }

        var provider = trimmedProvider!;
        var issuer = trimmedIssuer!;
        var providerSubject = trimmedProviderSubject!;

        // Fast-path: already provisioned.
        var existing = await _external.FindAsync(
            tenantId,
            provider,
            issuer,
            providerSubject,
            cancellationToken);
        if (existing is not null)
        {
            return existing.OurSubject;
        }

        await using var tx = await _db.Database.BeginTransactionAsync(cancellationToken);

        // Ensure tenant exists.
        _ = await _tenants.FindAsync(tenantId, cancellationToken)
            ?? await _tenants.CreateAsync(tenantId, $"tenant-{tenantId:N}", cancellationToken);

        // Re-check inside transaction.
        existing = await _external.FindAsync(
            tenantId,
            provider,
            issuer,
            providerSubject,
            cancellationToken);
        if (existing is not null)
        {
            await tx.CommitAsync(cancellationToken);
            return existing.OurSubject;
        }

        var ourSubject = Guid.NewGuid();
        _ = await _subjects.CreateAsync(tenantId, ourSubject, cancellationToken);
        _ = await _external.CreateAsync(
            tenantId,
            ourSubject,
            provider,
            issuer,
            providerSubject,
            cancellationToken);

        await tx.CommitAsync(cancellationToken);
        return ourSubject;
    }
}
