namespace Birdsoft.Security.Data.EfCore.Stores;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Data.EfCore.Entities;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

public sealed class EfOidcProviderRegistry : IOidcProviderRegistry
{
    private readonly SecurityDbContext _db;

    public EfOidcProviderRegistry(SecurityDbContext db) => _db = db;

    public async ValueTask<OidcProviderOptions?> GetAsync(Guid tenantId, string provider, CancellationToken cancellationToken = default)
    {
        if (tenantId == Guid.Empty || string.IsNullOrWhiteSpace(provider))
        {
            return null;
        }

        var entity = await _db.OidcProviders.AsNoTracking()
            .FirstOrDefaultAsync(x => x.TenantId == tenantId && x.Provider == provider, cancellationToken);

        if (entity is null || !entity.Enabled)
        {
            return null;
        }

        var scopes = ParseScopes(entity.ScopesJson) ?? ["openid", "profile", "email"];

        return new OidcProviderOptions
        {
            Provider = entity.Provider,
            Authority = entity.Authority,
            Issuer = entity.Issuer,
            ClientId = entity.ClientId,
            ClientSecret = entity.ClientSecret,
            CallbackPath = string.IsNullOrWhiteSpace(entity.CallbackPath)
                ? "/api/v1/auth/oidc/{provider}/callback"
                : entity.CallbackPath,
            Scopes = scopes,
        };
    }

    private static IReadOnlyList<string>? ParseScopes(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            var list = JsonSerializer.Deserialize<List<string>>(json);
            return list is { Count: > 0 } ? list : null;
        }
        catch
        {
            return null;
        }
    }
}
