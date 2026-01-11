namespace Birdsoft.Security.Abstractions.Options;

using System.Security.Cryptography;
using System.Text;

public static class JwtSafetyChecks
{
    public static void ThrowIfUnsafe(JwtOptions jwt, SecurityEnvironmentOptions env, SecuritySafetyOptions safety)
    {
        if (safety.RequireEnvironmentId && string.IsNullOrWhiteSpace(env.EnvironmentId))
        {
            throw new InvalidOperationException("Security:Environment:EnvironmentId must be set for environment isolation.");
        }

        // Enforce that issuer/audience embed env id (or will be suffixed at runtime).
        if (!string.IsNullOrWhiteSpace(jwt.Issuer) && safety.RequireEnvironmentId)
        {
            _ = JwtTenantResolution.ApplyEnvironmentSuffix(jwt.Issuer, env);
        }

        if (!string.IsNullOrWhiteSpace(jwt.Audience) && safety.RequireEnvironmentId)
        {
            _ = JwtTenantResolution.ApplyEnvironmentSuffix(jwt.Audience, env);
        }

        if (safety.EnforceTenantJwtIsolation && jwt.Tenants is { Length: > 0 })
        {
            var seenTenantIds = new HashSet<Guid>();
            foreach (var t in jwt.Tenants)
            {
                if (!seenTenantIds.Add(t.TenantId))
                {
                    throw new InvalidOperationException($"Duplicate JwtOptions.Tenants entry for tenant {t.TenantId}.");
                }
            }

            // Compare fingerprints of active keys across tenants; duplicates are dangerous.
            var fingerprints = new Dictionary<string, Guid>(StringComparer.OrdinalIgnoreCase);

            foreach (var t in jwt.Tenants)
            {
                var eff = JwtTenantResolution.Resolve(jwt, t.TenantId);

                if (eff.KeyRing?.Keys is { Length: > 0 })
                {
                    var active = eff.KeyRing.Keys.Where(k => k.Status == JwtKeyStatus.Active).ToArray();
                    if (active.Length == 0)
                    {
                        throw new InvalidOperationException($"Tenant {t.TenantId} has no active JWT key.");
                    }

                    foreach (var k in active)
                    {
                        if (string.IsNullOrWhiteSpace(k.Kid))
                        {
                            throw new InvalidOperationException($"Tenant {t.TenantId} has JWT key with empty kid.");
                        }

                        var fp = Convert.ToHexString(JwtTenantResolution.ComputeKeyFingerprint(k));
                        if (fingerprints.TryGetValue(fp, out var otherTenant) && otherTenant != t.TenantId)
                        {
                            throw new InvalidOperationException($"Dangerous config: tenants {otherTenant} and {t.TenantId} share the same JWT key material.");
                        }

                        fingerprints[fp] = t.TenantId;
                    }

                    continue;
                }

                // Legacy single-key per tenant
                if (!string.IsNullOrWhiteSpace(eff.SigningKey))
                {
                    var alg = string.IsNullOrWhiteSpace(eff.SigningAlgorithm) ? "RS256" : eff.SigningAlgorithm.Trim();
                    var bytes = alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase)
                        ? Encoding.UTF8.GetBytes(eff.SigningKey)
                        : Encoding.UTF8.GetBytes(eff.SigningKey); // For RS, this is PEM text.

                    var fp = Convert.ToHexString(SHA256.HashData(bytes));
                    if (fingerprints.TryGetValue(fp, out var otherTenant) && otherTenant != t.TenantId)
                    {
                        throw new InvalidOperationException($"Dangerous config: tenants {otherTenant} and {t.TenantId} share the same JWT signing key material.");
                    }

                    fingerprints[fp] = t.TenantId;
                }
            }
        }

        // Basic HS* minimum length safety (when configured globally)
        var globalAlg = string.IsNullOrWhiteSpace(jwt.SigningAlgorithm) ? "RS256" : jwt.SigningAlgorithm.Trim();
        if (globalAlg.StartsWith("HS", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(jwt.SigningKey))
        {
            var len = Encoding.UTF8.GetByteCount(jwt.SigningKey);
            if (len < 32)
            {
                throw new InvalidOperationException("HS* SigningKey is too short; require at least 32 bytes.");
            }
        }
    }
}
