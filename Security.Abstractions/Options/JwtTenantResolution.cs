namespace Birdsoft.Security.Abstractions.Options;

using System.Security.Cryptography;
using System.Text;

public sealed record JwtEffectiveSettings(
    string Issuer,
    string Audience,
    string SigningAlgorithm,
    string? Kid,
    JwtKeyRingOptions? KeyRing,
    string? SigningKey);

public static class JwtTenantResolution
{
    public static JwtEffectiveSettings Resolve(JwtOptions opts, Guid tenantId)
    {
        if (opts.Tenants is { Length: > 0 })
        {
            var t = opts.Tenants.FirstOrDefault(x => x.TenantId == tenantId);
            if (t is not null)
            {
                var issuer = !string.IsNullOrWhiteSpace(t.Issuer) ? t.Issuer! : opts.Issuer;
                var audience = !string.IsNullOrWhiteSpace(t.Audience) ? t.Audience! : opts.Audience;
                var alg = !string.IsNullOrWhiteSpace(t.SigningAlgorithm) ? t.SigningAlgorithm! : opts.SigningAlgorithm;
                var kid = !string.IsNullOrWhiteSpace(t.Kid) ? t.Kid : opts.Kid;
                var ring = t.KeyRing ?? opts.KeyRing;
                var signingKey = !string.IsNullOrWhiteSpace(t.SigningKey) ? t.SigningKey : opts.SigningKey;
                return new JwtEffectiveSettings(issuer, audience, alg, kid, ring, signingKey);
            }
        }

        return new JwtEffectiveSettings(opts.Issuer, opts.Audience, opts.SigningAlgorithm, opts.Kid, opts.KeyRing, opts.SigningKey);
    }

    public static string ResolveExpectedIssuer(JwtOptions opts, Guid tenantId, SecurityEnvironmentOptions env)
    {
        var eff = Resolve(opts, tenantId);
        return ApplyEnvironmentSuffix(eff.Issuer, env);
    }

    public static string ResolveExpectedAudience(JwtOptions opts, Guid tenantId, SecurityEnvironmentOptions env)
    {
        var eff = Resolve(opts, tenantId);
        return ApplyEnvironmentSuffix(eff.Audience, env);
    }

    public static string ApplyEnvironmentSuffix(string value, SecurityEnvironmentOptions env)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        if (string.IsNullOrWhiteSpace(env.EnvironmentId))
        {
            return value;
        }

        // Non-breaking convention: if caller already embeds env, keep it.
        // Otherwise, append a stable suffix so tokens cannot validate cross-env.
        return value.Contains($"/env/{env.EnvironmentId}", StringComparison.OrdinalIgnoreCase)
            || value.EndsWith($"-env-{env.EnvironmentId}", StringComparison.OrdinalIgnoreCase)
            ? value
            : value.TrimEnd('/') + $"/env/{env.EnvironmentId}";
    }

    public static byte[] ComputeKeyFingerprint(JwtKeyMaterialOptions key)
    {
        var alg = string.IsNullOrWhiteSpace(key.Algorithm) ? "RS256" : key.Algorithm.Trim();
        if (alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
        {
            var bytes = string.IsNullOrWhiteSpace(key.SymmetricKey) ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(key.SymmetricKey);
            return SHA256.HashData(bytes);
        }

        // RS256: hash the public key bytes.
        var rsa = TryLoadRsa(key.PublicKeyPem) ?? TryLoadRsa(key.PrivateKeyPem);
        if (rsa is null)
        {
            return SHA256.HashData(Array.Empty<byte>());
        }

        var pub = rsa.ExportSubjectPublicKeyInfo();
        return SHA256.HashData(pub);
    }

    private static RSA? TryLoadRsa(string? pemOrBase64)
    {
        if (string.IsNullOrWhiteSpace(pemOrBase64))
        {
            return null;
        }

        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pemOrBase64);
            return rsa;
        }
        catch
        {
        }

        try
        {
            var bytes = Convert.FromBase64String(pemOrBase64);
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(bytes, out _);
            return rsa;
        }
        catch
        {
            return null;
        }
    }
}
