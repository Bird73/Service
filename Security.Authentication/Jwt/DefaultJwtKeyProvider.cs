namespace Birdsoft.Security.Authentication.Jwt;

using Birdsoft.Security.Abstractions.Options;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

public sealed class DefaultJwtKeyProvider : IJwtKeyProvider
{
    private sealed class NoOpDisposable : IDisposable
    {
        public static readonly IDisposable Instance = new NoOpDisposable();

        public void Dispose()
        {
        }
    }

    private sealed record KeyState(
        string Algorithm,
        string Kid,
        RSA? RsaPrivate,
        RSA? RsaPublic,
        byte[]? SymmetricKeyBytes,
        object Jwks);

    private readonly IOptionsMonitor<JwtOptions> _options;
    private readonly object _gate = new();
    private KeyState? _state;
    private readonly IDisposable _onChange = NoOpDisposable.Instance;

    public DefaultJwtKeyProvider(IOptionsMonitor<JwtOptions> options)
    {
        _options = options;
        _onChange = _options.OnChange(_ =>
        {
            lock (_gate)
            {
                _state = null;
            }
        }) ?? NoOpDisposable.Instance;
    }

    public string Algorithm => Ensure().Algorithm;

    public string Kid => Ensure().Kid;

    public RSA? GetRsaPrivateKey() => Ensure().RsaPrivate;

    public RSA? GetRsaPublicKey() => Ensure().RsaPublic;

    public byte[]? GetSymmetricKeyBytes() => Ensure().SymmetricKeyBytes;

    public object GetJwksDocument() => Ensure().Jwks;

    private KeyState Ensure()
    {
        var snapshot = _state;
        if (snapshot is not null)
        {
            return snapshot;
        }

        lock (_gate)
        {
            if (_state is not null)
            {
                return _state;
            }

            var opts = _options.CurrentValue;

            if (opts.KeyRing?.Keys is { Length: > 0 })
            {
                var (signing, jwks) = BuildFromKeyRing(opts);
                _state = signing with { Jwks = jwks };
                return _state;
            }

            // Legacy single-key configuration
            var alg = string.IsNullOrWhiteSpace(opts.SigningAlgorithm) ? "RS256" : opts.SigningAlgorithm.Trim();
            if (alg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
            {
                var rsaPrivate = CreateOrLoadRsaPrivate(opts.SigningKey);
                var rsaPublic = CreateRsaPublic(rsaPrivate);

                var (n, e) = ExportRsaJwkParameters(rsaPublic);
                var kid = !string.IsNullOrWhiteSpace(opts.Kid)
                    ? opts.Kid!
                    : ComputeKid(n, e);

                var jwk = new
                {
                    kty = "RSA",
                    use = "sig",
                    alg = "RS256",
                    kid,
                    n,
                    e,
                };

                var jwks = new { keys = new[] { jwk } };
                _state = new KeyState("RS256", kid, rsaPrivate, rsaPublic, null, jwks);
                return _state;
            }

            // HS* symmetric signing. For security, we do NOT publish symmetric secrets in JWKS.
            var symKey = string.IsNullOrWhiteSpace(opts.SigningKey)
                ? null
                : Encoding.UTF8.GetBytes(opts.SigningKey);

            var symKid = !string.IsNullOrWhiteSpace(opts.Kid)
                ? opts.Kid!
                : "sym";

            _state = new KeyState(alg.ToUpperInvariant(), symKid, null, null, symKey, new { keys = Array.Empty<object>() });
            return _state;
        }
    }

    private static (KeyState signing, object jwks) BuildFromKeyRing(JwtOptions opts)
    {
        var ring = opts.KeyRing!;
        var keys = ring.Keys
            .Where(k => k is not null)
            .Where(k => k.Status != Birdsoft.Security.Abstractions.Options.JwtKeyStatus.Disabled)
            .ToArray();

        // Signing key: ActiveSigningKid -> first Active
        var signingKey = !string.IsNullOrWhiteSpace(ring.ActiveSigningKid)
            ? keys.FirstOrDefault(k => string.Equals(k.Kid, ring.ActiveSigningKid, StringComparison.Ordinal))
            : null;

        signingKey ??= keys.FirstOrDefault(k => k.Status == Birdsoft.Security.Abstractions.Options.JwtKeyStatus.Active);
        signingKey ??= keys.First();

        if (string.IsNullOrWhiteSpace(signingKey.Kid))
        {
            throw new InvalidOperationException("JwtOptions.KeyRing requires kid.");
        }

        var alg = string.IsNullOrWhiteSpace(signingKey.Algorithm) ? "RS256" : signingKey.Algorithm.Trim();
        if (alg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
        {
            var rsaPrivate = CreateOrLoadRsaPrivate(signingKey.PrivateKeyPem);
            var rsaPublic = !string.IsNullOrWhiteSpace(signingKey.PublicKeyPem)
                ? CreateOrLoadRsaPublic(signingKey.PublicKeyPem)
                : CreateRsaPublic(rsaPrivate);

            var jwksObj = BuildJwks(keys);
            return (new KeyState("RS256", signingKey.Kid, rsaPrivate, rsaPublic, null, jwksObj), jwksObj);
        }

        var sym = string.IsNullOrWhiteSpace(signingKey.SymmetricKey) ? null : Encoding.UTF8.GetBytes(signingKey.SymmetricKey);
        return (new KeyState(alg.ToUpperInvariant(), signingKey.Kid, null, null, sym, new { keys = Array.Empty<object>() }), new { keys = Array.Empty<object>() });
    }

    private static object BuildJwks(IEnumerable<Birdsoft.Security.Abstractions.Options.JwtKeyMaterialOptions> keys)
    {
        var jwkKeys = new List<object>();

        foreach (var k in keys)
        {
            var alg = string.IsNullOrWhiteSpace(k.Algorithm) ? "RS256" : k.Algorithm.Trim();
            if (!alg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var rsa = !string.IsNullOrWhiteSpace(k.PublicKeyPem)
                ? CreateOrLoadRsaPublic(k.PublicKeyPem)
                : (!string.IsNullOrWhiteSpace(k.PrivateKeyPem) ? CreateRsaPublic(CreateOrLoadRsaPrivate(k.PrivateKeyPem)) : null);

            if (rsa is null)
            {
                continue;
            }

            var (n, e) = ExportRsaJwkParameters(rsa);
            jwkKeys.Add(new { kty = "RSA", use = "sig", alg = "RS256", kid = k.Kid, n, e });
        }

        return new { keys = jwkKeys.ToArray() };
    }

    private static RSA CreateOrLoadRsaPrivate(string? signingKey)
    {
        var rsa = RSA.Create();

        if (string.IsNullOrWhiteSpace(signingKey))
        {
            rsa.KeySize = 2048;
            return rsa;
        }

        // PEM (recommended)
        if (signingKey.Contains("BEGIN", StringComparison.Ordinal))
        {
            rsa.ImportFromPem(signingKey);
            return rsa;
        }

        // Base64 PKCS#8 private key (optional)
        try
        {
            var pkcs8 = Convert.FromBase64String(signingKey);
            rsa.ImportPkcs8PrivateKey(pkcs8, out _);
            return rsa;
        }
        catch
        {
            // Fall back to treating it as a literal string; generate an ephemeral key.
            rsa.KeySize = 2048;
            return rsa;
        }
    }

    private static RSA? CreateOrLoadRsaPublic(string pem)
    {
        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch
        {
            return null;
        }
    }

    private static RSA CreateRsaPublic(RSA rsaPrivate)
    {
        var rsaPublic = RSA.Create();
        rsaPublic.ImportParameters(rsaPrivate.ExportParameters(includePrivateParameters: false));
        return rsaPublic;
    }

    private static (string n, string e) ExportRsaJwkParameters(RSA rsaPublic)
    {
        var p = rsaPublic.ExportParameters(includePrivateParameters: false);
        if (p.Modulus is null || p.Exponent is null)
        {
            throw new InvalidOperationException("RSA public parameters missing.");
        }

        return (Base64Url.Encode(p.Modulus), Base64Url.Encode(p.Exponent));
    }

    private static string ComputeKid(string n, string e)
    {
        var input = Encoding.ASCII.GetBytes(n + "." + e);
        var hash = SHA256.HashData(input);
        var kid = Base64Url.Encode(hash);
        return kid.Length <= 16 ? kid : kid[..16];
    }
}
