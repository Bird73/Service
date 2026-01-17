namespace Birdsoft.Security.Authentication.Jwt;

using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// DB-backed JWT key provider. If no DB signing keys exist, falls back to the legacy options-based provider.
/// </summary>
public sealed class DbBackedJwtKeyProvider : IJwtKeyProvider
{
    private sealed record KeyState(
        string Algorithm,
        string Kid,
        RSA? RsaPrivate,
        RSA? RsaPublic,
        byte[]? SymmetricKeyBytes,
        object Jwks,
        bool FromDb);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IKeyMaterialChangeSignal _signal;
    private readonly DefaultJwtKeyProvider _fallback;
    private readonly object _gate = new();
    private KeyState? _state;
    private long _stateVersion;
    private DateTimeOffset _lastRefresh;

    public DbBackedJwtKeyProvider(IServiceScopeFactory scopeFactory, IKeyMaterialChangeSignal signal, DefaultJwtKeyProvider fallback)
    {
        _scopeFactory = scopeFactory;
        _signal = signal;
        _fallback = fallback;
    }

    public string Algorithm => Ensure().Algorithm;

    public string Kid => Ensure().Kid;

    public RSA? GetRsaPrivateKey() => Ensure().RsaPrivate;

    public RSA? GetRsaPublicKey() => Ensure().RsaPublic;

    public byte[]? GetSymmetricKeyBytes() => Ensure().SymmetricKeyBytes;

    public object GetJwksDocument() => Ensure().Jwks;

    private KeyState Ensure()
    {
        lock (_gate)
        {
            _state = LoadFromDbOrFallback();
            _stateVersion = _signal.Version;
            _lastRefresh = DateTimeOffset.UtcNow;
            return _state;
        }
    }

    private KeyState LoadFromDbOrFallback()
    {
        using var scope = _scopeFactory.CreateScope();
        var store = scope.ServiceProvider.GetService<IJwtSigningKeyStore>();
        if (store is null)
        {
            return FromFallback();
        }

        var hasAny = store.HasAnyAsync().GetAwaiter().GetResult();
        if (!hasAny)
        {
            return FromFallback();
        }

        var active = store.GetActiveSigningMaterialAsync().GetAwaiter().GetResult();
        if (active is null || string.IsNullOrWhiteSpace(active.Kid))
        {
            return FromFallback();
        }

        var alg = string.IsNullOrWhiteSpace(active.Algorithm) ? "RS256" : active.Algorithm.Trim().ToUpperInvariant();
        if (alg == "RS256")
        {
            var rsaPrivate = CreateOrLoadRsaPrivate(active.PrivateKeyPem);
            var rsaPublic = CreateRsaPublic(rsaPrivate);
            var jwks = BuildJwks(store.GetVerificationKeysAsync().GetAwaiter().GetResult());
            return new KeyState("RS256", active.Kid, rsaPrivate, rsaPublic, null, jwks, FromDb: true);
        }

        // HS* symmetric signing. Do NOT publish symmetric secrets in JWKS.
        var sym = string.IsNullOrWhiteSpace(active.SymmetricKey) ? null : Encoding.UTF8.GetBytes(active.SymmetricKey);
        return new KeyState(alg, active.Kid, null, null, sym, new { keys = Array.Empty<object>() }, FromDb: true);
    }

    private KeyState FromFallback()
        => new(
            _fallback.Algorithm,
            _fallback.Kid,
            _fallback.GetRsaPrivateKey(),
            _fallback.GetRsaPublicKey(),
            _fallback.GetSymmetricKeyBytes(),
            _fallback.GetJwksDocument(),
            FromDb: false);

    private static object BuildJwks(IEnumerable<JwtSigningKeyVerificationMaterial> keys)
    {
        var jwkKeys = new List<object>();

        foreach (var k in keys)
        {
            var alg = string.IsNullOrWhiteSpace(k.Algorithm) ? "RS256" : k.Algorithm.Trim();
            if (!alg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            RSA? rsa = null;
            if (!string.IsNullOrWhiteSpace(k.PublicKeyPem))
            {
                try
                {
                    rsa = RSA.Create();
                    rsa.ImportFromPem(k.PublicKeyPem);
                }
                catch
                {
                    rsa = null;
                }
            }

            if (rsa is null)
            {
                continue;
            }

            var (n, e) = ExportRsaJwkParameters(rsa);
            jwkKeys.Add(new { kty = "RSA", use = "sig", alg = "RS256", kid = k.Kid, n, e });
        }

        return new { keys = jwkKeys.ToArray() };
    }

    private static (string n, string e) ExportRsaJwkParameters(RSA rsaPublic)
    {
        var p = rsaPublic.ExportParameters(includePrivateParameters: false);
        if (p.Modulus is null || p.Exponent is null)
        {
            throw new InvalidOperationException("RSA public parameters missing.");
        }

        return (Base64UrlEncode(p.Modulus), Base64UrlEncode(p.Exponent));
    }

    private static RSA CreateOrLoadRsaPrivate(string? pem)
    {
        var rsa = RSA.Create();
        if (string.IsNullOrWhiteSpace(pem))
        {
            rsa.KeySize = 2048;
            return rsa;
        }

        rsa.ImportFromPem(pem);
        return rsa;
    }

    private static RSA CreateRsaPublic(RSA rsaPrivate)
    {
        var rsaPublic = RSA.Create();
        rsaPublic.ImportParameters(rsaPrivate.ExportParameters(includePrivateParameters: false));
        return rsaPublic;
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        var s = Convert.ToBase64String(bytes);
        return s.TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
