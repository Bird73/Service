namespace Birdsoft.Security.Authorization.Api.Auth;

using Birdsoft.Security.Abstractions.Options;
using Microsoft.Extensions.Options;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

public sealed class DefaultJwtKeyProvider : IJwtKeyProvider
{
    private sealed record KeyState(
        string Algorithm,
        string Kid,
        RSA? RsaPublic,
        byte[]? SymmetricKeyBytes);

    private readonly IOptionsMonitor<JwtOptions> _options;
    private readonly object _gate = new();
    private KeyState? _state;
    private readonly IDisposable _onChange;

    public DefaultJwtKeyProvider(IOptionsMonitor<JwtOptions> options)
    {
        _options = options;
        _onChange = _options.OnChange(_ =>
        {
            lock (_gate)
            {
                _state = null;
            }
        });
    }

    public string Algorithm => Ensure().Algorithm;

    public string Kid => Ensure().Kid;

    public RSA? GetRsaPublicKey() => Ensure().RsaPublic;

    public byte[]? GetSymmetricKeyBytes() => Ensure().SymmetricKeyBytes;

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
                var ring = opts.KeyRing;
                var keys = ring.Keys.Where(k => k.Status != JwtKeyStatus.Disabled).ToArray();

                var active = !string.IsNullOrWhiteSpace(ring.ActiveSigningKid)
                    ? keys.FirstOrDefault(k => string.Equals(k.Kid, ring.ActiveSigningKid, StringComparison.Ordinal))
                    : null;
                active ??= keys.FirstOrDefault(k => k.Status == JwtKeyStatus.Active);
                active ??= keys.First();

                var alg = string.IsNullOrWhiteSpace(active.Algorithm) ? "RS256" : active.Algorithm.Trim();
                if (alg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
                {
                    var rsaPublic = !string.IsNullOrWhiteSpace(active.PublicKeyPem)
                        ? TryLoadRsa(active.PublicKeyPem)
                        : (!string.IsNullOrWhiteSpace(active.PrivateKeyPem) ? CreateRsaPublic(CreateOrLoadRsaPrivate(active.PrivateKeyPem)) : null);

                    _state = new KeyState("RS256", active.Kid, rsaPublic, null);
                    return _state;
                }

                var symKey = string.IsNullOrWhiteSpace(active.SymmetricKey) ? null : Encoding.UTF8.GetBytes(active.SymmetricKey);
                _state = new KeyState(alg.ToUpperInvariant(), active.Kid, null, symKey);
                return _state;
            }

            var legacyAlg = string.IsNullOrWhiteSpace(opts.SigningAlgorithm) ? "RS256" : opts.SigningAlgorithm.Trim();
            if (legacyAlg.Equals("RS256", StringComparison.OrdinalIgnoreCase))
            {
                var rsaPrivate = CreateOrLoadRsaPrivate(opts.SigningKey);
                var rsaPublic = RSA.Create();
                rsaPublic.ImportParameters(rsaPrivate.ExportParameters(includePrivateParameters: false));

                var kid = !string.IsNullOrWhiteSpace(opts.Kid)
                    ? opts.Kid!
                    : "rsa";

                _state = new KeyState("RS256", kid, rsaPublic, null);
                return _state;
            }

            var legacySym = string.IsNullOrWhiteSpace(opts.SigningKey)
                ? null
                : Encoding.UTF8.GetBytes(opts.SigningKey);

            var legacyKid = !string.IsNullOrWhiteSpace(opts.Kid)
                ? opts.Kid!
                : "sym";

            _state = new KeyState(legacyAlg.ToUpperInvariant(), legacyKid, null, legacySym);
            return _state;
        }
    }

    private static RSA? TryLoadRsa(string pem)
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

    private static RSA CreateOrLoadRsaPrivate(string? signingKey)
    {
        var rsa = RSA.Create();

        if (string.IsNullOrWhiteSpace(signingKey))
        {
            rsa.KeySize = 2048;
            return rsa;
        }

        if (signingKey.Contains("BEGIN", StringComparison.Ordinal))
        {
            rsa.ImportFromPem(signingKey);
            return rsa;
        }

        try
        {
            var pkcs8 = Convert.FromBase64String(signingKey);
            rsa.ImportPkcs8PrivateKey(pkcs8, out _);
            return rsa;
        }
        catch
        {
            rsa.KeySize = 2048;
            return rsa;
        }
    }
}
