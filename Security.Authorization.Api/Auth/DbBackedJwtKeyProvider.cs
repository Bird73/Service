namespace Birdsoft.Security.Authorization.Api.Auth;

using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// DB-backed JWT validation key provider. If no DB signing keys exist, falls back to the legacy options-based provider.
/// </summary>
public sealed class DbBackedJwtKeyProvider : IJwtKeyProvider
{
    private sealed record KeyState(
        string Algorithm,
        string Kid,
        RSA? RsaPublic,
        byte[]? SymmetricKeyBytes,
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

    public RSA? GetRsaPublicKey() => Ensure().RsaPublic;

    public byte[]? GetSymmetricKeyBytes() => Ensure().SymmetricKeyBytes;

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
            RSA? rsaPublic = null;
            if (!string.IsNullOrWhiteSpace(active.PrivateKeyPem))
            {
                try
                {
                    using var rsaPrivate = RSA.Create();
                    rsaPrivate.ImportFromPem(active.PrivateKeyPem);
                    rsaPublic = RSA.Create();
                    rsaPublic.ImportParameters(rsaPrivate.ExportParameters(includePrivateParameters: false));
                }
                catch
                {
                    rsaPublic = null;
                }
            }

            return new KeyState("RS256", active.Kid, rsaPublic, null, FromDb: true);
        }

        var sym = string.IsNullOrWhiteSpace(active.SymmetricKey) ? null : Encoding.UTF8.GetBytes(active.SymmetricKey);
        return new KeyState(alg, active.Kid, null, sym, FromDb: true);
    }

    private KeyState FromFallback()
        => new(
            _fallback.Algorithm,
            _fallback.Kid,
            _fallback.GetRsaPublicKey(),
            _fallback.GetSymmetricKeyBytes(),
            FromDb: false);
}
