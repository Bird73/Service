namespace Birdsoft.Security.Abstractions.Services;

/// <summary>
/// Minimal abstraction for producing a JWKS document.
/// Hosts can implement this over any key source (in-memory, DB-backed, KMS, etc.).
/// </summary>
public interface IJwksProvider
{
    object GetJwksDocument();
}
