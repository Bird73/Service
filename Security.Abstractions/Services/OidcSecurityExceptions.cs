namespace Birdsoft.Security.Abstractions.Services;

/// <summary>
/// Thrown when the OIDC ID token nonce does not match the state-bound nonce.
/// </summary>
public sealed class OidcNonceMismatchException : Exception
{
    public OidcNonceMismatchException()
    {
    }

    public OidcNonceMismatchException(string? message) : base(message)
    {
    }

    public OidcNonceMismatchException(string? message, Exception? innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// Thrown when the OAuth/OIDC PKCE code_verifier does not match the state-bound code_verifier.
/// </summary>
public sealed class OidcPkceMismatchException : Exception
{
    public OidcPkceMismatchException()
    {
    }

    public OidcPkceMismatchException(string? message) : base(message)
    {
    }

    public OidcPkceMismatchException(string? message, Exception? innerException) : base(message, innerException)
    {
    }
}
