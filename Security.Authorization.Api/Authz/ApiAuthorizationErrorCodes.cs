namespace Birdsoft.Security.Authorization.Api.Authz;

public static class ApiAuthorizationErrorCodes
{
    public const string MissingBearerToken = "missing_bearer_token";
    public const string InvalidToken = "invalid_token";
    public const string Forbidden = "forbidden";
    public const string InsufficientScope = "insufficient_scope";
}
