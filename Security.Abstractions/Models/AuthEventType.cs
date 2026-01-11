namespace Birdsoft.Security.Abstractions.Models;

public enum AuthEventType
{
    Authentication = 0,
    Authorization = 1,
    TokenIssued = 2,
    TokenRefreshed = 3,
    TokenRevoked = 4,
    SessionTerminated = 5,
    SecurityDefense = 6,
    Mfa = 7,
}
