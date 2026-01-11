namespace Birdsoft.Security.Abstractions.RateLimiting;

public sealed record RateLimitDecision(bool Allowed, int? RetryAfterSeconds);
