namespace Birdsoft.Security.Abstractions.Services;

public interface IPasswordAuthenticator
{
    ValueTask<PasswordAuthResult> AuthenticateAsync(
        Guid tenantId,
        string username,
        string password,
        CancellationToken cancellationToken = default);
}

public sealed record PasswordAuthResult
{
    public bool Succeeded { get; init; }
    public string? ErrorCode { get; init; }
    public Guid? OurSubject { get; init; }

    public static PasswordAuthResult Success(Guid ourSubject) => new() { Succeeded = true, OurSubject = ourSubject };
    public static PasswordAuthResult Fail(string errorCode) => new() { Succeeded = false, ErrorCode = errorCode };
}
