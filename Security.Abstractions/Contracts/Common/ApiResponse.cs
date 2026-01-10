namespace Birdsoft.Security.Abstractions.Contracts.Common;

public sealed record ApiError(
    string Code,
    string? Message = null,
    IReadOnlyDictionary<string, string[]>? Details = null);

public sealed record ApiResponse<T>(
    bool Success,
    T? Data = default,
    ApiError? Error = null)
{
    public static ApiResponse<T> Ok(T data) => new(true, data, null);

    public static ApiResponse<T> Fail(string code, string? message = null, IReadOnlyDictionary<string, string[]>? details = null)
        => new(false, default, new ApiError(code, message, details));
}
