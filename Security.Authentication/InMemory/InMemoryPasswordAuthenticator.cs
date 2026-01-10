namespace Birdsoft.Security.Authentication;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Services;
using Microsoft.Extensions.Options;

public sealed class InMemoryPasswordAuthenticator : IPasswordAuthenticator
{
    private readonly IOptionsMonitor<PasswordLoginOptions> _options;

    public InMemoryPasswordAuthenticator(IOptionsMonitor<PasswordLoginOptions> options)
    {
        _options = options;
    }

    public ValueTask<PasswordAuthResult> AuthenticateAsync(Guid tenantId, string username, string password, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = cancellationToken;

        var opts = _options.CurrentValue;
        if (!opts.Enabled)
        {
            return ValueTask.FromResult(PasswordAuthResult.Fail("password_login_disabled"));
        }

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return ValueTask.FromResult(PasswordAuthResult.Fail("invalid_request"));
        }

        var user = opts.Users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
        if (user is null)
        {
            return ValueTask.FromResult(PasswordAuthResult.Fail("invalid_credentials"));
        }

        if (!string.Equals(user.Password, password, StringComparison.Ordinal))
        {
            return ValueTask.FromResult(PasswordAuthResult.Fail("invalid_credentials"));
        }

        return ValueTask.FromResult(PasswordAuthResult.Success(user.OurSubject));
    }
}
