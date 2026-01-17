namespace Birdsoft.Security.Authentication.Persistence;

using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Microsoft.Extensions.Options;

public sealed class RepositoryPasswordAuthenticator : IPasswordAuthenticator
{
    private readonly IOptionsMonitor<PasswordLoginOptions> _options;
    private readonly ILocalAccountRepository _localAccounts;

    public RepositoryPasswordAuthenticator(
        IOptionsMonitor<PasswordLoginOptions> options,
        ILocalAccountRepository localAccounts)
    {
        _options = options;
        _localAccounts = localAccounts;
    }

    public async ValueTask<PasswordAuthResult> AuthenticateAsync(
        Guid tenantId,
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        if (!_options.CurrentValue.Enabled)
        {
            return PasswordAuthResult.Fail("password_login_disabled");
        }

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return PasswordAuthResult.Fail("invalid_request");
        }

        var ourSubject = await _localAccounts.VerifyPasswordAsync(tenantId, username, password, cancellationToken);
        return ourSubject is Guid s
            ? PasswordAuthResult.Success(s)
            : PasswordAuthResult.Fail("invalid_credentials");
    }
}
