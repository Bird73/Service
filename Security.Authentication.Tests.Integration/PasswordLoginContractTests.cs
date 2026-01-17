namespace Birdsoft.Security.Authentication.Tests.Integration;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Contracts.Auth;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Mfa;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

public sealed class PasswordLoginContractTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static HttpRequestMessage CreateLoginRequest(Guid tenantId, string? username, string? password)
    {
        var msg = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/password/login");
        msg.Headers.Add("X-Tenant-Id", tenantId.ToString());
        msg.Content = JsonContent.Create(new LoginRequest(username ?? string.Empty, password ?? string.Empty));
        return msg;
    }

    [Fact]
    public async Task Missing_Required_Fields_Returns_400_InvalidRequest_With_ApiResponseFail()
    {
        var tenantId = Guid.NewGuid();
        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            TenantId = tenantId,
            Tenants = new StubTenantRepository(new TenantDto { TenantId = tenantId, Name = "t", Status = TenantStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            BruteForce = new StubBruteForceProtection(new BruteForceDecision(true, TimeSpan.Zero, null)),
            Password = new StubPasswordAuthenticator(PasswordAuthResult.Fail(AuthErrorCodes.InvalidCredentials)),
        });

        var client = factory.CreateClient();
        using var req = CreateLoginRequest(tenantId, username: "", password: "");

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.False(body!.Success);
        Assert.NotNull(body.Error);
        Assert.Equal("invalid_request", body.Error!.Code);
    }

    [Fact]
    public async Task Tenant_Not_Found_Returns_403_TenantNotActive()
    {
        var tenantId = Guid.NewGuid();
        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            TenantId = tenantId,
            Tenants = new StubTenantRepository(null),
            BruteForce = new StubBruteForceProtection(new BruteForceDecision(true, TimeSpan.Zero, null)),
            Password = new StubPasswordAuthenticator(PasswordAuthResult.Fail(AuthErrorCodes.InvalidCredentials)),
        });

        var client = factory.CreateClient();
        using var req = CreateLoginRequest(tenantId, username: "alice", password: "pw");

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.False(body!.Success);
        Assert.Equal("tenant_not_active", body.Error!.Code);
    }

    [Fact]
    public async Task Tenant_Not_Active_Returns_403_TenantNotActive()
    {
        var tenantId = Guid.NewGuid();
        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            TenantId = tenantId,
            Tenants = new StubTenantRepository(new TenantDto { TenantId = tenantId, Name = "t", Status = TenantStatus.Suspended, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            BruteForce = new StubBruteForceProtection(new BruteForceDecision(true, TimeSpan.Zero, null)),
            Password = new StubPasswordAuthenticator(PasswordAuthResult.Fail(AuthErrorCodes.InvalidCredentials)),
        });

        var client = factory.CreateClient();
        using var req = CreateLoginRequest(tenantId, username: "alice", password: "pw");

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.False(body!.Success);
        Assert.Equal("tenant_not_active", body.Error!.Code);
    }

    [Fact]
    public async Task User_Not_Active_Returns_403_UserNotActive()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            TenantId = tenantId,
            Tenants = new StubTenantRepository(new TenantDto { TenantId = tenantId, Name = "t", Status = TenantStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            BruteForce = new StubBruteForceProtection(new BruteForceDecision(true, TimeSpan.Zero, null)),
            Password = new StubPasswordAuthenticator(PasswordAuthResult.Success(ourSubject)),
            Subjects = new StubSubjectRepository(new SubjectDto { TenantId = tenantId, OurSubject = ourSubject, Status = UserStatus.Disabled, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
        });

        var client = factory.CreateClient();
        using var req = CreateLoginRequest(tenantId, username: "alice", password: "pw");

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.False(body!.Success);
        Assert.Equal("user_not_active", body.Error!.Code);
    }

    [Fact]
    public async Task Password_Wrong_Below_Threshold_Returns_401_InvalidCredentials()
    {
        var tenantId = Guid.NewGuid();

        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            TenantId = tenantId,
            Tenants = new StubTenantRepository(new TenantDto { TenantId = tenantId, Name = "t", Status = TenantStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            BruteForce = new StubBruteForceProtection(new BruteForceDecision(true, TimeSpan.Zero, null)),
            Password = new StubPasswordAuthenticator(PasswordAuthResult.Fail(AuthErrorCodes.InvalidCredentials)),
        });

        var client = factory.CreateClient();
        using var req = CreateLoginRequest(tenantId, username: "alice", password: "bad");

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.False(body!.Success);
        Assert.Equal(AuthErrorCodes.InvalidCredentials, body.Error!.Code);
    }

    [Fact]
    public async Task BruteForce_Blocked_Returns_429_With_RetryAfter()
    {
        var tenantId = Guid.NewGuid();
        var blockedUntil = DateTimeOffset.UtcNow.AddSeconds(30);

        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            TenantId = tenantId,
            Tenants = new StubTenantRepository(new TenantDto { TenantId = tenantId, Name = "t", Status = TenantStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            BruteForce = new StubBruteForceProtection(new BruteForceDecision(false, TimeSpan.Zero, blockedUntil)),
            Password = new StubPasswordAuthenticator(PasswordAuthResult.Fail(AuthErrorCodes.InvalidCredentials)),
        });

        var client = factory.CreateClient();
        using var req = CreateLoginRequest(tenantId, username: "alice", password: "bad");

        var res = await client.SendAsync(req);
        Assert.Equal((HttpStatusCode)429, res.StatusCode);
        Assert.True(res.Headers.TryGetValues("Retry-After", out var values));
        Assert.True(int.TryParse(values!.FirstOrDefault(), out var retryAfter));
        Assert.True(retryAfter >= 0);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<object>>(JsonOptions);
        Assert.NotNull(body);
        Assert.False(body!.Success);
        Assert.Equal(AuthErrorCodes.BruteForceBlocked, body.Error!.Code);
    }

    [Fact]
    public async Task Mfa_Required_Returns_401_With_Challenge_Payload()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();
        var challenge = new MfaChallenge(Guid.NewGuid(), tenantId, ourSubject, DateTimeOffset.UtcNow.AddMinutes(5), "inmemory");

        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            TenantId = tenantId,
            Tenants = new StubTenantRepository(new TenantDto { TenantId = tenantId, Name = "t", Status = TenantStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            BruteForce = new StubBruteForceProtection(new BruteForceDecision(true, TimeSpan.Zero, null)),
            Password = new StubPasswordAuthenticator(PasswordAuthResult.Success(ourSubject)),
            Subjects = new StubSubjectRepository(new SubjectDto { TenantId = tenantId, OurSubject = ourSubject, Status = UserStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            Authz = new StubAuthorizationDataStore(),
            MfaPolicy = new StubMfaPolicyProvider(MfaPolicy.Required),
            MfaChallenges = new StubMfaChallengeStore(challenge),
        });

        var client = factory.CreateClient();
        using var req = CreateLoginRequest(tenantId, username: "alice", password: "pw");

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
        Assert.NotNull(body);
        Assert.True(body!.Success);
        Assert.NotNull(body.Data);
        Assert.Equal("mfa_required", body.Data!.Status);
        Assert.Null(body.Data.Tokens);
        Assert.NotNull(body.Data.Mfa);
        Assert.NotEqual(Guid.Empty, body.Data.Mfa!.ChallengeId);
        Assert.True(body.Data.Mfa.ExpiresAt > DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Mfa_Provider_Failure_With_AllowSkip_Issues_Tokens()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();
        var challenge = new MfaChallenge(Guid.NewGuid(), tenantId, ourSubject, DateTimeOffset.UtcNow.AddMinutes(5), "inmemory");

        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            TenantId = tenantId,
            AllowSkipOnMfaProviderFailure = true,
            Tenants = new StubTenantRepository(new TenantDto { TenantId = tenantId, Name = "t", Status = TenantStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            BruteForce = new StubBruteForceProtection(new BruteForceDecision(true, TimeSpan.Zero, null)),
            Password = new StubPasswordAuthenticator(PasswordAuthResult.Success(ourSubject)),
            Subjects = new StubSubjectRepository(new SubjectDto { TenantId = tenantId, OurSubject = ourSubject, Status = UserStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            Authz = new StubAuthorizationDataStore(),
            MfaPolicy = new StubMfaPolicyProvider(MfaPolicy.Required),
            MfaChallenges = new StubMfaChallengeStore(challenge, throwOnCreate: true),
        });

        var client = factory.CreateClient();
        using var req = CreateLoginRequest(tenantId, username: "alice", password: "pw");

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
        Assert.NotNull(body);
        Assert.True(body!.Success);
        Assert.NotNull(body.Data);
        Assert.Equal("success", body.Data!.Status);
        Assert.NotNull(body.Data.Tokens);
        Assert.False(string.IsNullOrWhiteSpace(body.Data.Tokens!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(body.Data.Tokens.RefreshToken));
    }

    [Fact]
    public async Task Successful_Login_Returns_200_With_Tokens_And_Required_Jwt_Claims()
    {
        var tenantId = Guid.NewGuid();
        var ourSubject = Guid.NewGuid();

        using var factory = new AuthenticationApiFactory(new AuthenticationApiFactory.Overrides
        {
            TenantId = tenantId,
            Tenants = new StubTenantRepository(new TenantDto { TenantId = tenantId, Name = "t", Status = TenantStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            BruteForce = new StubBruteForceProtection(new BruteForceDecision(true, TimeSpan.Zero, null)),
            Password = new StubPasswordAuthenticator(PasswordAuthResult.Success(ourSubject)),
            Subjects = new StubSubjectRepository(new SubjectDto { TenantId = tenantId, OurSubject = ourSubject, Status = UserStatus.Active, TokenVersion = 1, CreatedAt = DateTimeOffset.UtcNow }),
            Authz = new StubAuthorizationDataStore(),
            MfaPolicy = new StubMfaPolicyProvider(MfaPolicy.Disabled),
        });

        var client = factory.CreateClient();
        using var req = CreateLoginRequest(tenantId, username: "alice", password: "pw");

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        var body = await res.Content.ReadFromJsonAsync<ApiResponse<LoginResult>>(JsonOptions);
        Assert.NotNull(body);
        Assert.True(body!.Success);
        Assert.NotNull(body.Data);
        Assert.Equal("success", body.Data!.Status);
        Assert.NotNull(body.Data.Tokens);

        var access = body.Data.Tokens!.AccessToken;
        var refresh = body.Data.Tokens.RefreshToken;
        Assert.False(string.IsNullOrWhiteSpace(access));
        Assert.False(string.IsNullOrWhiteSpace(refresh));

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(access);
        Assert.False(string.IsNullOrWhiteSpace(jwt.Issuer));
        Assert.NotEmpty(jwt.Audiences);
        Assert.True(jwt.ValidTo > DateTime.UtcNow);

        // Standard required fields
        Assert.Contains(jwt.Claims, c => c.Type == JwtRegisteredClaimNames.Iat);
        Assert.Contains(jwt.Claims, c => c.Type == JwtRegisteredClaimNames.Nbf);
        Assert.Contains(jwt.Claims, c => c.Type == JwtRegisteredClaimNames.Jti);
        Assert.Contains(jwt.Claims, c => c.Type == JwtRegisteredClaimNames.Sub);

        // Required custom fields
        Assert.Contains(jwt.Claims, c => c.Type == SecurityClaimTypes.TenantId && c.Value == tenantId.ToString());
        Assert.Contains(jwt.Claims, c => c.Type == SecurityClaimTypes.SessionId && Guid.TryParse(c.Value, out _));
        Assert.Contains(jwt.Claims, c => c.Type == SecurityClaimTypes.TokenType && string.Equals(c.Value, "access", StringComparison.OrdinalIgnoreCase));
    }
}
