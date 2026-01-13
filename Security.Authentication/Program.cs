using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Audit;
using Birdsoft.Security.Abstractions.Contracts.Auth;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Mfa;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Observability.Correlation;
using Birdsoft.Security.Abstractions.Observability.Health;
using Birdsoft.Security.Abstractions.Observability.Metrics;
using Birdsoft.Security.Abstractions.RateLimiting;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Abstractions.Tenancy;
using Birdsoft.Security.Authentication;
using Birdsoft.Security.Authentication.Auth;
using Birdsoft.Security.Authentication.Jwt;
using Birdsoft.Security.Authentication.Mfa;
using Birdsoft.Security.Authentication.Observability.Health;
using Birdsoft.Security.Authentication.Persistence;
using Birdsoft.Security.Authentication.Tenancy;
using Birdsoft.Security.Authentication.Observability.Logging;
using Birdsoft.Security.Authentication.Authz;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Infrastructure.Logging.Abstractions;
using Birdsoft.Infrastructure.Logging.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

// Central clock (overridable in tests)
builder.Services.AddSingleton(TimeProvider.System);

// Error log (jsonl): auth-error-yyyyMMdd.jsonl
builder.Services.AddBirdsoftJsonLogging(o =>
{
    o.RootDirectory = "logs";
    o.RetentionDays = 30;
});
builder.Services.Replace(ServiceDescriptor.Singleton<ILogFilePathProvider>(sp =>
{
    var options = sp.GetRequiredService<IOptions<JsonLoggingOptions>>().Value;
    var root = options.RootDirectory;
    if (!Path.IsPathRooted(root))
    {
        root = Path.Combine(AppContext.BaseDirectory, root);
    }

    return new AuthErrorLogFilePathProvider(root);
}));

builder.Services.AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection(JwtOptions.SectionName));

builder.Services.AddOptions<SecurityEnvironmentOptions>()
    .Bind(builder.Configuration.GetSection(SecurityEnvironmentOptions.SectionName));

builder.Services.AddOptions<SecuritySafetyOptions>()
    .Bind(builder.Configuration.GetSection(SecuritySafetyOptions.SectionName));

builder.Services.AddOptions<OidcProviderRegistryOptions>()
    .Bind(builder.Configuration.GetSection(OidcProviderRegistryOptions.SectionName));

// Note: single provider options are carried via OidcProviderRegistryOptions.Providers.
builder.Services.AddOptions<OidcProviderOptions>();
builder.Services.AddOptions<PasswordLoginOptions>()
    .Bind(builder.Configuration.GetSection(PasswordLoginOptions.SectionName));

builder.Services.AddOptions<RateLimitingOptions>()
    .Bind(builder.Configuration.GetSection(RateLimitingOptions.SectionName));

builder.Services.AddOptions<BruteForceProtectionOptions>()
    .Bind(builder.Configuration.GetSection(BruteForceProtectionOptions.SectionName));

builder.Services.AddOptions<RefreshTokenHashingOptions>()
    .Bind(builder.Configuration.GetSection(RefreshTokenHashingOptions.SectionName));

builder.Services.AddOptions<MfaOptions>()
    .Bind(builder.Configuration.GetSection(MfaOptions.SectionName));

builder.Services.AddOptions<AuditReliabilityOptions>()
    .Bind(builder.Configuration.GetSection(AuditReliabilityOptions.SectionName));

builder.Services.AddSingleton<IRateLimiterGate, TenantIpRateLimiterGate>();
builder.Services.AddSingleton<IBruteForceProtection, InMemoryBruteForceProtection>();

builder.Services.AddSingleton<IJwtKeyProvider, DefaultJwtKeyProvider>();
builder.Services.AddSingleton<IJwksProvider>(sp => sp.GetRequiredService<IJwtKeyProvider>());

builder.Services.AddTransient<CorrelationIdMiddleware>();

builder.Services.AddSingleton<IMfaPolicyProvider, DefaultMfaPolicyProvider>();
builder.Services.AddSingleton<IMfaChallengeStore, InMemoryMfaChallengeStore>();
builder.Services.AddSingleton<IMfaVerifier, InMemoryMfaVerifier>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("AdminOnly", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(ctx =>
        {
            var user = ctx.User;
            if (user?.Identity?.IsAuthenticated != true)
            {
                return false;
            }

            var scope = user.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scope)?.Value
                ?? user.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scopes)?.Value;
            if (!string.IsNullOrWhiteSpace(scope) && scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Any(s => string.Equals(s, "security.admin", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            var roles = user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Roles).Select(c => c.Value)
                .Concat(user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Role).Select(c => c.Value));
            if (roles.Any(r => string.Equals(r, "security_admin", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            var perms = user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Permissions).Select(c => c.Value);
            return perms.Any(p => string.Equals(p, "security:admin", StringComparison.OrdinalIgnoreCase));
        });
    });

    // Test-only policies (used by /api/v1/test/* endpoints).
    o.AddPolicy(TestAuthorizationPolicies.ScopeRead, policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.AddRequirements(new RequireScopeAuthorizationRequirement(TestAuthorizationPolicies.RequiredScopeRead));
    });

    o.AddPolicy(TestAuthorizationPolicies.AdminRole, policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.AddRequirements(new RequireRoleAuthorizationRequirement(TestAuthorizationPolicies.RequiredRoleAdmin));
    });
});
builder.Services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>, BirdsoftJwtBearerPostConfigureOptions>();

// Emit spec-like JSON bodies for 401/403 produced by authorization middleware.
builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, ApiAuthorizationMiddlewareResultHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, RequireScopeAuthorizationHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, RequireRoleAuthorizationHandler>();

builder.Services.AddSingleton<ITenantResolver, HeaderOrClaimTenantResolver>();
builder.Services.AddScoped<TenantContextAccessor>();
builder.Services.AddTransient<TenantResolutionMiddleware>();

var dbConn = builder.Configuration.GetConnectionString("SecurityDb");
var useEf = !string.IsNullOrWhiteSpace(dbConn);

if (useEf)
{
    builder.Services.AddDbContext<SecurityDbContext>(o => o.UseSqlite(dbConn));
    builder.Services.AddSecurityEfCoreDataAccess();

    builder.Services.AddScoped<IAuthStateService, RepositoryAuthStateService>();
    builder.Services.AddScoped<IExternalIdentityStore, ExternalIdentityStoreFromRepository>();
    builder.Services.AddScoped<ITokenService, RepositoryTokenService>();
}
else
{
    builder.Services.AddSingleton<IAuthEventStore, InMemoryAuthEventStore>();
    builder.Services.AddSingleton<IAuthStateService, InMemoryAuthStateService>();
    builder.Services.AddSingleton<IExternalIdentityStore, InMemoryExternalIdentityStore>();
    builder.Services.AddSingleton<ITenantRepository, InMemoryTenantRepository>();
    builder.Services.AddSingleton<ISubjectRepository, InMemorySubjectRepository>();
    builder.Services.AddSingleton<ISessionStore, InMemorySessionStore>();
    builder.Services.AddSingleton<InMemoryTokenService>();
    builder.Services.AddSingleton<ITokenService>(sp => sp.GetRequiredService<InMemoryTokenService>());
    builder.Services.AddSingleton<Birdsoft.Security.Abstractions.Repositories.IAccessTokenDenylistStore>(sp => sp.GetRequiredService<InMemoryTokenService>());
}

builder.Services.AddScoped<IAuditEventWriter, ResilientAuditEventWriter>();

var hc = builder.Services.AddHealthChecks()
    .AddCheck<JwtKeySourceHealthCheck>("jwt_keys", tags: ["ready"])
    .AddCheck<SessionStoreHealthCheck>("session_store", tags: ["ready"]);

if (useEf)
{
    hc.AddCheck<SecurityDbHealthCheck>("db", tags: ["ready"]);
}

// OIDC Provider sources/services
if (useEf)
{
    // Provided by AddSecurityEfCoreDataAccess(): IOidcProviderRegistry / IOidcProviderService
}
else
{
    builder.Services.AddSingleton<IOidcProviderRegistry, InMemoryOidcProviderRegistry>();
    builder.Services.AddSingleton<IOidcProviderService, InMemoryOidcProviderService>();
}

// In-memory skeleton services (可替換為實際實作)
builder.Services.AddSingleton<IUserProvisioner, InMemoryUserProvisioner>();
builder.Services.AddSingleton<InMemoryAuthorizationDataStore>();
builder.Services.AddSingleton<IAuthorizationDataStore>(sp => sp.GetRequiredService<InMemoryAuthorizationDataStore>());
builder.Services.AddSingleton<IAuthorizationAdminStore>(sp => sp.GetRequiredService<InMemoryAuthorizationDataStore>());
builder.Services.AddSingleton<IPasswordAuthenticator, InMemoryPasswordAuthenticator>();

var app = builder.Build();

// Startup safety checks (enabled by default outside Development)
{
    var envOpts = app.Services.GetRequiredService<IOptionsMonitor<SecurityEnvironmentOptions>>().CurrentValue;
    var safety = app.Services.GetRequiredService<IOptionsMonitor<SecuritySafetyOptions>>().CurrentValue;
    var enabled = safety.Enabled || !app.Environment.IsDevelopment();
    if (enabled)
    {
        var jwt = app.Services.GetRequiredService<IOptionsMonitor<JwtOptions>>().CurrentValue;
        JwtSafetyChecks.ThrowIfUnsafe(jwt, envOpts, safety);
    }
}

if (useEf && app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<SecurityDbContext>();
    _ = db.Database.EnsureCreated();
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Centralized unhandled-exception handler -> error log.
app.UseMiddleware<AuthErrorLoggingMiddleware>();

app.UseHttpsRedirection();
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<TenantResolutionMiddleware>();

var api = app.MapGroup("/api/v1");
var auth = api.MapGroup("/auth");
auth.AddEndpointFilter(new MetricsEndpointFilter("auth"));

// Test-only endpoints (integration test host can enable via TestEndpoints:Enabled=true).
if (app.Configuration.GetValue<bool>("TestEndpoints:Enabled"))
{
    var test = api.MapGroup("/test");

    test.MapGet("/protected", () => Results.Json(ApiResponse<object>.Ok(new { ok = true })))
        .RequireAuthorization();

    test.MapGet("/protected-scope", () => Results.Json(ApiResponse<object>.Ok(new { ok = true })))
        .RequireAuthorization(TestAuthorizationPolicies.ScopeRead);

    test.MapGet("/protected-role", () => Results.Json(ApiResponse<object>.Ok(new { ok = true })))
        .RequireAuthorization(TestAuthorizationPolicies.AdminRole);
}

static IReadOnlyDictionary<string, string[]> SingleField(string field, string message)
    => new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase) { [field] = [message] };

static string? TryGetBearerToken(HttpContext http)
{
    var header = http.Request.Headers.Authorization.ToString();
    if (string.IsNullOrWhiteSpace(header))
    {
        return null;
    }

    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        return null;
    }

    return header["Bearer ".Length..].Trim();
}

static async Task<IResult> PasswordLogin(
    HttpContext http,
    LoginRequest request,
    IPasswordAuthenticator password,
    IBruteForceProtection bruteForce,
    ITenantRepository tenants,
    ISubjectRepository subjects,
    IAuthorizationDataStore authzData,
    ITokenService tokens,
    IMfaPolicyProvider mfaPolicy,
    IMfaChallengeStore mfaChallenges,
    IOptionsMonitor<MfaOptions> mfaOptions,
    IAuditEventWriter audit,
    CancellationToken ct)
{
    var tenant = http.GetTenantContext();
    var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenant.TenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "invalid_request",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(
            ApiResponse<object>.Fail(
                "invalid_request",
                "username/password is required",
                new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
                {
                    ["username"] = ["required"],
                    ["password"] = ["required"],
                }),
            statusCode: StatusCodes.Status400BadRequest);
    }

    var tenantDto = await tenants.FindAsync(tenant.TenantId, ct);
    if (tenantDto is null || tenantDto.Status != Birdsoft.Security.Abstractions.Models.TenantStatus.Active)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenant.TenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "tenant_not_active",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("tenant_not_active"), statusCode: StatusCodes.Status403Forbidden);
    }

    var decision = await bruteForce.CheckAsync(tenant.TenantId, request.Username, ip, ct);
    if (!decision.Allowed)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenant.TenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.BruteForceBlocked,
            Detail = decision.BlockedUntil?.ToString("O"),
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        if (decision.RetryAfterSeconds is int retry)
        {
            http.Response.Headers.RetryAfter = retry.ToString();
        }

        return Results.Json(
            ApiResponse<object>.Fail(Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.BruteForceBlocked),
            statusCode: StatusCodes.Status429TooManyRequests);
    }

    if (decision.Delay > TimeSpan.Zero)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenant.TenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "delay",
            Code = Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.BruteForceDelayed,
            Detail = $"{(int)decision.Delay.TotalMilliseconds}ms",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        await Task.Delay(decision.Delay, ct);
    }

    var authResult = await password.AuthenticateAsync(tenant.TenantId, request.Username, request.Password, ct);
    if (!authResult.Succeeded || authResult.OurSubject is null)
    {
        await bruteForce.RecordFailureAsync(
            tenant.TenantId,
            request.Username,
            ip,
            authResult.ErrorCode ?? Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.InvalidCredentials,
            ct);

        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenant.TenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = authResult.ErrorCode ?? Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.InvalidCredentials,
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(
            ApiResponse<object>.Fail(authResult.ErrorCode ?? Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.InvalidCredentials),
            statusCode: StatusCodes.Status401Unauthorized);
    }

    await bruteForce.RecordSuccessAsync(tenant.TenantId, request.Username, ip, ct);

    var ourSubject = authResult.OurSubject.Value;
    var subjectDto = await subjects.FindAsync(tenant.TenantId, ourSubject, ct) ?? await subjects.CreateAsync(tenant.TenantId, ourSubject, ct);
    if (subjectDto.Status != Birdsoft.Security.Abstractions.Models.UserStatus.Active)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenant.TenantId,
            OurSubject = ourSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "user_not_active",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("user_not_active"), statusCode: StatusCodes.Status403Forbidden);
    }

    var policy = await mfaPolicy.GetPolicyAsync(tenant.TenantId, ourSubject, ct);
    var skipRequested = http.Request.Headers.TryGetValue("X-Mfa-Skip", out var skipHeader)
        && string.Equals(skipHeader.ToString(), "true", StringComparison.OrdinalIgnoreCase);

    if (policy == MfaPolicy.Required)
    {
        try
        {
            var ch = await mfaChallenges.CreateAsync(tenant.TenantId, ourSubject, ttl: TimeSpan.FromMinutes(5), providerHint: "inmemory", cancellationToken: ct);
            return Results.Json(ApiResponse<LoginResult>.Ok(new LoginResult(
                Status: "mfa_required",
                Tokens: null,
                Mfa: new MfaChallengeResponse(ch.ChallengeId, ch.ExpiresAt, true, ch.ProviderHint))),
                statusCode: StatusCodes.Status401Unauthorized);
        }
        catch (Exception ex)
        {
            if (mfaOptions.CurrentValue.AllowSkipOnProviderFailure)
            {
                await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
                {
                    Id = Guid.NewGuid(),
                    OccurredAt = DateTimeOffset.UtcNow,
                    TenantId = tenant.TenantId,
                    OurSubject = ourSubject,
                    Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
                    Outcome = "skip",
                    Code = "mfa_skipped_provider_failure",
                    Detail = ex.GetType().Name,
                    CorrelationId = http.GetCorrelationId(),
                    TraceId = http.GetTraceId(),
                    Ip = ip,
                    UserAgent = http.Request.Headers.UserAgent.ToString(),
                }, ct);
            }
            else
            {
                await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
                {
                    Id = Guid.NewGuid(),
                    OccurredAt = DateTimeOffset.UtcNow,
                    TenantId = tenant.TenantId,
                    OurSubject = ourSubject,
                    Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
                    Outcome = "fail",
                    Code = "mfa_unavailable",
                    Detail = ex.GetType().Name,
                    CorrelationId = http.GetCorrelationId(),
                    TraceId = http.GetTraceId(),
                    Ip = ip,
                    UserAgent = http.Request.Headers.UserAgent.ToString(),
                }, ct);

                return Results.Json(ApiResponse<object>.Fail("mfa_unavailable"), statusCode: StatusCodes.Status503ServiceUnavailable);
            }
        }
    }

    if (policy == MfaPolicy.Optional && skipRequested)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenant.TenantId,
            OurSubject = ourSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
            Outcome = "skip",
            Code = "mfa_skipped",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);
    }

    var roles = await authzData.GetRolesAsync(tenant.TenantId, ourSubject, ct);
    var scopes = await authzData.GetScopesAsync(tenant.TenantId, ourSubject, ct);
    var pair = await tokens.GenerateTokensAsync(tenant.TenantId, ourSubject, roles, scopes, ct);

    Guid? sessionId = null;
    try
    {
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(pair.AccessToken);
        var sessionClaim = jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.SessionId, StringComparison.Ordinal))?.Value;
        if (!string.IsNullOrWhiteSpace(sessionClaim) && Guid.TryParse(sessionClaim, out var parsed))
        {
            sessionId = parsed;
        }
    }
    catch
    {
    }

    await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
    {
        Id = Guid.NewGuid(),
        OccurredAt = DateTimeOffset.UtcNow,
        TenantId = tenant.TenantId,
        OurSubject = ourSubject,
        SessionId = sessionId,
        Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
        Outcome = "success",
        Code = "password_login",
        CorrelationId = http.GetCorrelationId(),
        TraceId = http.GetTraceId(),
        Ip = ip,
        UserAgent = http.Request.Headers.UserAgent.ToString(),
    }, ct);

    await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
    {
        Id = Guid.NewGuid(),
        OccurredAt = DateTimeOffset.UtcNow,
        TenantId = tenant.TenantId,
        OurSubject = ourSubject,
        SessionId = sessionId,
        Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenIssued,
        Outcome = "success",
        Code = "password_login",
        CorrelationId = http.GetCorrelationId(),
        TraceId = http.GetTraceId(),
        Ip = ip,
        UserAgent = http.Request.Headers.UserAgent.ToString(),
    }, ct);

    return Results.Json(ApiResponse<LoginResult>.Ok(new LoginResult(Status: "success", Tokens: pair, Mfa: null)));
}

static async Task<IResult> MfaVerify(
    HttpContext http,
    MfaVerifyRequest request,
    ITenantRepository tenants,
    ISubjectRepository subjects,
    IAuthorizationDataStore authzData,
    ITokenService tokens,
    IMfaChallengeStore mfaChallenges,
    IMfaVerifier mfaVerifier,
    IAuditEventWriter audit,
    CancellationToken ct)
{
    var tenant = http.GetTenantContext();
    var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    if (request.ChallengeId == Guid.Empty || string.IsNullOrWhiteSpace(request.Code))
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenant.TenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
            Outcome = "fail",
            Code = "invalid_request",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("invalid_request"), statusCode: StatusCodes.Status400BadRequest);
    }

    var challenge = await mfaChallenges.FindAsync(request.ChallengeId, ct);
    if (challenge is null)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenant.TenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
            Outcome = "fail",
            Code = "mfa_challenge_not_found",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("mfa_challenge_not_found"), statusCode: StatusCodes.Status400BadRequest);
    }

    if (challenge.TenantId != tenant.TenantId)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenant.TenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
            Outcome = "fail",
            Code = "tenant_mismatch",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("tenant_mismatch"), statusCode: StatusCodes.Status403Forbidden);
    }

    if (challenge.ExpiresAt <= DateTimeOffset.UtcNow)
    {
        _ = await mfaChallenges.ConsumeAsync(challenge.ChallengeId, ct);

        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = challenge.TenantId,
            OurSubject = challenge.OurSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
            Outcome = "fail",
            Code = "mfa_expired",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("mfa_expired"), statusCode: StatusCodes.Status401Unauthorized);
    }

    var tenantDto = await tenants.FindAsync(challenge.TenantId, ct);
    if (tenantDto is not null && tenantDto.Status != Birdsoft.Security.Abstractions.Models.TenantStatus.Active)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = challenge.TenantId,
            OurSubject = challenge.OurSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
            Outcome = "fail",
            Code = "tenant_not_active",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("tenant_not_active"), statusCode: StatusCodes.Status403Forbidden);
    }

    var subjectDto = await subjects.FindAsync(challenge.TenantId, challenge.OurSubject, ct);
    if (subjectDto is null)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = challenge.TenantId,
            OurSubject = challenge.OurSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
            Outcome = "fail",
            Code = Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.UserNotFound,
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail(Birdsoft.Security.Abstractions.Constants.AuthErrorCodes.UserNotFound), statusCode: StatusCodes.Status401Unauthorized);
    }

    if (subjectDto.Status != Birdsoft.Security.Abstractions.Models.UserStatus.Active)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = challenge.TenantId,
            OurSubject = challenge.OurSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
            Outcome = "fail",
            Code = "user_not_active",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("user_not_active"), statusCode: StatusCodes.Status403Forbidden);
    }

    var verify = await mfaVerifier.VerifyAsync(challenge.TenantId, challenge.OurSubject, request.Code, ct);
    if (!verify.Succeeded)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = challenge.TenantId,
            OurSubject = challenge.OurSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
            Outcome = "fail",
            Code = verify.ErrorCode ?? "mfa_failed",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail(verify.ErrorCode ?? "mfa_failed"), statusCode: StatusCodes.Status401Unauthorized);
    }

    var consumed = await mfaChallenges.ConsumeAsync(challenge.ChallengeId, ct);
    if (!consumed)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = challenge.TenantId,
            OurSubject = challenge.OurSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
            Outcome = "fail",
            Code = "mfa_challenge_already_used",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("mfa_challenge_already_used"), statusCode: StatusCodes.Status409Conflict);
    }

    var roles = await authzData.GetRolesAsync(challenge.TenantId, challenge.OurSubject, ct);
    var scopes = await authzData.GetScopesAsync(challenge.TenantId, challenge.OurSubject, ct);
    var pair = await tokens.GenerateTokensAsync(challenge.TenantId, challenge.OurSubject, roles, scopes, ct);

    Guid? sessionId = null;
    try
    {
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(pair.AccessToken);
        var sessionClaim = jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.SessionId, StringComparison.Ordinal))?.Value;
        if (!string.IsNullOrWhiteSpace(sessionClaim) && Guid.TryParse(sessionClaim, out var parsed))
        {
            sessionId = parsed;
        }
    }
    catch
    {
    }

    await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
    {
        Id = Guid.NewGuid(),
        OccurredAt = DateTimeOffset.UtcNow,
        TenantId = challenge.TenantId,
        OurSubject = challenge.OurSubject,
        SessionId = sessionId,
        Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
        Outcome = "success",
        Code = "mfa_verified",
        CorrelationId = http.GetCorrelationId(),
        TraceId = http.GetTraceId(),
        Ip = ip,
        UserAgent = http.Request.Headers.UserAgent.ToString(),
    }, ct);

    await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
    {
        Id = Guid.NewGuid(),
        OccurredAt = DateTimeOffset.UtcNow,
        TenantId = challenge.TenantId,
        OurSubject = challenge.OurSubject,
        SessionId = sessionId,
        Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenIssued,
        Outcome = "success",
        Code = "mfa_verified",
        CorrelationId = http.GetCorrelationId(),
        TraceId = http.GetTraceId(),
        Ip = ip,
        UserAgent = http.Request.Headers.UserAgent.ToString(),
    }, ct);

    return Results.Json(ApiResponse<LoginResult>.Ok(new LoginResult(Status: "success", Tokens: pair, Mfa: null)));
}

static async Task<IResult> TokenRefresh(HttpContext http, RefreshRequest request, ITokenService tokens, IAuditEventWriter audit, CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(request.RefreshToken))
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRefreshed,
            Outcome = "fail",
            Code = "invalid_request",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString(),
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(
            ApiResponse<object>.Fail("invalid_request", "refreshToken is required", SingleField("refreshToken", "required")),
            statusCode: StatusCodes.Status400BadRequest);
    }

    // Tenant comes from header for refresh (no JWT claim on this endpoint).
    var tenant = http.GetTenantContext();
    var result = await tokens.RefreshAsync(tenant.TenantId, request.RefreshToken, ct);
    if (!result.Succeeded)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRefreshed,
            Outcome = "fail",
            Code = result.ErrorCode ?? "invalid_refresh_token",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString(),
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);
    }

    if (result.Succeeded && result.Tokens is not null)
    {
        Guid? sessionId = null;
        try
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(result.Tokens.AccessToken);
            var sessionClaim = jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.SessionId, StringComparison.Ordinal))?.Value;
            if (!string.IsNullOrWhiteSpace(sessionClaim) && Guid.TryParse(sessionClaim, out var parsed))
            {
                sessionId = parsed;
            }
        }
        catch
        {
        }

        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            SessionId = sessionId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRefreshed,
            Outcome = "success",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString(),
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);
    }

    return result.Succeeded && result.Tokens is not null
        ? Results.Json(ApiResponse<TokenPair>.Ok(result.Tokens))
        : Results.Json(ApiResponse<object>.Fail(result.ErrorCode ?? "invalid_refresh_token"), statusCode: StatusCodes.Status401Unauthorized);
}

static async Task<IResult> TokenRevoke(HttpContext http, TokenRevokeRequest request, ITokenService tokens, [Microsoft.AspNetCore.Mvc.FromServices] Birdsoft.Security.Abstractions.Repositories.IAccessTokenDenylistStore denylist, IAuditEventWriter audit, CancellationToken ct)
{
    var bearer = TryGetBearerToken(http);
    if (string.IsNullOrWhiteSpace(bearer))
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRevoked,
            Outcome = "fail",
            Code = "missing_bearer_token",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString(),
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("missing_bearer_token"), statusCode: StatusCodes.Status401Unauthorized);
    }

    var validation = await tokens.ValidateAccessTokenAsync(bearer, ct);
    if (!validation.Succeeded)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRevoked,
            Outcome = "fail",
            Code = validation.ErrorCode ?? "invalid_token",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString(),
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail(validation.ErrorCode ?? "invalid_token"), statusCode: StatusCodes.Status401Unauthorized);
    }

    if (validation.TenantId is null || validation.OurSubject is null)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRevoked,
            Outcome = "fail",
            Code = "invalid_token",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString(),
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("invalid_token"), statusCode: StatusCodes.Status401Unauthorized);
    }

    var tenantId = validation.TenantId.Value;
    var ourSubject = validation.OurSubject.Value;

    // Optional immediate invalidation: add current access token jti to denylist until exp.
    try
    {
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(bearer);
        var jti = jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Jti, StringComparison.Ordinal))?.Value;
        var expRaw = jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, "exp", StringComparison.Ordinal))?.Value;
        if (!string.IsNullOrWhiteSpace(jti) && long.TryParse(expRaw, out var expSeconds))
        {
            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expSeconds);
            await denylist.AddAsync(tenantId, jti, expiresAt, ct);
        }
    }
    catch
    {
    }

    if (request.AllDevices)
    {
        var revoked = await tokens.RevokeAllAsync(tenantId, ourSubject, ct);

        Guid? sessionId = null;
        try
        {
            var jwt = new JwtSecurityTokenHandler().ReadJwtToken(bearer);
            var sessionClaim = jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.SessionId, StringComparison.Ordinal))?.Value;
            if (!string.IsNullOrWhiteSpace(sessionClaim) && Guid.TryParse(sessionClaim, out var parsed))
            {
                sessionId = parsed;
            }
        }
        catch
        {
        }

        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenantId,
            OurSubject = ourSubject,
            SessionId = sessionId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRevoked,
            Outcome = "success",
            Code = "revoke_all",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString(),
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<TokenRevokeResponse>.Ok(new TokenRevokeResponse(revoked)));
    }

    if (string.IsNullOrWhiteSpace(request.RefreshToken))
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenantId,
            OurSubject = ourSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRevoked,
            Outcome = "fail",
            Code = "invalid_request",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString(),
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(
            ApiResponse<object>.Fail("invalid_request", "refreshToken is required unless allDevices=true", SingleField("refreshToken", "required")),
            statusCode: StatusCodes.Status400BadRequest);
    }

    var result = await tokens.RevokeAsync(tenantId, ourSubject, request.RefreshToken, ct);
    if (!result.Succeeded)
    {
        var status = string.Equals(result.ErrorCode, "forbidden", StringComparison.Ordinal)
            ? StatusCodes.Status403Forbidden
            : StatusCodes.Status400BadRequest;

        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenantId,
            OurSubject = ourSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRevoked,
            Outcome = "fail",
            Code = result.ErrorCode ?? "revoke_failed",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString(),
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail(result.ErrorCode ?? "revoke_failed"), statusCode: status);
    }

    Guid? revokedSessionId = null;
    try
    {
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(bearer);
        var sessionClaim = jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.SessionId, StringComparison.Ordinal))?.Value;
        if (!string.IsNullOrWhiteSpace(sessionClaim) && Guid.TryParse(sessionClaim, out var parsed))
        {
            revokedSessionId = parsed;
        }
    }
    catch
    {
    }

    await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
    {
        Id = Guid.NewGuid(),
        OccurredAt = DateTimeOffset.UtcNow,
        TenantId = tenantId,
        OurSubject = ourSubject,
        SessionId = revokedSessionId,
        Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRevoked,
        Outcome = "success",
        CorrelationId = http.GetCorrelationId(),
        TraceId = http.GetTraceId(),
        Ip = http.Connection.RemoteIpAddress?.ToString(),
        UserAgent = http.Request.Headers.UserAgent.ToString(),
    }, ct);

    return Results.Json(ApiResponse<TokenRevokeResponse>.Ok(new TokenRevokeResponse(1)));
}

static async Task<IResult> OidcChallenge(
    HttpContext http,
    string provider,
    IAuthStateService authState,
    IOidcProviderRegistry registry,
    IOidcProviderService oidc,
    ITenantRepository tenants,
    CancellationToken ct)
{
    var tenant = http.GetTenantContext();

    var tenantDto = await tenants.FindAsync(tenant.TenantId, ct);
    if (tenantDto is not null && tenantDto.Status != Birdsoft.Security.Abstractions.Models.TenantStatus.Active)
    {
        return Results.Json(ApiResponse<object>.Fail("tenant_not_active"), statusCode: StatusCodes.Status403Forbidden);
    }

    var opts = await registry.GetAsync(tenant.TenantId, provider, ct);
    if (opts is null)
    {
        return Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "Provider not enabled");
    }

    var stateInfo = await authState.CreateStateAsync(tenant.TenantId, ct);
    var codeVerifier = Pkce.CreateCodeVerifier();
    var nonce = Nonce.Create();
    _ = await authState.TryAttachOidcContextAsync(stateInfo.State, codeVerifier, nonce, ct);

    var url = await oidc.GetAuthorizationUrlAsync(
        tenant.TenantId,
        provider,
        stateInfo.State,
        nonce,
        cancellationToken: ct);
    return Results.Redirect(url);
}

static async Task<IResult> OidcCallback(
    HttpContext http,
    string provider,
    string? code,
    string? state,
    string? error,
    IAuthStateService authState,
    IOidcProviderService oidc,
    IExternalIdentityStore externalStore,
    IUserProvisioner provisioner,
    ITenantRepository tenants,
    ISubjectRepository subjects,
    IAuthorizationDataStore authzData,
    ITokenService tokens,
    IMfaPolicyProvider mfaPolicy,
    IMfaChallengeStore mfaChallenges,
    IOptionsMonitor<MfaOptions> mfaOptions,
    IAuditEventWriter audit,
    CancellationToken ct)
{
    var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    if (!string.IsNullOrWhiteSpace(error))
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "oidc_error",
            Detail = error,
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("oidc_error", error), statusCode: StatusCodes.Status400BadRequest);
    }

    if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(state))
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "invalid_request",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("invalid_request", "Missing code/state"), statusCode: StatusCodes.Status400BadRequest);
    }

    var ctx = await authState.ConsumeStateAsync(state, ct);
    if (ctx is null)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "invalid_state",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("invalid_state"), statusCode: StatusCodes.Status400BadRequest);
    }

    // Optional hardening: if callers provide X-Tenant-Id, it must match the state-bound tenant.
    // Real OIDC provider callbacks won't include this header; those should continue to work.
    if (http.Request.Headers.TryGetValue("X-Tenant-Id", out var tenantHeader)
        && Guid.TryParse(tenantHeader.ToString(), out var headerTenantId)
        && headerTenantId != ctx.TenantId)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = headerTenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "invalid_state",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        // Avoid leaking which tenant a state belongs to.
        return Results.Json(ApiResponse<object>.Fail("invalid_state"), statusCode: StatusCodes.Status400BadRequest);
    }

    var tenantDto = await tenants.FindAsync(ctx.TenantId, ct);
    if (tenantDto is not null && tenantDto.Status != Birdsoft.Security.Abstractions.Models.TenantStatus.Active)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = ctx.TenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "tenant_not_active",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("tenant_not_active"), statusCode: StatusCodes.Status403Forbidden);
    }

    var enabled = await oidc.IsTenantProviderEnabledAsync(ctx.TenantId, provider, ct);
    if (!enabled)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = ctx.TenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "provider_not_enabled",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("provider_not_enabled"), statusCode: StatusCodes.Status403Forbidden);
    }

    OidcUserInfo userInfo;
    try
    {
        userInfo = await oidc.ExchangeCodeAsync(ctx.TenantId, provider, code, ctx, cancellationToken: ct);
    }
    catch (Exception ex)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = ctx.TenantId,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "oidc_exchange_failed",
            Detail = ex.GetType().Name,
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("oidc_exchange_failed"), statusCode: StatusCodes.Status400BadRequest);
    }

    var key = new Birdsoft.Security.Abstractions.Identity.ExternalIdentityKey(ctx.TenantId, provider, userInfo.Issuer, userInfo.ProviderSub);
    var mapping = await externalStore.FindMappingAsync(key, ct);

    if (mapping is not null && !mapping.Enabled)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = ctx.TenantId,
            OurSubject = mapping.OurSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "external_identity_disabled",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("external_identity_disabled"), statusCode: StatusCodes.Status403Forbidden);
    }

    var ourSubject = mapping?.OurSubject ?? await provisioner.ProvisionAsync(ctx.TenantId, key, userInfo, ct);

    var subjectDto = await subjects.FindAsync(ctx.TenantId, ourSubject, ct) ?? await subjects.CreateAsync(ctx.TenantId, ourSubject, ct);
    if (subjectDto.Status != Birdsoft.Security.Abstractions.Models.UserStatus.Active)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = ctx.TenantId,
            OurSubject = ourSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication,
            Outcome = "fail",
            Code = "user_not_active",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("user_not_active"), statusCode: StatusCodes.Status403Forbidden);
    }

    if (mapping is null)
    {
        _ = await externalStore.CreateMappingAsync(new Birdsoft.Security.Abstractions.Identity.ExternalIdentityMapping(
            ctx.TenantId,
            ourSubject,
            provider,
            userInfo.Issuer,
            userInfo.ProviderSub,
            DateTimeOffset.UtcNow), ct);
    }

    var policy = await mfaPolicy.GetPolicyAsync(ctx.TenantId, ourSubject, ct);
    var skipRequested = http.Request.Headers.TryGetValue("X-Mfa-Skip", out var skipHeader)
        && string.Equals(skipHeader.ToString(), "true", StringComparison.OrdinalIgnoreCase);

    if (policy == MfaPolicy.Required)
    {
        try
        {
            var ch = await mfaChallenges.CreateAsync(ctx.TenantId, ourSubject, ttl: TimeSpan.FromMinutes(5), providerHint: "inmemory", cancellationToken: ct);
            return Results.Json(ApiResponse<LoginResult>.Ok(new LoginResult(
                Status: "mfa_required",
                Tokens: null,
                Mfa: new MfaChallengeResponse(ch.ChallengeId, ch.ExpiresAt, true, ch.ProviderHint))),
                statusCode: StatusCodes.Status401Unauthorized);
        }
        catch (Exception ex)
        {
            if (mfaOptions.CurrentValue.AllowSkipOnProviderFailure)
            {
                await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
                {
                    Id = Guid.NewGuid(),
                    OccurredAt = DateTimeOffset.UtcNow,
                    TenantId = ctx.TenantId,
                    OurSubject = ourSubject,
                    Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
                    Outcome = "skip",
                    Code = "mfa_skipped_provider_failure",
                    Detail = ex.GetType().Name,
                    CorrelationId = http.GetCorrelationId(),
                    TraceId = http.GetTraceId(),
                    Ip = ip,
                    UserAgent = http.Request.Headers.UserAgent.ToString(),
                }, ct);
            }
            else
            {
                await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
                {
                    Id = Guid.NewGuid(),
                    OccurredAt = DateTimeOffset.UtcNow,
                    TenantId = ctx.TenantId,
                    OurSubject = ourSubject,
                    Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
                    Outcome = "fail",
                    Code = "mfa_unavailable",
                    Detail = ex.GetType().Name,
                    CorrelationId = http.GetCorrelationId(),
                    TraceId = http.GetTraceId(),
                    Ip = ip,
                    UserAgent = http.Request.Headers.UserAgent.ToString(),
                }, ct);
                return Results.Json(ApiResponse<object>.Fail("mfa_unavailable"), statusCode: StatusCodes.Status503ServiceUnavailable);
            }
        }
    }

    if (policy == MfaPolicy.Optional && skipRequested)
    {
        await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = ctx.TenantId,
            OurSubject = ourSubject,
            Type = Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa,
            Outcome = "skip",
            Code = "mfa_skipped",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);
    }

    var roles = await authzData.GetRolesAsync(ctx.TenantId, ourSubject, ct);
    var scopes = await authzData.GetScopesAsync(ctx.TenantId, ourSubject, ct);
    var pair = await tokens.GenerateTokensAsync(ctx.TenantId, ourSubject, roles, scopes, ct);

    Guid? sessionId = null;
    try
    {
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(pair.AccessToken);
        var sessionClaim = jwt.Claims.FirstOrDefault(c => string.Equals(c.Type, Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.SessionId, StringComparison.Ordinal))?.Value;
        if (!string.IsNullOrWhiteSpace(sessionClaim) && Guid.TryParse(sessionClaim, out var parsed))
        {
            sessionId = parsed;
        }
    }
    catch
    {
    }

    await audit.WriteAsync(new Birdsoft.Security.Abstractions.Models.AuthEvent
    {
        Id = Guid.NewGuid(),
        OccurredAt = DateTimeOffset.UtcNow,
        TenantId = ctx.TenantId,
        OurSubject = ourSubject,
        SessionId = sessionId,
        Type = Birdsoft.Security.Abstractions.Models.AuthEventType.TokenIssued,
        Outcome = "success",
        Code = $"oidc:{provider}",
        CorrelationId = http.GetCorrelationId(),
        TraceId = http.GetTraceId(),
        Ip = ip,
        UserAgent = http.Request.Headers.UserAgent.ToString(),
    }, ct);

    return Results.Json(ApiResponse<LoginResult>.Ok(new LoginResult(Status: "success", Tokens: pair, Mfa: null)));
}

auth.MapPost("/password/login", PasswordLogin)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication));

auth.MapPost("/mfa/verify", MfaVerify)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa));

auth.MapGet("/oidc/{provider}/challenge", OidcChallenge)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication));

auth.MapGet("/oidc/{provider}/callback", OidcCallback)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication));

auth.MapPost("/token/refresh", TokenRefresh)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRefreshed));

// Legacy alias: prefer POST /api/v1/auth/token/revoke
auth.MapPost("/logout", TokenRevoke)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRevoked));

auth.MapPost("/token/revoke", TokenRevoke)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRevoked));

// Legacy route mappings (temporary compatibility)
var legacyAuth = app.MapGroup("/auth");
legacyAuth.MapPost("/login", PasswordLogin)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication));
legacyAuth.MapPost("/mfa/verify", MfaVerify)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.Mfa));
legacyAuth.MapPost("/refresh", TokenRefresh)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRefreshed));
legacyAuth.MapPost("/logout", TokenRevoke)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRevoked));
legacyAuth.MapPost("/token/revoke", TokenRevoke)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.TokenRevoked));
legacyAuth.MapGet("/oidc/{provider}/challenge", OidcChallenge)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication));
legacyAuth.MapGet("/oidc/{provider}/callback", OidcCallback)
    .AddEndpointFilter(new RateLimitEndpointFilter("auth_sensitive", Birdsoft.Security.Abstractions.Models.AuthEventType.Authentication));

app.MapGet("/.well-known/jwks.json", (IJwtKeyProvider keys) => Results.Ok(keys.GetJwksDocument()));

app.MapGet("/metrics", () => Results.Text(SecurityMetrics.ToPrometheusText(SecurityMetrics.Snapshot()), "text/plain"));

app.MapHealthChecks("/health", new HealthCheckOptions
{
    Predicate = _ => true,
});

app.MapHealthChecks("/ready", new HealthCheckOptions
{
    Predicate = r => r.Tags.Contains("ready"),
    ResultStatusCodes =
    {
        [HealthStatus.Healthy] = StatusCodes.Status200OK,
        [HealthStatus.Degraded] = StatusCodes.Status503ServiceUnavailable,
        [HealthStatus.Unhealthy] = StatusCodes.Status503ServiceUnavailable,
    }
});

app.Run();

public partial class Program { }
