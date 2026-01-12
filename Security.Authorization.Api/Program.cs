using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Contracts.Authz;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Audit;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Observability.Correlation;
using Birdsoft.Security.Abstractions.Observability.Health;
using Birdsoft.Security.Abstractions.Observability.Metrics;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authorization.Evaluation;
using Birdsoft.Security.Authorization.Api.Auth;
using Birdsoft.Security.Authorization.Api.Observability.Health;
using Birdsoft.Security.Authorization.Api.Observability.Logging;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Infrastructure.Logging.Abstractions;
using Birdsoft.Infrastructure.Logging.Json;
using Microsoft.Extensions.DependencyInjection.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

// Error log (jsonl): auth-error-yyyyMMdd.jsonl (shared with Authentication service)
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

builder.Services.AddOptions<AuditReliabilityOptions>()
    .Bind(builder.Configuration.GetSection(AuditReliabilityOptions.SectionName));

builder.Services.AddSingleton<IJwtKeyProvider, DefaultJwtKeyProvider>();

builder.Services.AddTransient<CorrelationIdMiddleware>();
builder.Services.AddScoped<IAuditEventWriter, ResilientAuditEventWriter>();

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
});
builder.Services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>, BirdsoftJwtBearerPostConfigureOptions>();

var dbConn = builder.Configuration.GetConnectionString("SecurityDb");
var useEf = !string.IsNullOrWhiteSpace(dbConn);

if (useEf)
{
    builder.Services.AddDbContext<SecurityDbContext>(o => o.UseSqlite(dbConn));
    builder.Services.AddSecurityEfCoreDataAccess();
}
else
{
    builder.Services.AddSingleton<Birdsoft.Security.Abstractions.Repositories.ITenantRepository, InMemoryTenantRepository>();
    builder.Services.AddSingleton<Birdsoft.Security.Abstractions.Repositories.ISubjectRepository, InMemorySubjectRepository>();
    builder.Services.AddSingleton<ISessionStore, AllowAllSessionStore>();
    builder.Services.AddSingleton<IAuthEventStore, InMemoryAuthEventStore>();
}

var hc = builder.Services.AddHealthChecks()
    .AddCheck<JwtValidationKeyHealthCheck>("jwt_keys", tags: ["ready"])
    .AddCheck<SessionStoreHealthCheck>("session_store", tags: ["ready"]);

if (useEf)
{
    hc.AddCheck<SecurityDbHealthCheck>("db", tags: ["ready"]);
}

// Default (in-memory) authorization data store; replace with DB-backed implementation via DI.
builder.Services.AddSingleton<IAuthorizationDataStore, InMemoryAuthorizationDataStore>();

builder.Services.AddSingleton<IAuthorizationEvaluator, SimpleRbacAuthorizationEvaluator>();

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

var api = app.MapGroup("/api/v1");
var authz = api.MapGroup("/authz");
authz.AddEndpointFilter(new MetricsEndpointFilter("authz"));

authz.MapPost("/check", async (HttpContext http, AuthzCheckRequest request, IAuthorizationEvaluator evaluator, IAuditEventWriter audit, CancellationToken ct) =>
{
    static Guid? ResolveTenantId(HttpContext http)
    {
        var claim = http.User?.FindFirst(SecurityClaimTypes.TenantId)?.Value;
        if (!string.IsNullOrWhiteSpace(claim) && Guid.TryParse(claim, out var fromClaim))
        {
            return fromClaim;
        }
        return null;
    }

    var tenantId = ResolveTenantId(http);

    // Optional defense-in-depth: if a header is present, it must match the token claim.
    if (tenantId is not null
        && http.Request.Headers.TryGetValue("X-Tenant-Id", out var header)
        && Guid.TryParse(header.ToString(), out var fromHeader)
        && fromHeader != tenantId.Value)
    {
        await audit.WriteAsync(new AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenantId,
            OurSubject = request.OurSubject,
            Type = AuthEventType.Authorization,
            Outcome = "fail",
            Code = "tenant_mismatch",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("tenant_mismatch"), statusCode: StatusCodes.Status403Forbidden);
    }

    var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    if (tenantId == null || request.OurSubject == Guid.Empty)
    {
        await audit.WriteAsync(new AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            Type = AuthEventType.Authorization,
            Outcome = "fail",
            Code = "invalid_request",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("invalid_request"), statusCode: StatusCodes.Status400BadRequest);
    }

    if (string.IsNullOrWhiteSpace(request.Resource) || string.IsNullOrWhiteSpace(request.Action))
    {
        await audit.WriteAsync(new AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenantId,
            OurSubject = request.OurSubject,
            Type = AuthEventType.Authorization,
            Outcome = "fail",
            Code = "invalid_request",
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail("invalid_request"), statusCode: StatusCodes.Status400BadRequest);
    }

    var tenants = http.RequestServices.GetService<Birdsoft.Security.Abstractions.Repositories.ITenantRepository>();
    if (tenants is not null)
    {
        var tenant = await tenants.FindAsync(tenantId ?? throw new InvalidOperationException(), ct);
        if (tenant is null || tenant.Status != Birdsoft.Security.Abstractions.Models.TenantStatus.Active)
        {
            await audit.WriteAsync(new AuthEvent
            {
                Id = Guid.NewGuid(),
                OccurredAt = DateTimeOffset.UtcNow,
                TenantId = tenantId,
                OurSubject = request.OurSubject,
                Type = AuthEventType.Authorization,
                Outcome = "fail",
                Code = "tenant_not_active",
                CorrelationId = http.GetCorrelationId(),
                TraceId = http.GetTraceId(),
                Ip = ip,
                UserAgent = http.Request.Headers.UserAgent.ToString(),
            }, ct);

            return Results.Json(ApiResponse<object>.Fail("tenant_not_active"), statusCode: StatusCodes.Status403Forbidden);
        }
    }

    var subjects = http.RequestServices.GetService<Birdsoft.Security.Abstractions.Repositories.ISubjectRepository>();
    if (subjects is not null)
    {
        var subject = await subjects.FindAsync(tenantId ?? throw new InvalidOperationException(), request.OurSubject, ct);
        if (subject is null || subject.Status != Birdsoft.Security.Abstractions.Models.UserStatus.Active)
        {
            await audit.WriteAsync(new AuthEvent
            {
                Id = Guid.NewGuid(),
                OccurredAt = DateTimeOffset.UtcNow,
                TenantId = tenantId,
                OurSubject = request.OurSubject,
                Type = AuthEventType.Authorization,
                Outcome = "fail",
                Code = "user_not_active",
                CorrelationId = http.GetCorrelationId(),
                TraceId = http.GetTraceId(),
                Ip = ip,
                UserAgent = http.Request.Headers.UserAgent.ToString(),
            }, ct);

            return Results.Json(ApiResponse<object>.Fail("user_not_active"), statusCode: StatusCodes.Status403Forbidden);
        }
    }

    Guid? sessionId = null;
    try
    {
        var claim = http.User?.FindFirst(SecurityClaimTypes.SessionId)?.Value;
        if (!string.IsNullOrWhiteSpace(claim) && Guid.TryParse(claim, out var parsed))
        {
            sessionId = parsed;
        }
    }
    catch
    {
    }

    var decision = await evaluator.EvaluateAsync(
        new AuthorizationRequest(tenantId ?? throw new InvalidOperationException(), request.OurSubject, request.Resource, request.Action, request.Context),
        ct);

    await audit.WriteAsync(new AuthEvent
    {
        Id = Guid.NewGuid(),
        OccurredAt = DateTimeOffset.UtcNow,
        TenantId = tenantId,
        OurSubject = request.OurSubject,
        SessionId = sessionId,
        Type = AuthEventType.Authorization,
        Outcome = decision.Allowed ? "allow" : "deny",
        Code = decision.Allowed ? "authz_allow" : "authz_deny",
        Detail = decision.Reason,
        CorrelationId = http.GetCorrelationId(),
        TraceId = http.GetTraceId(),
        Ip = ip,
        UserAgent = http.Request.Headers.UserAgent.ToString(),
    }, ct);

    return Results.Json(ApiResponse<AuthzCheckResponse>.Ok(new AuthzCheckResponse(decision.Allowed, decision.Reason)));
}).RequireAuthorization();

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

internal sealed class InMemoryAuthorizationDataStore : IAuthorizationDataStore
{
    public ValueTask<IReadOnlyList<string>> GetRolesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = ourSubject;
        _ = cancellationToken;
        return ValueTask.FromResult<IReadOnlyList<string>>([]);
    }

    public ValueTask<IReadOnlyList<string>> GetScopesAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = ourSubject;
        _ = cancellationToken;
        return ValueTask.FromResult<IReadOnlyList<string>>([]);
    }

    public ValueTask<IReadOnlyList<string>> GetPermissionsAsync(Guid tenantId, Guid ourSubject, CancellationToken cancellationToken = default)
    {
        _ = tenantId;
        _ = ourSubject;
        _ = cancellationToken;
        return ValueTask.FromResult<IReadOnlyList<string>>([]);
    }
}
