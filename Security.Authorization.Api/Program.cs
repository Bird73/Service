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
using Birdsoft.Security.Authorization.Api;
using Birdsoft.Security.Authorization.Api.Authz;
using Birdsoft.Security.Authorization.Api.Observability.Health;
using Birdsoft.Security.Authorization.Api.Observability.Logging;
using Birdsoft.Security.Authorization.Stores;
using AuthzEvaluator = Birdsoft.Security.Authorization.Evaluation.IAuthorizationEvaluator;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Birdsoft.Security.Data.EfCore;
using Birdsoft.Security.Data.EfCore.Entities;
using Birdsoft.Infrastructure.Logging.Abstractions;
using Birdsoft.Infrastructure.Logging.Json;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Text.Json;

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

builder.Services.AddOptions<BootstrapKeyHashingOptions>()
    .Bind(builder.Configuration.GetSection(BootstrapKeyHashingOptions.SectionName));

builder.Services.AddOptions<AuditReliabilityOptions>()
    .Bind(builder.Configuration.GetSection(AuditReliabilityOptions.SectionName));

builder.Services.AddSingleton<DefaultJwtKeyProvider>();
builder.Services.AddSingleton<IJwtKeyProvider, DbBackedJwtKeyProvider>();

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

            var tokenType = user.FindFirst(SecurityClaimTypes.TokenType)?.Value;
            if (!string.Equals(tokenType, "access", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var tokenPlane = user.FindFirst(SecurityClaimTypes.TokenPlane)?.Value;
            if (!string.IsNullOrWhiteSpace(tokenPlane) && !string.Equals(tokenPlane, "tenant", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // Tenant admin surfaces require a tenant-bound token.
            var tenantId = user.FindFirst(SecurityClaimTypes.TenantId)?.Value;
            if (string.IsNullOrWhiteSpace(tenantId))
            {
                return false;
            }

            // Tenant admin only: platform admins must use PlatformAdminOnly.
            var platformScopes = user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scope).Select(c => c.Value)
                .Concat((user.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scopes)?.Value ?? string.Empty)
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries));
            if (platformScopes.Any(s => string.Equals(s, "security.platform_admin", StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }

            var platformRoles = user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Roles).Select(c => c.Value)
                .Concat(user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Role).Select(c => c.Value));
            if (platformRoles.Any(r => string.Equals(r, PlatformRoles.LegacyPlatformAdmin, StringComparison.OrdinalIgnoreCase)
                || string.Equals(r, PlatformRoles.SuperAdmin, StringComparison.OrdinalIgnoreCase)
                || string.Equals(r, PlatformRoles.OpsAdmin, StringComparison.OrdinalIgnoreCase)
                || string.Equals(r, PlatformRoles.ReadonlyAdmin, StringComparison.OrdinalIgnoreCase)))
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

    o.AddPolicy("PlatformAdminOnly", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(ctx =>
        {
            var user = ctx.User;
            if (user?.Identity?.IsAuthenticated != true)
            {
                return false;
            }

            var tokenType = user.FindFirst(SecurityClaimTypes.TokenType)?.Value;
            if (!string.Equals(tokenType, "platform_access", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var tokenPlane = user.FindFirst(SecurityClaimTypes.TokenPlane)?.Value;
            if (!string.IsNullOrWhiteSpace(tokenPlane) && !string.Equals(tokenPlane, "platform", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // Platform admin must be cross-tenant; explicitly reject tenant-bound tokens.
            var tenantId = user.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TenantId)?.Value;
            if (!string.IsNullOrWhiteSpace(tenantId))
            {
                return false;
            }

            // V19 platform token model: scope=platform + permissions include platform.admin.
            var scopes = user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scope).Select(c => c.Value)
                .Concat((user.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scopes)?.Value ?? string.Empty)
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries));

            // V20 platform role tiers.
            var platformRoles = user.FindAll(SecurityClaimTypes.Roles).Select(c => c.Value)
                .Concat(user.FindAll(SecurityClaimTypes.Role).Select(c => c.Value));
            if (platformRoles.Any(r => string.Equals(r, PlatformRoles.SuperAdmin, StringComparison.OrdinalIgnoreCase)
                || string.Equals(r, PlatformRoles.OpsAdmin, StringComparison.OrdinalIgnoreCase)
                || string.Equals(r, PlatformRoles.ReadonlyAdmin, StringComparison.OrdinalIgnoreCase)
                || string.Equals(r, PlatformRoles.LegacyPlatformAdmin, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            if (scopes.Any(s => string.Equals(s, "platform", StringComparison.OrdinalIgnoreCase)))
            {
                var perms = user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Permissions).Select(c => c.Value);
                if (perms.Any(p => string.Equals(p, "platform.admin", StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }

            // Backwards compatibility (legacy platform admin role/scope).
            if (scopes.Any(s => string.Equals(s, "security.platform_admin", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            var roles = user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Roles).Select(c => c.Value)
                .Concat(user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Role).Select(c => c.Value));
            return roles.Any(r => string.Equals(r, PlatformRoles.LegacyPlatformAdmin, StringComparison.OrdinalIgnoreCase));
        });
    });

    o.AddPolicy("PlatformTokenOnly", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(ctx =>
        {
            var user = ctx.User;
            if (user?.Identity?.IsAuthenticated != true)
            {
                return false;
            }

            var tokenType = user.FindFirst(SecurityClaimTypes.TokenType)?.Value;
            if (!string.Equals(tokenType, "platform_access", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var tokenPlane = user.FindFirst(SecurityClaimTypes.TokenPlane)?.Value;
            if (!string.Equals(tokenPlane, "platform", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // Platform token must be cross-tenant; explicitly reject tenant-bound tokens.
            var tenantId = user.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TenantId)?.Value;
            if (!string.IsNullOrWhiteSpace(tenantId))
            {
                return false;
            }

            // Require scope=platform (preferred), but allow legacy platform_admin scope/role during transition.
            var scopes = user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scope).Select(c => c.Value)
                .Concat((user.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scopes)?.Value ?? string.Empty)
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries));
            if (scopes.Any(s => string.Equals(s, "platform", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            if (scopes.Any(s => string.Equals(s, "security.platform_admin", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            var roles = user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Roles).Select(c => c.Value)
                .Concat(user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Role).Select(c => c.Value));
            return roles.Any(r => string.Equals(r, PlatformRoles.LegacyPlatformAdmin, StringComparison.OrdinalIgnoreCase)
                || string.Equals(r, PlatformRoles.SuperAdmin, StringComparison.OrdinalIgnoreCase)
                || string.Equals(r, PlatformRoles.OpsAdmin, StringComparison.OrdinalIgnoreCase)
                || string.Equals(r, PlatformRoles.ReadonlyAdmin, StringComparison.OrdinalIgnoreCase));
        });
    });

    static void AddPlatformPermissionPolicy(
        AuthorizationOptions opts,
        string policyName,
        string requiredPermission,
        params string[] allowedRoles)
    {
        opts.AddPolicy(policyName, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireAssertion(ctx =>
            {
                var user = ctx.User;
                if (user?.Identity?.IsAuthenticated != true)
                {
                    return false;
                }

                var tokenType = user.FindFirst(SecurityClaimTypes.TokenType)?.Value;
                var tokenPlane = user.FindFirst(SecurityClaimTypes.TokenPlane)?.Value;
                if (!string.Equals(tokenPlane, "platform", StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(tokenType, "platform_access", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Must not carry tenant_id.
                if (!string.IsNullOrWhiteSpace(user.FindFirst(SecurityClaimTypes.TenantId)?.Value))
                {
                    return false;
                }

                if (allowedRoles is { Length: > 0 })
                {
                    var roles = user.FindAll(SecurityClaimTypes.Roles).Select(c => c.Value)
                        .Concat(user.FindAll(SecurityClaimTypes.Role).Select(c => c.Value));

                    if (roles.Any(r => string.Equals(r, PlatformRoles.LegacyPlatformAdmin, StringComparison.OrdinalIgnoreCase)))
                    {
                        return true;
                    }

                    if (roles.Any(r => allowedRoles.Any(ar => string.Equals(r, ar, StringComparison.OrdinalIgnoreCase))))
                    {
                        return true;
                    }
                }

                var perms = user.FindAll(SecurityClaimTypes.Permissions).Select(c => c.Value);
                return perms.Any(p => string.Equals(p, "platform.admin", StringComparison.OrdinalIgnoreCase))
                    || perms.Any(p => string.Equals(p, requiredPermission, StringComparison.OrdinalIgnoreCase));
            });
        });
    }

    AddPlatformPermissionPolicy(o, "PlatformProductsRead", "platform.products.read", PlatformRoles.SuperAdmin, PlatformRoles.OpsAdmin, PlatformRoles.ReadonlyAdmin);
    AddPlatformPermissionPolicy(o, "PlatformProductsWrite", "platform.products.write", PlatformRoles.SuperAdmin, PlatformRoles.OpsAdmin);
    AddPlatformPermissionPolicy(o, "PlatformTenantsRead", "platform.tenants.read", PlatformRoles.SuperAdmin, PlatformRoles.OpsAdmin, PlatformRoles.ReadonlyAdmin);
    AddPlatformPermissionPolicy(o, "PlatformTenantsWrite", "platform.tenants.write", PlatformRoles.SuperAdmin, PlatformRoles.OpsAdmin);
    AddPlatformPermissionPolicy(o, "PlatformEntitlementsRead", "platform.entitlements.read", PlatformRoles.SuperAdmin, PlatformRoles.OpsAdmin, PlatformRoles.ReadonlyAdmin);
    AddPlatformPermissionPolicy(o, "PlatformEntitlementsWrite", "platform.entitlements.write", PlatformRoles.SuperAdmin, PlatformRoles.OpsAdmin);
    AddPlatformPermissionPolicy(o, "PlatformPermissionsRead", "platform.permissions.read", PlatformRoles.SuperAdmin, PlatformRoles.OpsAdmin, PlatformRoles.ReadonlyAdmin);
    AddPlatformPermissionPolicy(o, "PlatformPermissionsWrite", "platform.permissions.write", PlatformRoles.SuperAdmin, PlatformRoles.OpsAdmin);
    AddPlatformPermissionPolicy(o, "PlatformAuditRead", "platform.audit.read", PlatformRoles.SuperAdmin, PlatformRoles.OpsAdmin, PlatformRoles.ReadonlyAdmin);
    AddPlatformPermissionPolicy(o, "PlatformTokensWrite", "platform.tokens.write", PlatformRoles.SuperAdmin);
});
builder.Services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>, BirdsoftJwtBearerPostConfigureOptions>();

// Authorization behavior configuration (fail-closed by default).
builder.Services.Configure<Birdsoft.Security.Abstractions.Options.SecurityAuthorizationOptions>(
    builder.Configuration.GetSection(Birdsoft.Security.Abstractions.Options.SecurityAuthorizationOptions.SectionName));

// Emit spec-like JSON bodies for 401/403 produced by authorization middleware.
builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, ApiAuthorizationMiddlewareResultHandler>();

// Fail-fast on dangerous authorization store wiring unless explicitly allowed.
builder.Services.AddHostedService<Birdsoft.Security.Authorization.Api.Authz.AuthorizationGuardrailsHostedService>();

// Governance: validate permission->product relationships at startup (no-op if EF/DB not wired).
builder.Services.AddHostedService<Birdsoft.Security.Data.EfCore.Services.PermissionProductIntegrityHostedService>();

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
if (!useEf)
{
    builder.Services.AddSingleton<InMemoryAuthorizationStore>();
    builder.Services.AddSingleton<IAuthorizationDataStore>(sp => sp.GetRequiredService<InMemoryAuthorizationStore>());
    builder.Services.AddSingleton<IAuthorizationAdminStore>(sp => sp.GetRequiredService<InMemoryAuthorizationStore>());
}

// Entitlement gating: EF-backed when available; otherwise allow-all for dev/in-memory mode.
if (!useEf)
{
    // V18-1: fail-closed in non-EF mode (seed via Security:Authorization config).
    builder.Services.AddSingleton<IPermissionCatalogStore, Birdsoft.Security.Authorization.Stores.ConfigurationPermissionCatalogStore>();
    builder.Services.AddSingleton<ITenantEntitlementStore, Birdsoft.Security.Authorization.Stores.ConfigurationTenantEntitlementStore>();
}

builder.Services.AddScoped<SimpleRbacAuthorizationEvaluator>();
builder.Services.AddScoped<AuthzEvaluator>(sp =>
    new EntitlementAuthorizationEvaluator(
        sp.GetRequiredService<SimpleRbacAuthorizationEvaluator>(),
        sp.GetRequiredService<IPermissionCatalogStore>(),
        sp.GetRequiredService<ITenantEntitlementStore>(),
        sp.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<Birdsoft.Security.Abstractions.Options.SecurityAuthorizationOptions>>()));

var app = builder.Build();

// Some hosting environments (e.g., WebApplicationFactory) can override services/config after Program.cs
// computes the initial useEf flag. Use the final DI container to decide whether EF-only endpoints exist.
bool efEnabled;
using (var scope = app.Services.CreateScope())
{
    efEnabled = scope.ServiceProvider.GetService<SecurityDbContext>() is not null;
}

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

// Test-only endpoints (integration test host can enable via TestEndpoints:Enabled=true).
if (app.Configuration.GetValue<bool>("TestEndpoints:Enabled"))
{
    var test = api.MapGroup("/test");

    test.MapGet("/admin-only", () => Results.Json(ApiResponse<object>.Ok(new { ok = true })))
        .RequireAuthorization("AdminOnly");
}
var authz = api.MapGroup("/authz");
authz.AddEndpointFilter(new MetricsEndpointFilter("authz"));

authz.MapPost("/check", async (HttpContext http, AuthzCheckRequest request, AuthzEvaluator evaluator, IAuditEventWriter audit, CancellationToken ct) =>
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
            Code = AuthErrorCodes.TenantMismatch,
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail(AuthErrorCodes.TenantMismatch), statusCode: StatusCodes.Status403Forbidden);
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
            Code = AuthErrorCodes.InvalidRequest,
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest), statusCode: StatusCodes.Status400BadRequest);
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
            Code = AuthErrorCodes.InvalidRequest,
            CorrelationId = http.GetCorrelationId(),
            TraceId = http.GetTraceId(),
            Ip = ip,
            UserAgent = http.Request.Headers.UserAgent.ToString(),
        }, ct);

        return Results.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest), statusCode: StatusCodes.Status400BadRequest);
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
                Code = AuthErrorCodes.TenantNotActive,
                CorrelationId = http.GetCorrelationId(),
                TraceId = http.GetTraceId(),
                Ip = ip,
                UserAgent = http.Request.Headers.UserAgent.ToString(),
            }, ct);

            return Results.Json(ApiResponse<object>.Fail(AuthErrorCodes.TenantNotActive), statusCode: StatusCodes.Status403Forbidden);
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
                Code = AuthErrorCodes.UserNotActive,
                CorrelationId = http.GetCorrelationId(),
                TraceId = http.GetTraceId(),
                Ip = ip,
                UserAgent = http.Request.Headers.UserAgent.ToString(),
            }, ct);

            return Results.Json(ApiResponse<object>.Fail(AuthErrorCodes.UserNotActive), statusCode: StatusCodes.Status403Forbidden);
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

static IReadOnlyDictionary<string, string[]> SingleField(string field, string message)
    => new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase) { [field] = [message] };

static Guid? TryGetOurSubjectFromToken(HttpContext http)
{
    var raw = http.User?.FindFirst(SecurityClaimTypes.OurSubject)?.Value
        ?? http.User?.FindFirst("sub")?.Value;

    if (!string.IsNullOrWhiteSpace(raw) && Guid.TryParse(raw, out var ourSubject))
    {
        return ourSubject;
    }

    return null;
}

static Guid? TryGetSessionIdFromToken(HttpContext http)
{
    var raw = http.User?.FindFirst(SecurityClaimTypes.SessionId)?.Value;
    if (!string.IsNullOrWhiteSpace(raw) && Guid.TryParse(raw, out var sessionId))
    {
        return sessionId;
    }

    return null;
}

static async Task WritePlatformAuditAsync(
    HttpContext http,
    IAuditEventWriter audit,
    string code,
    string outcome,
    string? detail,
    object? meta,
    CancellationToken ct)
{
    var actor = TryGetOurSubjectFromToken(http);
    var sessionId = TryGetSessionIdFromToken(http);

    await audit.WriteAsync(new AuthEvent
    {
        Id = Guid.NewGuid(),
        OccurredAt = DateTimeOffset.UtcNow,
        TenantId = null,
        OurSubject = actor,
        SessionId = sessionId,
        Type = AuthEventType.Authorization,
        Outcome = outcome,
        Code = code,
        Detail = detail,
        MetaJson = meta is null ? null : JsonSerializer.Serialize(meta, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
        CorrelationId = http.GetCorrelationId(),
        TraceId = http.GetTraceId(),
        Ip = http.Connection.RemoteIpAddress?.ToString(),
        UserAgent = http.Request.Headers.UserAgent.ToString(),
    }, ct);
}

static Guid? TryGetTenantIdFromToken(HttpContext http)
{
    var claim = http.User?.FindFirst(SecurityClaimTypes.TenantId)?.Value;
    if (!string.IsNullOrWhiteSpace(claim) && Guid.TryParse(claim, out var tenantId))
    {
        return tenantId;
    }

    return null;
}

if (efEnabled)
{
    var platform = api.MapGroup("/platform");
    platform.RequireAuthorization("PlatformTokenOnly");

    // Platform admin governance (V20)
    // Only super_admin can manage platform admin accounts.
    platform.MapGet("/admins", async Task<Results<JsonHttpResult<ApiResponse<IReadOnlyList<PlatformAdminRecord>>>, JsonHttpResult<ApiResponse<object>>>> (
        IPlatformAdminStore admins,
        int? skip,
        int? take,
        CancellationToken ct) =>
    {
        var items = await admins.ListAsync(Math.Max(0, skip ?? 0), Math.Clamp(take ?? 50, 1, 200), ct);
        return TypedResults.Json(ApiResponse<IReadOnlyList<PlatformAdminRecord>>.Ok(items));
    }).RequireAuthorization("PlatformTokensWrite");

    platform.MapPost("/admins", async Task<Results<JsonHttpResult<ApiResponse<PlatformAdminRecord>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        IPlatformAdminStore admins,
        IAuditEventWriter audit,
        JsonElement body,
        CancellationToken ct) =>
    {
        if (body.ValueKind != JsonValueKind.Object)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "request body must be a JSON object"), statusCode: StatusCodes.Status400BadRequest);
        }

        if (!body.TryGetProperty("ourSubject", out var subjEl) || subjEl.ValueKind != JsonValueKind.String || !Guid.TryParse(subjEl.GetString(), out var ourSubject) || ourSubject == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "ourSubject is required", SingleField("ourSubject", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var role = PlatformRoles.SuperAdmin;
        if (body.TryGetProperty("role", out var roleEl) && roleEl.ValueKind == JsonValueKind.String)
        {
            var s = roleEl.GetString();
            role = string.IsNullOrWhiteSpace(s) ? PlatformRoles.SuperAdmin : s!.Trim();
        }

        string? reason = null;
        if (body.TryGetProperty("reason", out var reasonEl) && reasonEl.ValueKind == JsonValueKind.String)
        {
            var r = reasonEl.GetString();
            reason = string.IsNullOrWhiteSpace(r) ? null : r;
        }

        try
        {
            var created = await admins.CreateAsync(ourSubject, role, reason, ct);
            await WritePlatformAuditAsync(http, audit, code: "platform.admin.create", outcome: "success", detail: reason, meta: new { created.OurSubject, created.Role, created.Status, created.TokenVersion }, ct);
            return TypedResults.Json(ApiResponse<PlatformAdminRecord>.Ok(created), statusCode: StatusCodes.Status201Created);
        }
        catch (InvalidOperationException ex) when (string.Equals(ex.Message, "platform_admin_exists", StringComparison.Ordinal))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Conflict, "platform admin already exists"), statusCode: StatusCodes.Status409Conflict);
        }
        catch (InvalidOperationException ex) when (string.Equals(ex.Message, "invalid_platform_role", StringComparison.Ordinal))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "role is invalid", SingleField("role", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }
    }).RequireAuthorization("PlatformTokensWrite");

    platform.MapPut("/admins/{ourSubject:guid}/role", async Task<Results<JsonHttpResult<ApiResponse<PlatformAdminRecord>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        IPlatformAdminStore admins,
        IAuditEventWriter audit,
        Guid ourSubject,
        JsonElement body,
        CancellationToken ct) =>
    {
        if (ourSubject == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "ourSubject is invalid", SingleField("ourSubject", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        if (body.ValueKind != JsonValueKind.Object)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "request body must be a JSON object"), statusCode: StatusCodes.Status400BadRequest);
        }

        if (!body.TryGetProperty("role", out var roleEl) || roleEl.ValueKind != JsonValueKind.String)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "role is required", SingleField("role", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var role = (roleEl.GetString() ?? string.Empty).Trim();
        string? reason = null;
        if (body.TryGetProperty("reason", out var reasonEl) && reasonEl.ValueKind == JsonValueKind.String)
        {
            var r = reasonEl.GetString();
            reason = string.IsNullOrWhiteSpace(r) ? null : r;
        }

        try
        {
            var updated = await admins.SetRoleAsync(ourSubject, role, reason, ct);
            if (updated is null)
            {
                return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "platform admin not found"), statusCode: StatusCodes.Status404NotFound);
            }

            await WritePlatformAuditAsync(http, audit, code: "platform.admin.role.update", outcome: "success", detail: reason, meta: new { updated.OurSubject, updated.Role, updated.Status, updated.TokenVersion }, ct);
            return TypedResults.Json(ApiResponse<PlatformAdminRecord>.Ok(updated));
        }
        catch (InvalidOperationException ex) when (string.Equals(ex.Message, "invalid_platform_role", StringComparison.Ordinal))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "role is invalid", SingleField("role", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }
    }).RequireAuthorization("PlatformTokensWrite");

    platform.MapPut("/admins/{ourSubject:guid}/status", async Task<Results<JsonHttpResult<ApiResponse<PlatformAdminRecord>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        IPlatformAdminStore admins,
        IAuditEventWriter audit,
        Guid ourSubject,
        JsonElement body,
        CancellationToken ct) =>
    {
        if (ourSubject == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "ourSubject is invalid", SingleField("ourSubject", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        if (body.ValueKind != JsonValueKind.Object)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "request body must be a JSON object"), statusCode: StatusCodes.Status400BadRequest);
        }

        if (!body.TryGetProperty("status", out var statusEl) || statusEl.ValueKind != JsonValueKind.Number || !statusEl.TryGetInt32(out var statusInt))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "status is required", SingleField("status", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        if (!Enum.IsDefined(typeof(PlatformAdminStatus), statusInt))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "status is invalid", SingleField("status", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        var status = (PlatformAdminStatus)statusInt;
        string? reason = null;
        if (body.TryGetProperty("reason", out var reasonEl) && reasonEl.ValueKind == JsonValueKind.String)
        {
            var r = reasonEl.GetString();
            reason = string.IsNullOrWhiteSpace(r) ? null : r;
        }

        var updated = await admins.SetStatusAsync(ourSubject, status, reason, ct);
        if (updated is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "platform admin not found"), statusCode: StatusCodes.Status404NotFound);
        }

        await WritePlatformAuditAsync(http, audit, code: "platform.admin.status.update", outcome: "success", detail: reason, meta: new { updated.OurSubject, updated.Role, updated.Status, updated.TokenVersion }, ct);
        return TypedResults.Json(ApiResponse<PlatformAdminRecord>.Ok(updated));
    }).RequireAuthorization("PlatformTokensWrite");

    // Platform token governance: immediate revocation (global version bump)
    platform.MapPost("/tokens/revoke", async Task<Results<NoContent, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        IPlatformTokenVersionStore versions,
        IAuditEventWriter audit,
        string? reason,
        CancellationToken ct) =>
    {
        var newVersion = await versions.BumpAsync(reason, ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.token.revoke",
            outcome: "success",
            detail: reason,
            meta: new { platformTokenVersion = newVersion },
            ct);

        return TypedResults.NoContent();
    }).RequireAuthorization("PlatformTokensWrite");

    // Bootstrap key governance (V20-1)
    platform.MapGet("/bootstrap-keys", async Task<JsonHttpResult<ApiResponse<IReadOnlyList<BootstrapKeyRecord>>>> (
        IBootstrapKeyStore keys,
        bool? includeRevoked,
        CancellationToken ct) =>
    {
        var items = await keys.ListAsync(includeRevoked: includeRevoked ?? false, ct);
        return TypedResults.Json(ApiResponse<IReadOnlyList<BootstrapKeyRecord>>.Ok(items));
    }).RequireAuthorization("PlatformTokensWrite");

    platform.MapPost("/bootstrap-keys", async Task<JsonHttpResult<ApiResponse<object>>> (
        HttpContext http,
        IBootstrapKeyStore keys,
        IAuditEventWriter audit,
        JsonElement body,
        CancellationToken ct) =>
    {
        if (body.ValueKind != JsonValueKind.Object)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "request body must be a JSON object"), statusCode: StatusCodes.Status400BadRequest);
        }

        string? label = null;
        if (body.TryGetProperty("label", out var labelEl) && labelEl.ValueKind == JsonValueKind.String)
        {
            var s = labelEl.GetString();
            label = string.IsNullOrWhiteSpace(s) ? null : s;
        }

        DateTimeOffset? expiresAt = null;
        if (body.TryGetProperty("expiresAt", out var expEl) && expEl.ValueKind == JsonValueKind.String)
        {
            var s = expEl.GetString();
            if (!string.IsNullOrWhiteSpace(s) && DateTimeOffset.TryParse(s, out var parsed))
            {
                expiresAt = parsed;
            }
        }

        var created = await keys.CreateAsync(label, expiresAt, ct);
        await WritePlatformAuditAsync(http, audit, code: "platform.bootstrap_key.create", outcome: "success", detail: label, meta: new { created.Record.Id, created.Record.Label, created.Record.ExpiresAt }, ct);

        return TypedResults.Json(ApiResponse<object>.Ok(new
        {
            created.Record,
            plaintext_key = created.PlaintextKey,
        }), statusCode: StatusCodes.Status201Created);
    }).RequireAuthorization("PlatformTokensWrite");

    platform.MapPost("/bootstrap-keys/{id:guid}/revoke", async Task<Results<JsonHttpResult<ApiResponse<BootstrapKeyRecord>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        IBootstrapKeyStore keys,
        IAuditEventWriter audit,
        Guid id,
        JsonElement body,
        CancellationToken ct) =>
    {
        if (id == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "id is invalid", SingleField("id", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        string? reason = null;
        if (body.ValueKind == JsonValueKind.Object && body.TryGetProperty("reason", out var reasonEl) && reasonEl.ValueKind == JsonValueKind.String)
        {
            var s = reasonEl.GetString();
            reason = string.IsNullOrWhiteSpace(s) ? null : s;
        }

        var updated = await keys.RevokeAsync(id, reason, ct);
        if (updated is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "bootstrap key not found"), statusCode: StatusCodes.Status404NotFound);
        }

        await WritePlatformAuditAsync(http, audit, code: "platform.bootstrap_key.revoke", outcome: "success", detail: reason, meta: new { updated.Id, updated.Label, updated.Status }, ct);
        return TypedResults.Json(ApiResponse<BootstrapKeyRecord>.Ok(updated));
    }).RequireAuthorization("PlatformTokensWrite");

    // JWT signing key governance (V20-1)
    platform.MapGet("/signing-keys", async Task<JsonHttpResult<ApiResponse<IReadOnlyList<JwtSigningKeyRecord>>>> (
        IJwtSigningKeyStore keys,
        bool? includeDisabled,
        CancellationToken ct) =>
    {
        var items = await keys.ListAsync(includeDisabled: includeDisabled ?? false, ct);
        return TypedResults.Json(ApiResponse<IReadOnlyList<JwtSigningKeyRecord>>.Ok(items));
    }).RequireAuthorization("PlatformTokensWrite");

    platform.MapPost("/signing-keys/rotate", async Task<Results<JsonHttpResult<ApiResponse<JwtSigningKeyRecord>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        IJwtSigningKeyStore keys,
        IAuditEventWriter audit,
        JsonElement body,
        CancellationToken ct) =>
    {
        string alg = "HS256";
        int bytes = 32;
        string? reason = null;

        if (body.ValueKind == JsonValueKind.Object)
        {
            if (body.TryGetProperty("algorithm", out var algEl) && algEl.ValueKind == JsonValueKind.String)
            {
                var s = algEl.GetString();
                if (!string.IsNullOrWhiteSpace(s))
                {
                    alg = s!.Trim().ToUpperInvariant();
                }
            }

            if (body.TryGetProperty("bytes", out var bytesEl) && bytesEl.ValueKind == JsonValueKind.Number && bytesEl.TryGetInt32(out var b))
            {
                bytes = b;
            }

            if (body.TryGetProperty("reason", out var reasonEl) && reasonEl.ValueKind == JsonValueKind.String)
            {
                var s = reasonEl.GetString();
                reason = string.IsNullOrWhiteSpace(s) ? null : s;
            }
        }

        JwtSigningKeyRecord rotated;
        if (alg == "RS256")
        {
            rotated = await keys.RotateRsaAsync(reason, ct);
        }
        else if (alg == "HS256")
        {
            rotated = await keys.RotateHmacAsync(bytes, reason, ct);
        }
        else
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "algorithm is invalid", SingleField("algorithm", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        await WritePlatformAuditAsync(http, audit, code: "platform.signing_key.rotate", outcome: "success", detail: reason, meta: new { rotated.Kid, rotated.Algorithm, rotated.Status }, ct);
        return TypedResults.Json(ApiResponse<JwtSigningKeyRecord>.Ok(rotated), statusCode: StatusCodes.Status201Created);
    }).RequireAuthorization("PlatformTokensWrite");

    platform.MapPost("/signing-keys/{kid}/disable", async Task<Results<JsonHttpResult<ApiResponse<JwtSigningKeyRecord>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        IJwtSigningKeyStore keys,
        IAuditEventWriter audit,
        string kid,
        JsonElement body,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(kid))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "kid is required", SingleField("kid", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        string? reason = null;
        if (body.ValueKind == JsonValueKind.Object && body.TryGetProperty("reason", out var reasonEl) && reasonEl.ValueKind == JsonValueKind.String)
        {
            var s = reasonEl.GetString();
            reason = string.IsNullOrWhiteSpace(s) ? null : s;
        }

        JwtSigningKeyRecord? disabled;
        try
        {
            disabled = await keys.DisableAsync(kid.Trim(), reason, ct);
        }
        catch (InvalidOperationException ex) when (string.Equals(ex.Message, "Cannot disable the last signing key.", StringComparison.Ordinal))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Conflict, "cannot disable the last signing key"), statusCode: StatusCodes.Status409Conflict);
        }

        if (disabled is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "signing key not found"), statusCode: StatusCodes.Status404NotFound);
        }

        await WritePlatformAuditAsync(http, audit, code: "platform.signing_key.disable", outcome: "success", detail: reason, meta: new { disabled.Kid, disabled.Algorithm, disabled.Status }, ct);
        return TypedResults.Json(ApiResponse<JwtSigningKeyRecord>.Ok(disabled));
    }).RequireAuthorization("PlatformTokensWrite");

    // Minimal platform audit log query API (no sensitive payloads)
    platform.MapGet("/audit-logs", async Task<Results<JsonHttpResult<ApiResponse<IReadOnlyList<PlatformAuditLogDto>>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        Guid? actor,
        string? action,
        Guid? tenantId,
        string? productKey,
        DateTimeOffset? from,
        DateTimeOffset? to,
        int? skip,
        int? take,
        CancellationToken ct) =>
    {
        var s = Math.Max(0, skip ?? 0);
        var t = Math.Clamp(take ?? 50, 1, 200);

        var query = db.AuthEvents.AsNoTracking().Where(x => x.Type == (int)AuthEventType.Authorization);

        if (actor is not null)
        {
            query = query.Where(x => x.OurSubject == actor.Value);
        }

        if (!string.IsNullOrWhiteSpace(action))
        {
            var code = action.Trim();
            query = query.Where(x => x.Code == code);
        }

        if (tenantId is not null)
        {
            query = query.Where(x => x.TenantId == tenantId.Value);
        }

        if (from is not null)
        {
            query = query.Where(x => x.OccurredAt >= from.Value);
        }

        if (to is not null)
        {
            query = query.Where(x => x.OccurredAt <= to.Value);
        }

        if (!string.IsNullOrWhiteSpace(productKey))
        {
            var pk = productKey.Trim();
            query = query.Where(x => x.MetaJson != null && x.MetaJson.Contains("\"productKey\":\"" + pk + "\""));
        }

        var items = await query
            .OrderByDescending(x => x.OccurredAt)
            .Skip(s)
            .Take(t)
            .Select(x => new PlatformAuditLogDto(
                x.Id,
                x.OccurredAt,
                x.OurSubject,
                x.TenantId,
                x.Outcome,
                x.Code))
            .ToListAsync(ct);

        return TypedResults.Json(ApiResponse<IReadOnlyList<PlatformAuditLogDto>>.Ok(items));
    }).RequireAuthorization("PlatformAuditRead");

    platform.MapGet("/products", async Task<Results<JsonHttpResult<ApiResponse<IReadOnlyList<ProductDto>>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        int? skip,
        int? take,
        int? status,
        CancellationToken ct) =>
    {
        var s = Math.Max(0, skip ?? 0);
        var t = Math.Clamp(take ?? 50, 1, 200);

        var query = db.Products.AsNoTracking();
        if (status is not null)
        {
            query = query.Where(x => x.Status == status.Value);
        }

        var items = await query
            .OrderBy(x => x.ProductKey)
            .Skip(s)
            .Take(t)
            .Select(x => new ProductDto(
                x.ProductKey,
                x.DisplayName,
                x.Description,
                (ProductStatus)x.Status,
                x.CreatedAt,
                x.UpdatedAt))
            .ToListAsync(ct);

        return TypedResults.Json(ApiResponse<IReadOnlyList<ProductDto>>.Ok(items));
    }).RequireAuthorization("PlatformProductsRead");

    platform.MapGet("/products/{productKey}", async Task<Results<JsonHttpResult<ApiResponse<ProductDto>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        string productKey,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var p = await db.Products.AsNoTracking().FirstOrDefaultAsync(x => x.ProductKey == productKey, ct);
        if (p is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "product not found"), statusCode: StatusCodes.Status404NotFound);
        }

        return TypedResults.Json(ApiResponse<ProductDto>.Ok(new ProductDto(
            p.ProductKey,
            p.DisplayName,
            p.Description,
            (ProductStatus)p.Status,
            p.CreatedAt,
            p.UpdatedAt)));
    }).RequireAuthorization("PlatformProductsRead");

    platform.MapPost("/products", async Task<Results<JsonHttpResult<ApiResponse<ProductDto>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        IAuditEventWriter audit,
        PlatformCreateProductRequest request,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(request.ProductKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        if (string.IsNullOrWhiteSpace(request.DisplayName))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "displayName is required", SingleField("displayName", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var existing = await db.Products.AsNoTracking().AnyAsync(x => x.ProductKey == request.ProductKey.Trim(), ct);
        if (existing)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Conflict, "productKey already exists"), statusCode: StatusCodes.Status409Conflict);
        }

        var now = DateTimeOffset.UtcNow;
        var entity = new Birdsoft.Security.Data.EfCore.Entities.ProductEntity
        {
            ProductId = Guid.NewGuid(),
            ProductKey = request.ProductKey.Trim(),
            DisplayName = request.DisplayName.Trim(),
            Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim(),
            Status = (int)(request.Status ?? ProductStatus.Enabled),
            CreatedAt = now,
            UpdatedAt = now,
        };

        db.Products.Add(entity);
        await db.SaveChangesAsync(ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.product.create",
            outcome: "success",
            detail: request.Reason,
            meta: new { entity.ProductKey, entity.DisplayName, entity.Status },
            ct);

        return TypedResults.Json(ApiResponse<ProductDto>.Ok(new ProductDto(
            entity.ProductKey,
            entity.DisplayName,
            entity.Description,
            (ProductStatus)entity.Status,
            entity.CreatedAt,
            entity.UpdatedAt)), statusCode: StatusCodes.Status201Created);
    }).RequireAuthorization("PlatformProductsWrite");

    platform.MapPut("/products/{productKey}", async Task<Results<JsonHttpResult<ApiResponse<ProductDto>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        IAuditEventWriter audit,
        string productKey,
        PlatformUpdateProductRequest request,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        productKey = productKey.Trim();
        var p = await db.Products.FirstOrDefaultAsync(x => x.ProductKey == productKey, ct);
        if (p is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "product not found"), statusCode: StatusCodes.Status404NotFound);
        }

        if (!string.IsNullOrWhiteSpace(request.DisplayName))
        {
            p.DisplayName = request.DisplayName.Trim();
        }

        if (request.Description is not null)
        {
            var desc = request.Description.Trim();
            if (desc.Length != 0)
            {
                p.Description = desc;
            }
        }

        if (request.Status is not null)
        {
            p.Status = (int)request.Status.Value;
        }

        p.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.product.update",
            outcome: "success",
            detail: request.Reason,
            meta: new { p.ProductKey, p.DisplayName, p.Status },
            ct);

        return TypedResults.Json(ApiResponse<ProductDto>.Ok(new ProductDto(
            p.ProductKey,
            p.DisplayName,
            p.Description,
            (ProductStatus)p.Status,
            p.CreatedAt,
            p.UpdatedAt)));
    }).RequireAuthorization("PlatformProductsWrite");

    platform.MapDelete("/products/{productKey}", async Task<Results<NoContent, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        IAuditEventWriter audit,
        string productKey,
        string? reason,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var p = await db.Products.FirstOrDefaultAsync(x => x.ProductKey == productKey.Trim(), ct);
        if (p is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "product not found"), statusCode: StatusCodes.Status404NotFound);
        }

        // V19: products are never hard-deleted. DELETE means disable.
        p.Status = (int)ProductStatus.Disabled;
        p.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.product.disable",
            outcome: "success",
            detail: reason,
            meta: new { p.ProductKey, p.Status },
            ct);

        return TypedResults.NoContent();
    }).RequireAuthorization("PlatformProductsWrite");

    // Permissions (global keys; optional ProductKey linkage)
    platform.MapGet("/permissions", async Task<Results<JsonHttpResult<ApiResponse<IReadOnlyList<PermissionDto>>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        int? skip,
        int? take,
        string? productKey,
        CancellationToken ct) =>
    {
        var s = Math.Max(0, skip ?? 0);
        var t = Math.Clamp(take ?? 50, 1, 200);

        var query = db.Permissions.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(productKey))
        {
            var pk = productKey.Trim();
            query = query.Where(x => x.ProductKey == pk);
        }

        var items = await query
            .OrderBy(x => x.PermKey)
            .Skip(s)
            .Take(t)
            .Select(x => new PermissionDto(x.PermKey, x.ProductKey, x.Description, x.CreatedAt, x.UpdatedAt))
            .ToListAsync(ct);

        return TypedResults.Json(ApiResponse<IReadOnlyList<PermissionDto>>.Ok(items));
    }).RequireAuthorization("PlatformPermissionsRead");

    platform.MapGet("/permissions/{permissionKey}", async Task<Results<JsonHttpResult<ApiResponse<PermissionDto>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        string permissionKey,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(permissionKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "permissionKey is required", SingleField("permissionKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var p = await db.Permissions.AsNoTracking().FirstOrDefaultAsync(x => x.PermKey == permissionKey.Trim(), ct);
        if (p is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "permission not found"), statusCode: StatusCodes.Status404NotFound);
        }

        return TypedResults.Json(ApiResponse<PermissionDto>.Ok(new PermissionDto(p.PermKey, p.ProductKey, p.Description, p.CreatedAt, p.UpdatedAt)));
    }).RequireAuthorization("PlatformPermissionsRead");

    platform.MapPost("/permissions", async Task<Results<JsonHttpResult<ApiResponse<PermissionDto>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        IAuditEventWriter audit,
        PlatformCreatePermissionRequest request,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(request.PermissionKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "permissionKey is required", SingleField("permissionKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var permKey = request.PermissionKey.Trim();
        var existing = await db.Permissions.AsNoTracking().AnyAsync(x => x.PermKey == permKey, ct);
        if (existing)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Conflict, "permissionKey already exists"), statusCode: StatusCodes.Status409Conflict);
        }

        string? productKey = null;
        if (!string.IsNullOrWhiteSpace(request.ProductKey))
        {
            productKey = request.ProductKey.Trim();
            var productExists = await db.Products.AsNoTracking().AnyAsync(x => x.ProductKey == productKey, ct);
            if (!productExists)
            {
                return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "product not found"), statusCode: StatusCodes.Status404NotFound);
            }
        }

        var now = DateTimeOffset.UtcNow;
        var entity = new PermissionEntity
        {
            PermId = Guid.NewGuid(),
            PermKey = permKey,
            ProductKey = productKey,
            Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim(),
            CreatedAt = now,
            UpdatedAt = now,
        };

        db.Permissions.Add(entity);
        await db.SaveChangesAsync(ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.permission.create",
            outcome: "success",
            detail: request.Reason,
            meta: new { entity.PermKey, entity.ProductKey },
            ct);

        return TypedResults.Json(ApiResponse<PermissionDto>.Ok(new PermissionDto(
            entity.PermKey,
            entity.ProductKey,
            entity.Description,
            entity.CreatedAt,
            entity.UpdatedAt)), statusCode: StatusCodes.Status201Created);
    }).RequireAuthorization("PlatformPermissionsWrite");

    platform.MapPut("/permissions/{permissionKey}", async Task<Results<JsonHttpResult<ApiResponse<PermissionDto>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        IAuditEventWriter audit,
        string permissionKey,
        PlatformUpdatePermissionRequest request,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(permissionKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "permissionKey is required", SingleField("permissionKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var key = permissionKey.Trim();
        var p = await db.Permissions.FirstOrDefaultAsync(x => x.PermKey == key, ct);
        if (p is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "permission not found"), statusCode: StatusCodes.Status404NotFound);
        }

        if (request.ProductKey is not null)
        {
            if (string.IsNullOrWhiteSpace(request.ProductKey))
            {
                p.ProductKey = null;
            }
            else
            {
                var pk = request.ProductKey.Trim();
                var productExists = await db.Products.AsNoTracking().AnyAsync(x => x.ProductKey == pk, ct);
                if (!productExists)
                {
                    return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "product not found"), statusCode: StatusCodes.Status404NotFound);
                }

                p.ProductKey = pk;
            }
        }

        if (request.Description is not null)
        {
            var desc = request.Description.Trim();
            if (desc.Length != 0)
            {
                p.Description = desc;
            }
        }

        p.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.permission.update",
            outcome: "success",
            detail: request.Reason,
            meta: new { p.PermKey, p.ProductKey },
            ct);

        return TypedResults.Json(ApiResponse<PermissionDto>.Ok(new PermissionDto(
            p.PermKey,
            p.ProductKey,
            p.Description,
            p.CreatedAt,
            p.UpdatedAt)));
    }).RequireAuthorization("PlatformPermissionsWrite");

    platform.MapDelete("/permissions/{permissionKey}", async Task<Results<NoContent, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        IAuditEventWriter audit,
        string permissionKey,
        string? reason,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(permissionKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "permissionKey is required", SingleField("permissionKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var key = permissionKey.Trim();
        var p = await db.Permissions.FirstOrDefaultAsync(x => x.PermKey == key, ct);
        if (p is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "permission not found"), statusCode: StatusCodes.Status404NotFound);
        }

        db.Permissions.Remove(p);
        await db.SaveChangesAsync(ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.permission.delete",
            outcome: "success",
            detail: reason,
            meta: new { PermissionKey = key },
            ct);

        return TypedResults.NoContent();
    }).RequireAuthorization("PlatformPermissionsWrite");

    // Tenants (list/get/create)
    platform.MapGet("/tenants", async Task<Results<JsonHttpResult<ApiResponse<IReadOnlyList<TenantDto>>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        int? skip,
        int? take,
        int? status,
        CancellationToken ct) =>
    {
        var s = Math.Max(0, skip ?? 0);
        var t = Math.Clamp(take ?? 50, 1, 200);

        var query = db.Tenants.AsNoTracking();
        if (status is not null)
        {
            query = query.Where(x => x.Status == status.Value);
        }

        var items = await query
            .OrderBy(x => x.Name)
            .Skip(s)
            .Take(t)
            .Select(x => new TenantDto
            {
                TenantId = x.TenantId,
                Name = x.Name,
                Status = (TenantStatus)x.Status,
                TokenVersion = x.TokenVersion,
                CreatedAt = x.CreatedAt,
            })
            .ToListAsync(ct);

        return TypedResults.Json(ApiResponse<IReadOnlyList<TenantDto>>.Ok(items));
    }).RequireAuthorization("PlatformTenantsRead");

    platform.MapGet("/tenants/{tenantId:guid}", async Task<Results<JsonHttpResult<ApiResponse<TenantDto>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        Guid tenantId,
        CancellationToken ct) =>
    {
        var t = await db.Tenants.AsNoTracking().FirstOrDefaultAsync(x => x.TenantId == tenantId, ct);
        if (t is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant not found"), statusCode: StatusCodes.Status404NotFound);
        }

        return TypedResults.Json(ApiResponse<TenantDto>.Ok(new TenantDto
        {
            TenantId = t.TenantId,
            Name = t.Name,
            Status = (TenantStatus)t.Status,
            TokenVersion = t.TokenVersion,
            CreatedAt = t.CreatedAt,
        }));
    }).RequireAuthorization("PlatformTenantsRead");

    platform.MapPost("/tenants", async Task<Results<JsonHttpResult<ApiResponse<TenantDto>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        IAuditEventWriter audit,
        PlatformCreateTenantRequest request,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "name is required", SingleField("name", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var tenantId = request.TenantId ?? Guid.NewGuid();
        if (tenantId == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "tenantId is invalid", SingleField("tenantId", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        var exists = await db.Tenants.AsNoTracking().AnyAsync(x => x.TenantId == tenantId, ct);
        if (exists)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Conflict, "tenantId already exists"), statusCode: StatusCodes.Status409Conflict);
        }

        var now = DateTimeOffset.UtcNow;
        var entity = new Birdsoft.Security.Data.EfCore.Entities.TenantEntity
        {
            TenantId = tenantId,
            Name = request.Name.Trim(),
            Status = (int)(request.Status ?? TenantStatus.Active),
            TokenVersion = 1,
            CreatedAt = now,
            UpdatedAt = now,
        };

        db.Tenants.Add(entity);
        await db.SaveChangesAsync(ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.tenant.create",
            outcome: "success",
            detail: request.Reason,
            meta: new { entity.TenantId, entity.Name, entity.Status },
            ct);

        return TypedResults.Json(ApiResponse<TenantDto>.Ok(new TenantDto
        {
            TenantId = entity.TenantId,
            Name = entity.Name,
            Status = (TenantStatus)entity.Status,
            TokenVersion = entity.TokenVersion,
            CreatedAt = entity.CreatedAt,
        }), statusCode: StatusCodes.Status201Created);
    }).RequireAuthorization("PlatformTenantsWrite");

    platform.MapPut("/tenants/{tenantId:guid}", async Task<Results<JsonHttpResult<ApiResponse<TenantDto>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        IAuditEventWriter audit,
        Guid tenantId,
        PlatformUpdateTenantRequest request,
        CancellationToken ct) =>
    {
        if (tenantId == Guid.Empty)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "tenantId is invalid", SingleField("tenantId", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        var entity = await db.Tenants.FirstOrDefaultAsync(x => x.TenantId == tenantId, ct);
        if (entity is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant not found"), statusCode: StatusCodes.Status404NotFound);
        }

        var mutated = false;

        if (!string.IsNullOrWhiteSpace(request.Name))
        {
            entity.Name = request.Name.Trim();
            mutated = true;
        }

        if (request.Status is not null)
        {
            entity.Status = (int)request.Status.Value;
            mutated = true;
        }

        if (!mutated)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "no updatable fields provided"), statusCode: StatusCodes.Status400BadRequest);
        }

        // Governance changes should invalidate refresh tokens immediately.
        entity.TokenVersion = Math.Max(1, entity.TokenVersion + 1);
        entity.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.tenant.update",
            outcome: "success",
            detail: request.Reason,
            meta: new { entity.TenantId, entity.Name, entity.Status, entity.TokenVersion },
            ct);

        return TypedResults.Json(ApiResponse<TenantDto>.Ok(new TenantDto
        {
            TenantId = entity.TenantId,
            Name = entity.Name,
            Status = (TenantStatus)entity.Status,
            TokenVersion = entity.TokenVersion,
            CreatedAt = entity.CreatedAt,
        }));
    }).RequireAuthorization("PlatformTenantsWrite");

    var listTenantProducts = async Task<Results<JsonHttpResult<ApiResponse<IReadOnlyList<TenantProductDto>>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        Guid tenantId,
        CancellationToken ct) =>
    {
        var tenantExists = await db.Tenants.AsNoTracking().AnyAsync(x => x.TenantId == tenantId, ct);
        if (!tenantExists)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant not found"), statusCode: StatusCodes.Status404NotFound);
        }

        var items = await (
            from tp in db.TenantProducts.AsNoTracking()
            join p in db.Products.AsNoTracking() on tp.ProductKey equals p.ProductKey into p0
            from p in p0.DefaultIfEmpty()
            where tp.TenantId == tenantId
            orderby tp.ProductKey
            select new TenantProductDto(
                tp.TenantId,
                tp.ProductKey,
                p != null ? p.DisplayName : null,
                (TenantProductStatus)tp.Status,
                tp.StartAt,
                tp.EndAt,
                tp.PlanJson,
                tp.CreatedAt,
                tp.UpdatedAt))
            .ToListAsync(ct);

        return TypedResults.Json(ApiResponse<IReadOnlyList<TenantProductDto>>.Ok(items));
    };

    platform.MapGet("/tenants/{tenantId:guid}/products", listTenantProducts)
        .RequireAuthorization("PlatformEntitlementsRead");
    platform.MapGet("/tenants/{tenantId:guid}/entitlements", listTenantProducts)
        .RequireAuthorization("PlatformEntitlementsRead");

    var getTenantProduct = async Task<Results<JsonHttpResult<ApiResponse<TenantProductDto>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        Guid tenantId,
        string productKey,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var tenantExists = await db.Tenants.AsNoTracking().AnyAsync(x => x.TenantId == tenantId, ct);
        if (!tenantExists)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant not found"), statusCode: StatusCodes.Status404NotFound);
        }

        productKey = productKey.Trim();

        var item = await (
            from tp in db.TenantProducts.AsNoTracking()
            join p in db.Products.AsNoTracking() on tp.ProductKey equals p.ProductKey into p0
            from p in p0.DefaultIfEmpty()
            where tp.TenantId == tenantId && tp.ProductKey == productKey
            select new TenantProductDto(
                tp.TenantId,
                tp.ProductKey,
                p != null ? p.DisplayName : null,
                (TenantProductStatus)tp.Status,
                tp.StartAt,
                tp.EndAt,
                tp.PlanJson,
                tp.CreatedAt,
                tp.UpdatedAt))
            .FirstOrDefaultAsync(ct);

        if (item is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant product not found"), statusCode: StatusCodes.Status404NotFound);
        }

        return TypedResults.Json(ApiResponse<TenantProductDto>.Ok(item));
    };

    platform.MapGet("/tenants/{tenantId:guid}/products/{productKey}", getTenantProduct)
        .RequireAuthorization("PlatformEntitlementsRead");
    platform.MapGet("/tenants/{tenantId:guid}/entitlements/{productKey}", getTenantProduct)
        .RequireAuthorization("PlatformEntitlementsRead");

    var createTenantProduct = async Task<Results<JsonHttpResult<ApiResponse<TenantProductDto>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        IAuditEventWriter audit,
        Guid tenantId,
        PlatformCreateTenantProductRequest request,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(request.ProductKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var tenantExists = await db.Tenants.AsNoTracking().AnyAsync(x => x.TenantId == tenantId, ct);
        if (!tenantExists)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant not found"), statusCode: StatusCodes.Status404NotFound);
        }

        var productKey = request.ProductKey.Trim();

        var productExists = await db.Products.AsNoTracking().AnyAsync(x => x.ProductKey == productKey, ct);
        if (!productExists)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "product not found"), statusCode: StatusCodes.Status404NotFound);
        }

        var existing = await db.TenantProducts.AsNoTracking().AnyAsync(x => x.TenantId == tenantId && x.ProductKey == productKey, ct);
        if (existing)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.Conflict, "tenant product already exists"), statusCode: StatusCodes.Status409Conflict);
        }

        var now = DateTimeOffset.UtcNow;
        var startAt = request.StartAt ?? now;
        var endAt = request.EndAt;
        if (endAt is not null && endAt.Value <= startAt)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "endAt must be after startAt", SingleField("endAt", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        var tp = new Birdsoft.Security.Data.EfCore.Entities.TenantProductEntity
        {
            TenantId = tenantId,
            ProductKey = productKey,
            Status = (int)(request.Status ?? TenantProductStatus.Enabled),
            StartAt = startAt,
            EndAt = endAt,
            PlanJson = request.PlanJson,
            CreatedAt = now,
            UpdatedAt = now,
        };

        db.TenantProducts.Add(tp);
        await db.SaveChangesAsync(ct);

        var display = await db.Products.AsNoTracking()
            .Where(x => x.ProductKey == productKey)
            .Select(x => x.DisplayName)
            .FirstAsync(ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.tenant_product.create",
            outcome: "success",
            detail: request.Reason,
            meta: new { tp.TenantId, tp.ProductKey, tp.Status, tp.StartAt, tp.EndAt },
            ct);

        return TypedResults.Json(ApiResponse<TenantProductDto>.Ok(new TenantProductDto(
            tp.TenantId,
            tp.ProductKey,
            display,
            (TenantProductStatus)tp.Status,
            tp.StartAt,
            tp.EndAt,
            tp.PlanJson,
            tp.CreatedAt,
            tp.UpdatedAt)), statusCode: StatusCodes.Status201Created);
    };

    platform.MapPost("/tenants/{tenantId:guid}/products", createTenantProduct)
        .RequireAuthorization("PlatformEntitlementsWrite");
    platform.MapPost("/tenants/{tenantId:guid}/entitlements", createTenantProduct)
        .RequireAuthorization("PlatformEntitlementsWrite");

    var updateTenantProduct = async Task<Results<JsonHttpResult<ApiResponse<TenantProductDto>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        IAuditEventWriter audit,
        Guid tenantId,
        string productKey,
        JsonElement request,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        if (request.ValueKind != JsonValueKind.Object)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "request body must be a JSON object"), statusCode: StatusCodes.Status400BadRequest);
        }

        var tenantExists = await db.Tenants.AsNoTracking().AnyAsync(x => x.TenantId == tenantId, ct);
        if (!tenantExists)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant not found"), statusCode: StatusCodes.Status404NotFound);
        }

        productKey = productKey.Trim();
        var productExists = await db.Products.AsNoTracking().AnyAsync(x => x.ProductKey == productKey, ct);
        if (!productExists)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "product not found"), statusCode: StatusCodes.Status404NotFound);
        }

        var now = DateTimeOffset.UtcNow;
        var tp = await db.TenantProducts.FirstOrDefaultAsync(x => x.TenantId == tenantId && x.ProductKey == productKey, ct);
        if (tp is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant product not found"), statusCode: StatusCodes.Status404NotFound);
        }

        static bool TryReadEnumInt<TEnum>(JsonElement obj, string name, out TEnum value) where TEnum : struct, Enum
        {
            value = default;
            if (!obj.TryGetProperty(name, out var el))
            {
                return false;
            }

            if (el.ValueKind == JsonValueKind.Null)
            {
                throw new InvalidOperationException($"{name} cannot be null");
            }

            if (el.ValueKind != JsonValueKind.Number || !el.TryGetInt32(out var i))
            {
                throw new InvalidOperationException($"{name} must be an integer");
            }

            if (!Enum.IsDefined(typeof(TEnum), i))
            {
                throw new InvalidOperationException($"{name} is invalid");
            }

            value = (TEnum)Enum.ToObject(typeof(TEnum), i);
            return true;
        }

        static bool TryReadDateTimeOffset(JsonElement obj, string name, out DateTimeOffset value)
        {
            value = default;
            if (!obj.TryGetProperty(name, out var el))
            {
                return false;
            }

            if (el.ValueKind == JsonValueKind.Null)
            {
                throw new InvalidOperationException($"{name} cannot be null");
            }

            try
            {
                value = el.GetDateTimeOffset();
                return true;
            }
            catch
            {
                throw new InvalidOperationException($"{name} must be a datetime");
            }
        }

        static bool TryReadNullableDateTimeOffset(JsonElement obj, string name, out DateTimeOffset? value)
        {
            value = null;
            if (!obj.TryGetProperty(name, out var el))
            {
                return false;
            }

            if (el.ValueKind == JsonValueKind.Null)
            {
                value = null;
                return true;
            }

            try
            {
                value = el.GetDateTimeOffset();
                return true;
            }
            catch
            {
                throw new InvalidOperationException($"{name} must be a datetime or null");
            }
        }

        static bool TryReadNullableString(JsonElement obj, string name, out string? value)
        {
            value = null;
            if (!obj.TryGetProperty(name, out var el))
            {
                return false;
            }

            if (el.ValueKind == JsonValueKind.Null)
            {
                value = null;
                return true;
            }

            if (el.ValueKind != JsonValueKind.String)
            {
                throw new InvalidOperationException($"{name} must be a string or null");
            }

            var s = el.GetString();
            if (s is not null && s.Length != 0 && string.IsNullOrWhiteSpace(s))
            {
                throw new InvalidOperationException($"{name} cannot be whitespace");
            }

            value = s;
            return true;
        }

        string? reason = null;
        if (request.TryGetProperty("reason", out var reasonEl) && reasonEl.ValueKind == JsonValueKind.String)
        {
            var r = reasonEl.GetString();
            reason = string.IsNullOrWhiteSpace(r) ? null : r;
        }

        var hasMutationFields = false;

        TenantProductStatus? newStatus = null;
        DateTimeOffset? newStartAt = null;
        DateTimeOffset? newEndAt = null;
        string? newPlanJson = null;

        var statusProvided = false;
        var startAtProvided = false;
        var endAtProvided = false;
        var planJsonProvided = false;

        try
        {
            if (TryReadEnumInt<TenantProductStatus>(request, "status", out var s))
            {
                statusProvided = true;
                hasMutationFields = true;
                newStatus = s;
            }

            if (TryReadDateTimeOffset(request, "startAt", out var sa))
            {
                startAtProvided = true;
                hasMutationFields = true;
                newStartAt = sa;
            }

            if (TryReadNullableDateTimeOffset(request, "endAt", out var ea))
            {
                endAtProvided = true;
                hasMutationFields = true;
                newEndAt = ea;
            }

            if (TryReadNullableString(request, "planJson", out var pj))
            {
                planJsonProvided = true;
                hasMutationFields = true;
                newPlanJson = pj;
            }
        }
        catch (InvalidOperationException ex)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, ex.Message), statusCode: StatusCodes.Status400BadRequest);
        }

        if (!hasMutationFields)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "no updatable fields provided"), statusCode: StatusCodes.Status400BadRequest);
        }

        var effectiveStartAt = startAtProvided ? newStartAt!.Value : tp.StartAt;
        var effectiveEndAt = endAtProvided ? newEndAt : tp.EndAt;
        if (effectiveEndAt is not null && effectiveEndAt.Value <= effectiveStartAt)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "endAt must be after startAt", SingleField("endAt", "invalid")), statusCode: StatusCodes.Status400BadRequest);
        }

        if (statusProvided)
        {
            tp.Status = (int)newStatus!.Value;
        }

        if (startAtProvided)
        {
            tp.StartAt = newStartAt!.Value;
        }

        if (endAtProvided)
        {
            tp.EndAt = newEndAt;
        }

        if (planJsonProvided)
        {
            tp.PlanJson = newPlanJson;
        }

        tp.UpdatedAt = now;
        await db.SaveChangesAsync(ct);

        var display = await db.Products.AsNoTracking()
            .Where(x => x.ProductKey == productKey)
            .Select(x => x.DisplayName)
            .FirstAsync(ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.tenant_product.update",
            outcome: "success",
            detail: reason,
            meta: new { tp.TenantId, tp.ProductKey, tp.Status, tp.StartAt, tp.EndAt },
            ct);

        return TypedResults.Json(ApiResponse<TenantProductDto>.Ok(new TenantProductDto(
            tp.TenantId,
            tp.ProductKey,
            display,
            (TenantProductStatus)tp.Status,
            tp.StartAt,
            tp.EndAt,
            tp.PlanJson,
            tp.CreatedAt,
            tp.UpdatedAt)));
    };

    platform.MapPut("/tenants/{tenantId:guid}/products/{productKey}", updateTenantProduct)
        .RequireAuthorization("PlatformEntitlementsWrite");
    platform.MapPut("/tenants/{tenantId:guid}/entitlements/{productKey}", updateTenantProduct)
        .RequireAuthorization("PlatformEntitlementsWrite");

    var deleteTenantProduct = async Task<Results<NoContent, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        IAuditEventWriter audit,
        Guid tenantId,
        string productKey,
        string? reason,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        productKey = productKey.Trim();

        var tenantExists = await db.Tenants.AsNoTracking().AnyAsync(x => x.TenantId == tenantId, ct);
        if (!tenantExists)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant not found"), statusCode: StatusCodes.Status404NotFound);
        }

        var entity = await db.TenantProducts
            .FirstOrDefaultAsync(x => x.TenantId == tenantId && x.ProductKey == productKey, ct);

        if (entity is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant product not found"), statusCode: StatusCodes.Status404NotFound);
        }

        // V19: entitlements are never hard-deleted. DELETE means disable.
        entity.Status = (int)TenantProductStatus.Disabled;
        entity.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        await WritePlatformAuditAsync(
            http,
            audit,
            code: "platform.tenant_product.disable",
            outcome: "success",
            detail: reason,
            meta: new { entity.TenantId, entity.ProductKey, entity.Status },
            ct);

        return TypedResults.NoContent();
    };

    platform.MapDelete("/tenants/{tenantId:guid}/products/{productKey}", deleteTenantProduct)
        .RequireAuthorization("PlatformEntitlementsWrite");
    platform.MapDelete("/tenants/{tenantId:guid}/entitlements/{productKey}", deleteTenantProduct)
        .RequireAuthorization("PlatformEntitlementsWrite");

    var tenant = api.MapGroup("/tenant");
    tenant.RequireAuthorization("AdminOnly");

    tenant.MapGet("/products", async Task<Results<JsonHttpResult<ApiResponse<IReadOnlyList<TenantProductDto>>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        DateTimeOffset? now,
        CancellationToken ct) =>
    {
        var tenantId = TryGetTenantIdFromToken(http);
        if (tenantId is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "tenant_id claim is required"), statusCode: StatusCodes.Status400BadRequest);
        }

        var clock = now ?? DateTimeOffset.UtcNow;

        // SQLite has limitations translating DateTimeOffset comparisons; filter time windows in-memory only for SQLite.
        List<TenantProductDto> items;
        if (db.Database.IsSqlite())
        {
            items = await (
                from tp in db.TenantProducts.AsNoTracking()
                join p in db.Products.AsNoTracking() on tp.ProductKey equals p.ProductKey
                where tp.TenantId == tenantId.Value
                    && tp.Status == (int)TenantProductStatus.Enabled
                    && p.Status == (int)ProductStatus.Enabled
                orderby tp.ProductKey
                select new TenantProductDto(
                    tp.TenantId,
                    tp.ProductKey,
                    p.DisplayName,
                    (TenantProductStatus)tp.Status,
                    tp.StartAt,
                    tp.EndAt,
                    tp.PlanJson,
                    tp.CreatedAt,
                    tp.UpdatedAt))
                .ToListAsync(ct);

            items = items
                .Where(x => x.StartAt <= clock && (x.EndAt is null || x.EndAt > clock))
                .ToList();
        }
        else
        {
            items = await (
                from tp in db.TenantProducts.AsNoTracking()
                join p in db.Products.AsNoTracking() on tp.ProductKey equals p.ProductKey
                where tp.TenantId == tenantId.Value
                    && tp.Status == (int)TenantProductStatus.Enabled
                    && p.Status == (int)ProductStatus.Enabled
                    && tp.StartAt <= clock
                    && (tp.EndAt == null || tp.EndAt > clock)
                orderby tp.ProductKey
                select new TenantProductDto(
                    tp.TenantId,
                    tp.ProductKey,
                    p.DisplayName,
                    (TenantProductStatus)tp.Status,
                    tp.StartAt,
                    tp.EndAt,
                    tp.PlanJson,
                    tp.CreatedAt,
                    tp.UpdatedAt))
                .ToListAsync(ct);
        }

        return TypedResults.Json(ApiResponse<IReadOnlyList<TenantProductDto>>.Ok(items));
    });

    tenant.MapGet("/products/{productKey}", async Task<Results<JsonHttpResult<ApiResponse<TenantProductDto>>, JsonHttpResult<ApiResponse<object>>>> (
        HttpContext http,
        SecurityDbContext db,
        string productKey,
        DateTimeOffset? now,
        CancellationToken ct) =>
    {
        var tenantId = TryGetTenantIdFromToken(http);
        if (tenantId is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "tenant_id claim is required"), statusCode: StatusCodes.Status400BadRequest);
        }

        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var clock = now ?? DateTimeOffset.UtcNow;

        var item = await (
            from tp in db.TenantProducts.AsNoTracking()
            join p in db.Products.AsNoTracking() on tp.ProductKey equals p.ProductKey
            where tp.TenantId == tenantId.Value && tp.ProductKey == productKey
            select new { tp, p })
            .FirstOrDefaultAsync(ct);

        if (item is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant product not found"), statusCode: StatusCodes.Status404NotFound);
        }

        // If it's not currently enabled, still return it (tenant admins need visibility).
        _ = clock;

        return TypedResults.Json(ApiResponse<TenantProductDto>.Ok(new TenantProductDto(
            item.tp.TenantId,
            item.tp.ProductKey,
            item.p.DisplayName,
            (TenantProductStatus)item.tp.Status,
            item.tp.StartAt,
            item.tp.EndAt,
            item.tp.PlanJson,
            item.tp.CreatedAt,
            item.tp.UpdatedAt)));
    });

    tenant.MapTenantPermissionManagement();
}

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

public sealed record ProductDto(
    string ProductKey,
    string DisplayName,
    string? Description,
    ProductStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record TenantProductDto(
    Guid TenantId,
    string ProductKey,
    string? DisplayName,
    TenantProductStatus Status,
    DateTimeOffset StartAt,
    DateTimeOffset? EndAt,
    string? PlanJson,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record PermissionDto(
    string PermissionKey,
    string? ProductKey,
    string? Description,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

public sealed record PlatformAuditLogDto(
    Guid Id,
    DateTimeOffset OccurredAt,
    Guid? OurSubject,
    Guid? TenantId,
    string Outcome,
    string? Code);

public sealed record PlatformCreateProductRequest(
    string ProductKey,
    string DisplayName,
    string? Description,
    ProductStatus? Status,
    string? Reason);

public sealed record PlatformUpdateProductRequest(
    string? DisplayName,
    string? Description,
    ProductStatus? Status,
    string? Reason);

public sealed record PlatformCreatePermissionRequest(
    string PermissionKey,
    string? ProductKey,
    string? Description,
    string? Reason);

public sealed record PlatformUpdatePermissionRequest(
    string? ProductKey,
    string? Description,
    string? Reason);

public sealed record PlatformCreateTenantRequest(
    Guid? TenantId,
    string Name,
    TenantStatus? Status,
    string? Reason);

public sealed record PlatformUpdateTenantRequest(
    string? Name,
    TenantStatus? Status,
    string? Reason);

public sealed record PlatformCreateTenantProductRequest(
    string ProductKey,
    TenantProductStatus? Status,
    DateTimeOffset? StartAt,
    DateTimeOffset? EndAt,
    string? PlanJson,
    string? Reason);

public sealed record PlatformUpdateTenantProductRequest(
    TenantProductStatus? Status,
    DateTimeOffset? StartAt,
    DateTimeOffset? EndAt,
    string? PlanJson,
    string? Reason);

public partial class Program { }
