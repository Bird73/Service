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
            if (platformRoles.Any(r => string.Equals(r, "platform_admin", StringComparison.OrdinalIgnoreCase)))
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

            // Platform admin must be cross-tenant; explicitly reject tenant-bound tokens.
            var tenantId = user.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.TenantId)?.Value;
            if (!string.IsNullOrWhiteSpace(tenantId))
            {
                return false;
            }

            var scope = user.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scope)?.Value
                ?? user.FindFirst(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Scopes)?.Value;
            if (!string.IsNullOrWhiteSpace(scope) && scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Any(s => string.Equals(s, "security.platform_admin", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            var roles = user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Roles).Select(c => c.Value)
                .Concat(user.FindAll(Birdsoft.Security.Abstractions.Constants.SecurityClaimTypes.Role).Select(c => c.Value));
            return roles.Any(r => string.Equals(r, "platform_admin", StringComparison.OrdinalIgnoreCase));
        });
    });
});
builder.Services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>, BirdsoftJwtBearerPostConfigureOptions>();

// Emit spec-like JSON bodies for 401/403 produced by authorization middleware.
builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, ApiAuthorizationMiddlewareResultHandler>();

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
    builder.Services.AddSingleton<IAuthorizationDataStore, InMemoryAuthorizationDataStore>();
}

// Entitlement gating: EF-backed when available; otherwise allow-all for dev/in-memory mode.
if (!useEf)
{
    builder.Services.AddSingleton<IPermissionCatalogStore, NullPermissionCatalogStore>();
    builder.Services.AddSingleton<ITenantEntitlementStore, AllowAllTenantEntitlementStore>();
}

builder.Services.AddScoped<SimpleRbacAuthorizationEvaluator>();
builder.Services.AddScoped<AuthzEvaluator>(sp =>
    new EntitlementAuthorizationEvaluator(
        sp.GetRequiredService<SimpleRbacAuthorizationEvaluator>(),
        sp.GetRequiredService<IPermissionCatalogStore>(),
        sp.GetRequiredService<ITenantEntitlementStore>()));

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
    platform.RequireAuthorization("PlatformAdminOnly");

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
    });

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
    });

    platform.MapPost("/products", async Task<Results<JsonHttpResult<ApiResponse<ProductDto>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
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

        return TypedResults.Json(ApiResponse<ProductDto>.Ok(new ProductDto(
            entity.ProductKey,
            entity.DisplayName,
            entity.Description,
            (ProductStatus)entity.Status,
            entity.CreatedAt,
            entity.UpdatedAt)), statusCode: StatusCodes.Status201Created);
    });

    platform.MapPut("/products/{productKey}", async Task<Results<JsonHttpResult<ApiResponse<ProductDto>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        string productKey,
        PlatformUpdateProductRequest request,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

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
            p.Description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim();
        }

        if (request.Status is not null)
        {
            p.Status = (int)request.Status.Value;
        }

        p.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        return TypedResults.Json(ApiResponse<ProductDto>.Ok(new ProductDto(
            p.ProductKey,
            p.DisplayName,
            p.Description,
            (ProductStatus)p.Status,
            p.CreatedAt,
            p.UpdatedAt)));
    });

    platform.MapGet("/tenants/{tenantId:guid}/products", async Task<Results<JsonHttpResult<ApiResponse<IReadOnlyList<TenantProductDto>>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        Guid tenantId,
        CancellationToken ct) =>
    {
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
    });

    platform.MapGet("/tenants/{tenantId:guid}/products/{productKey}", async Task<Results<JsonHttpResult<ApiResponse<TenantProductDto>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        Guid tenantId,
        string productKey,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

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
    });

    platform.MapPut("/tenants/{tenantId:guid}/products/{productKey}", async Task<Results<JsonHttpResult<ApiResponse<TenantProductDto>>, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        Guid tenantId,
        string productKey,
        PlatformUpsertTenantProductRequest request,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var productExists = await db.Products.AsNoTracking().AnyAsync(x => x.ProductKey == productKey, ct);
        if (!productExists)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "product not found"), statusCode: StatusCodes.Status404NotFound);
        }

        var now = DateTimeOffset.UtcNow;
        var tp = await db.TenantProducts.FirstOrDefaultAsync(x => x.TenantId == tenantId && x.ProductKey == productKey, ct);

        if (tp is null)
        {
            tp = new Birdsoft.Security.Data.EfCore.Entities.TenantProductEntity
            {
                TenantId = tenantId,
                ProductKey = productKey,
                Status = (int)(request.Status ?? TenantProductStatus.Enabled),
                StartAt = request.StartAt ?? now,
                EndAt = request.EndAt,
                PlanJson = request.PlanJson,
                CreatedAt = now,
                UpdatedAt = now,
            };

            db.TenantProducts.Add(tp);
        }
        else
        {
            if (request.Status is not null)
            {
                tp.Status = (int)request.Status.Value;
            }

            if (request.StartAt is not null)
            {
                tp.StartAt = request.StartAt.Value;
            }

            tp.EndAt = request.EndAt;
            tp.PlanJson = request.PlanJson;

            tp.UpdatedAt = now;
        }

        await db.SaveChangesAsync(ct);

        var display = await db.Products.AsNoTracking()
            .Where(x => x.ProductKey == productKey)
            .Select(x => x.DisplayName)
            .FirstAsync(ct);

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
    });

    platform.MapDelete("/tenants/{tenantId:guid}/products/{productKey}", async Task<Results<NoContent, JsonHttpResult<ApiResponse<object>>>> (
        SecurityDbContext db,
        Guid tenantId,
        string productKey,
        CancellationToken ct) =>
    {
        if (string.IsNullOrWhiteSpace(productKey))
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.InvalidRequest, "productKey is required", SingleField("productKey", "required")), statusCode: StatusCodes.Status400BadRequest);
        }

        var entity = await db.TenantProducts
            .FirstOrDefaultAsync(x => x.TenantId == tenantId && x.ProductKey == productKey, ct);

        if (entity is null)
        {
            return TypedResults.Json(ApiResponse<object>.Fail(AuthErrorCodes.NotFound, "tenant product not found"), statusCode: StatusCodes.Status404NotFound);
        }

        db.TenantProducts.Remove(entity);
        await db.SaveChangesAsync(ct);
        return TypedResults.NoContent();
    });

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

public sealed record PlatformCreateProductRequest(
    string ProductKey,
    string DisplayName,
    string? Description,
    ProductStatus? Status);

public sealed record PlatformUpdateProductRequest(
    string? DisplayName,
    string? Description,
    ProductStatus? Status);

public sealed record PlatformUpsertTenantProductRequest(
    TenantProductStatus? Status,
    DateTimeOffset? StartAt,
    DateTimeOffset? EndAt,
    string? PlanJson);

public partial class Program { }
