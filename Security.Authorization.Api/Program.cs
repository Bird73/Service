using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Contracts.Authz;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Models;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authorization.Evaluation;
using Birdsoft.Security.Authorization.Api.Auth;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Birdsoft.Security.Data.EfCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection(JwtOptions.SectionName));

builder.Services.AddSingleton<IJwtKeyProvider, DefaultJwtKeyProvider>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();
builder.Services.AddAuthorization();
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
    builder.Services.AddSingleton<IAuthEventStore, NoOpAuthEventStore>();
}

// Default (in-memory) authorization data store; replace with DB-backed implementation via DI.
builder.Services.AddSingleton<IAuthorizationDataStore, InMemoryAuthorizationDataStore>();

builder.Services.AddSingleton<IAuthorizationEvaluator, SimpleRbacAuthorizationEvaluator>();

var app = builder.Build();

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

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

var api = app.MapGroup("/api/v1");
var authz = api.MapGroup("/authz");

authz.MapPost("/check", async (HttpContext http, AuthzCheckRequest request, IAuthorizationEvaluator evaluator, IAuthEventStore events, CancellationToken ct) =>
{
    static Guid? ResolveTenantId(HttpContext http)
    {
        var claim = http.User?.FindFirst(SecurityClaimTypes.TenantId)?.Value;
        if (!string.IsNullOrWhiteSpace(claim) && Guid.TryParse(claim, out var fromClaim))
        {
            return fromClaim;
        }

        if (http.Request.Headers.TryGetValue("X-Tenant-Id", out var header)
            && Guid.TryParse(header.ToString(), out var fromHeader))
        {
            return fromHeader;
        }

        return null;
    }

    var tenantId = ResolveTenantId(http);

    if (tenantId == null || request.OurSubject == Guid.Empty)
    {
        try
        {
            await events.AppendAsync(new AuthEvent
            {
                Id = Guid.NewGuid(),
                OccurredAt = DateTimeOffset.UtcNow,
                Type = AuthEventType.Authorization,
                Outcome = "fail",
                Detail = "invalid_request",
            }, ct);
        }
        catch
        {
        }

        return Results.Json(ApiResponse<object>.Fail("invalid_request"), statusCode: StatusCodes.Status400BadRequest);
    }

    if (string.IsNullOrWhiteSpace(request.Resource) || string.IsNullOrWhiteSpace(request.Action))
    {
        try
        {
            await events.AppendAsync(new AuthEvent
            {
                Id = Guid.NewGuid(),
                OccurredAt = DateTimeOffset.UtcNow,
                TenantId = tenantId,
                OurSubject = request.OurSubject,
                Type = AuthEventType.Authorization,
                Outcome = "fail",
                Detail = "invalid_request",
            }, ct);
        }
        catch
        {
        }

        return Results.Json(ApiResponse<object>.Fail("invalid_request"), statusCode: StatusCodes.Status400BadRequest);
    }

    var tenants = http.RequestServices.GetService<Birdsoft.Security.Abstractions.Repositories.ITenantRepository>();
    if (tenants is not null)
    {
        var tenant = await tenants.FindAsync(tenantId ?? throw new InvalidOperationException(), ct);
        if (tenant is null || tenant.Status != Birdsoft.Security.Abstractions.Models.TenantStatus.Active)
        {
            try
            {
                await events.AppendAsync(new AuthEvent
                {
                    Id = Guid.NewGuid(),
                    OccurredAt = DateTimeOffset.UtcNow,
                    TenantId = tenantId,
                    OurSubject = request.OurSubject,
                    Type = AuthEventType.Authorization,
                    Outcome = "fail",
                    Detail = "tenant_not_active",
                }, ct);
            }
            catch
            {
            }

            return Results.Json(ApiResponse<object>.Fail("tenant_not_active"), statusCode: StatusCodes.Status403Forbidden);
        }
    }

    var subjects = http.RequestServices.GetService<Birdsoft.Security.Abstractions.Repositories.ISubjectRepository>();
    if (subjects is not null)
    {
        var subject = await subjects.FindAsync(tenantId ?? throw new InvalidOperationException(), request.OurSubject, ct);
        if (subject is null || subject.Status != Birdsoft.Security.Abstractions.Models.UserStatus.Active)
        {
            try
            {
                await events.AppendAsync(new AuthEvent
                {
                    Id = Guid.NewGuid(),
                    OccurredAt = DateTimeOffset.UtcNow,
                    TenantId = tenantId,
                    OurSubject = request.OurSubject,
                    Type = AuthEventType.Authorization,
                    Outcome = "fail",
                    Detail = "user_not_active",
                }, ct);
            }
            catch
            {
            }

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

    try
    {
        await events.AppendAsync(new AuthEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = DateTimeOffset.UtcNow,
            TenantId = tenantId,
            OurSubject = request.OurSubject,
            SessionId = sessionId,
            Type = AuthEventType.Authorization,
            Outcome = decision.Allowed ? "allow" : "deny",
            Detail = decision.Reason,
        }, ct);
    }
    catch
    {
    }

    return Results.Json(ApiResponse<AuthzCheckResponse>.Ok(new AuthzCheckResponse(decision.Allowed, decision.Reason)));
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
