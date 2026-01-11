using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Contracts.Authz;
using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Authorization.Evaluation;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

// Default (in-memory) authorization data store; replace with DB-backed implementation via DI.
builder.Services.AddSingleton<IAuthorizationDataStore, InMemoryAuthorizationDataStore>();

builder.Services.AddSingleton<IAuthorizationEvaluator, SimpleRbacAuthorizationEvaluator>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

var api = app.MapGroup("/api/v1");
var authz = api.MapGroup("/authz");

authz.MapPost("/check", async (HttpContext http, AuthzCheckRequest request, IAuthorizationEvaluator evaluator, CancellationToken ct) =>
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
        return Results.Json(ApiResponse<object>.Fail("invalid_request"), statusCode: StatusCodes.Status400BadRequest);
    }

    if (string.IsNullOrWhiteSpace(request.Resource) || string.IsNullOrWhiteSpace(request.Action))
    {
        return Results.Json(ApiResponse<object>.Fail("invalid_request"), statusCode: StatusCodes.Status400BadRequest);
    }

    var decision = await evaluator.EvaluateAsync(
        new AuthorizationRequest(tenantId ?? throw new InvalidOperationException(), request.OurSubject, request.Resource, request.Action, request.Context),
        ct);

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
}
