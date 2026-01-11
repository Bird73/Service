using Birdsoft.Security.Abstractions;
using Birdsoft.Security.Abstractions.Contracts.Auth;
using Birdsoft.Security.Abstractions.Contracts.Common;
using Birdsoft.Security.Abstractions.Options;
using Birdsoft.Security.Abstractions.Repositories;
using Birdsoft.Security.Abstractions.Services;
using Birdsoft.Security.Abstractions.Stores;
using Birdsoft.Security.Abstractions.Tenancy;
using Birdsoft.Security.Authentication;
using Birdsoft.Security.Authentication.Auth;
using Birdsoft.Security.Authentication.Jwt;
using Birdsoft.Security.Authentication.Persistence;
using Birdsoft.Security.Authentication.Tenancy;
using Birdsoft.Security.Data.EfCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection(JwtOptions.SectionName));

builder.Services.AddOptions<OidcProviderRegistryOptions>()
    .Bind(builder.Configuration.GetSection(OidcProviderRegistryOptions.SectionName));

// Note: single provider options are carried via OidcProviderRegistryOptions.Providers.
builder.Services.AddOptions<OidcProviderOptions>();
builder.Services.AddOptions<PasswordLoginOptions>()
    .Bind(builder.Configuration.GetSection(PasswordLoginOptions.SectionName));

builder.Services.AddSingleton<IJwtKeyProvider, DefaultJwtKeyProvider>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();
builder.Services.AddAuthorization();
builder.Services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>, BirdsoftJwtBearerPostConfigureOptions>();

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
    builder.Services.AddSingleton<IAuthStateService, InMemoryAuthStateService>();
    builder.Services.AddSingleton<IExternalIdentityStore, InMemoryExternalIdentityStore>();
    builder.Services.AddSingleton<ITokenService, InMemoryTokenService>();
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
builder.Services.AddSingleton<IAuthorizationDataStore, InMemoryAuthorizationDataStore>();
builder.Services.AddSingleton<IPasswordAuthenticator, InMemoryPasswordAuthenticator>();

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
app.UseMiddleware<TenantResolutionMiddleware>();

var api = app.MapGroup("/api/v1");
var auth = api.MapGroup("/auth");

static IReadOnlyDictionary<string, string[]> SingleField(string field, string message)
    => new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase) { [field] = [message] };

static string? TryGetBearerToken(HttpContext http)
{
    if (!http.Request.Headers.TryGetValue("Authorization", out var authHeader))
    {
        return null;
    }

    var raw = authHeader.ToString();
    if (raw.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
    {
        return raw[7..].Trim();
    }

    return null;
}

static async Task<IResult> PasswordLogin(
    HttpContext http,
    LoginRequest request,
    IPasswordAuthenticator passwords,
    IAuthorizationDataStore authzData,
    ITokenService tokens,
    CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.Json(
            ApiResponse<object>.Fail("invalid_request", "username/password is required", SingleField("username", "required")),
            statusCode: StatusCodes.Status400BadRequest);
    }

    var tenant = http.GetTenantContext();
    var authn = await passwords.AuthenticateAsync(tenant.TenantId, request.Username, request.Password, ct);
    if (!authn.Succeeded || authn.OurSubject is null)
    {
        var code = authn.ErrorCode ?? "invalid_credentials";
        var status = code == "password_login_disabled"
            ? StatusCodes.Status403Forbidden
            : StatusCodes.Status401Unauthorized;

        return Results.Json(ApiResponse<object>.Fail(code), statusCode: status);
    }

    var roles = await authzData.GetRolesAsync(tenant.TenantId, authn.OurSubject.Value, ct);
    var scopes = await authzData.GetScopesAsync(tenant.TenantId, authn.OurSubject.Value, ct);
    var pair = await tokens.GenerateTokensAsync(tenant.TenantId, authn.OurSubject.Value, roles, scopes, ct);
    return Results.Json(ApiResponse<TokenPair>.Ok(pair));
}

static async Task<IResult> TokenRefresh(RefreshRequest request, ITokenService tokens, CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(request.RefreshToken))
    {
        return Results.Json(
            ApiResponse<object>.Fail("invalid_request", "refreshToken is required", SingleField("refreshToken", "required")),
            statusCode: StatusCodes.Status400BadRequest);
    }

    var result = await tokens.RefreshAsync(request.RefreshToken, ct);
    return result.Succeeded && result.Tokens is not null
        ? Results.Json(ApiResponse<TokenPair>.Ok(result.Tokens))
        : Results.Json(ApiResponse<object>.Fail(result.ErrorCode ?? "invalid_refresh_token"), statusCode: StatusCodes.Status401Unauthorized);
}

static async Task<IResult> TokenRevoke(HttpContext http, TokenRevokeRequest request, ITokenService tokens, CancellationToken ct)
{
    var bearer = TryGetBearerToken(http);
    if (string.IsNullOrWhiteSpace(bearer))
    {
        return Results.Json(ApiResponse<object>.Fail("missing_bearer_token"), statusCode: StatusCodes.Status401Unauthorized);
    }

    var validation = await tokens.ValidateAccessTokenAsync(bearer, ct);
    if (!validation.Succeeded)
    {
        return Results.Json(ApiResponse<object>.Fail(validation.ErrorCode ?? "invalid_token"), statusCode: StatusCodes.Status401Unauthorized);
    }

    if (validation.TenantId is null || validation.OurSubject is null)
    {
        return Results.Json(ApiResponse<object>.Fail("invalid_token"), statusCode: StatusCodes.Status401Unauthorized);
    }

    var tenantId = validation.TenantId.Value;
    var ourSubject = validation.OurSubject.Value;

    if (request.AllDevices)
    {
        var revoked = await tokens.RevokeAllAsync(tenantId, ourSubject, ct);
        return Results.Json(ApiResponse<TokenRevokeResponse>.Ok(new TokenRevokeResponse(revoked)));
    }

    if (string.IsNullOrWhiteSpace(request.RefreshToken))
    {
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
        return Results.Json(ApiResponse<object>.Fail(result.ErrorCode ?? "revoke_failed"), statusCode: status);
    }

    return Results.Json(ApiResponse<TokenRevokeResponse>.Ok(new TokenRevokeResponse(1)));
}

static async Task<IResult> OidcChallenge(
    HttpContext http,
    string provider,
    IAuthStateService authState,
    IOidcProviderRegistry registry,
    IOidcProviderService oidc,
    CancellationToken ct)
{
    var tenant = http.GetTenantContext();
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
    IAuthorizationDataStore authzData,
    ITokenService tokens,
    CancellationToken ct)
{
    if (!string.IsNullOrWhiteSpace(error))
    {
        return Results.Json(ApiResponse<object>.Fail("oidc_error", error), statusCode: StatusCodes.Status400BadRequest);
    }

    if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(state))
    {
        return Results.Json(ApiResponse<object>.Fail("invalid_request", "Missing code/state"), statusCode: StatusCodes.Status400BadRequest);
    }

    var ctx = await authState.ConsumeStateAsync(state, ct);
    if (ctx is null)
    {
        return Results.Json(ApiResponse<object>.Fail("invalid_state"), statusCode: StatusCodes.Status400BadRequest);
    }

    try
    {
        var enabled = await oidc.IsTenantProviderEnabledAsync(ctx.TenantId, provider, ct);
        if (!enabled)
        {
            return Results.Json(ApiResponse<object>.Fail("provider_not_enabled"), statusCode: StatusCodes.Status403Forbidden);
        }
    }
    catch (InvalidOperationException)
    {
        return Results.Json(ApiResponse<object>.Fail("provider_not_enabled"), statusCode: StatusCodes.Status403Forbidden);
    }

    OidcUserInfo userInfo;
    try
    {
        userInfo = await oidc.ExchangeCodeAsync(
            ctx.TenantId,
            provider,
            code,
            ctx,
            cancellationToken: ct);
    }
    catch (InvalidOperationException)
    {
        return Results.Json(ApiResponse<object>.Fail("provider_not_enabled"), statusCode: StatusCodes.Status403Forbidden);
    }

    var key = new Birdsoft.Security.Abstractions.Identity.ExternalIdentityKey(
        ctx.TenantId,
        provider,
        userInfo.Issuer,
        userInfo.ProviderSub);

    var mapping = await externalStore.FindMappingAsync(key, ct);
    var ourSubject = mapping?.OurSubject
        ?? await provisioner.ProvisionAsync(ctx.TenantId, key, userInfo, ct);

    if (mapping is null)
    {
        _ = await externalStore.CreateMappingAsync(
            new Birdsoft.Security.Abstractions.Identity.ExternalIdentityMapping(
                ctx.TenantId,
                ourSubject,
                provider,
                userInfo.Issuer,
                userInfo.ProviderSub,
                DateTimeOffset.UtcNow),
            ct);
    }

    var roles = await authzData.GetRolesAsync(ctx.TenantId, ourSubject, ct);
    var scopes = await authzData.GetScopesAsync(ctx.TenantId, ourSubject, ct);
    var pair = await tokens.GenerateTokensAsync(ctx.TenantId, ourSubject, roles, scopes, ct);
    return Results.Json(ApiResponse<TokenPair>.Ok(pair));
}

auth.MapPost("/password/login", PasswordLogin);

auth.MapGet("/oidc/{provider}/challenge", OidcChallenge);

auth.MapGet("/oidc/{provider}/callback", OidcCallback);

auth.MapPost("/token/refresh", TokenRefresh);

// Legacy alias: prefer POST /api/v1/auth/token/revoke
auth.MapPost("/logout", TokenRevoke);

auth.MapPost("/token/revoke", TokenRevoke);

// Legacy route mappings (temporary compatibility)
var legacyAuth = app.MapGroup("/auth");
legacyAuth.MapPost("/login", PasswordLogin);
legacyAuth.MapPost("/refresh", TokenRefresh);
legacyAuth.MapPost("/logout", TokenRevoke);
legacyAuth.MapPost("/token/revoke", TokenRevoke);
legacyAuth.MapGet("/oidc/{provider}/challenge", OidcChallenge);
legacyAuth.MapGet("/oidc/{provider}/callback", OidcCallback);

app.MapGet("/.well-known/jwks.json", (IJwtKeyProvider keys) => Results.Ok(keys.GetJwksDocument()));

app.Run();
