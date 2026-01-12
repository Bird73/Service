namespace Birdsoft.Security.Authentication.Tests.Unit;

using Birdsoft.Security.Abstractions.Constants;
using Birdsoft.Security.Abstractions.Tenancy;
using Birdsoft.Security.Authentication.Tenancy;

public sealed class TenantResolutionTests
{
    [Fact]
    public void Resolve_Prefers_TenantId_From_Jwt_Claim_Over_Header()
    {
        var resolver = new HeaderOrClaimTenantResolver();
        var headerTenant = Guid.NewGuid();
        var claimTenant = Guid.NewGuid();

        var input = new TenantResolveInput(
            Host: null,
            Path: null,
            Headers: new Dictionary<string, string?> { [HeaderOrClaimTenantResolver.TenantHeaderName] = headerTenant.ToString() },
            Claims: new Dictionary<string, string?> { [SecurityClaimTypes.TenantId] = claimTenant.ToString() });

        var ok = resolver.TryResolve(input, out var ctx);
        Assert.True(ok);
        Assert.Equal(claimTenant, ctx.TenantId);
        Assert.Equal(TenantResolutionSource.TokenClaim, ctx.Source);
    }

    [Fact]
    public void Resolve_Falls_Back_To_Header_When_No_Claim_Present()
    {
        var resolver = new HeaderOrClaimTenantResolver();
        var headerTenant = Guid.NewGuid();

        var input = new TenantResolveInput(
            Host: null,
            Path: null,
            Headers: new Dictionary<string, string?> { [HeaderOrClaimTenantResolver.TenantHeaderName] = headerTenant.ToString() },
            Claims: new Dictionary<string, string?>());

        var ok = resolver.TryResolve(input, out var ctx);
        Assert.True(ok);
        Assert.Equal(headerTenant, ctx.TenantId);
        Assert.Equal(TenantResolutionSource.Header, ctx.Source);
    }

    [Fact]
    public void Resolve_Fails_When_Neither_Claim_Nor_Header_Is_A_Valid_Guid()
    {
        var resolver = new HeaderOrClaimTenantResolver();

        var input = new TenantResolveInput(
            Host: null,
            Path: null,
            Headers: new Dictionary<string, string?> { [HeaderOrClaimTenantResolver.TenantHeaderName] = "not-a-guid" },
            Claims: new Dictionary<string, string?> { [SecurityClaimTypes.TenantId] = "also-not-a-guid" });

        var ok = resolver.TryResolve(input, out var ctx);
        Assert.False(ok);
        Assert.Equal(Guid.Empty, ctx.TenantId);
        Assert.Equal(TenantResolutionSource.Unknown, ctx.Source);
    }
}
