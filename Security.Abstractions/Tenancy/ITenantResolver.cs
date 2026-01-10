namespace Birdsoft.Security.Abstractions.Tenancy;

public interface ITenantResolver
{
    /// <summary>
    /// 嘗試由 host/header/path/token claim 解析 tenant。
    /// </summary>
    bool TryResolve(TenantResolveInput input, out TenantContext tenant);
}
