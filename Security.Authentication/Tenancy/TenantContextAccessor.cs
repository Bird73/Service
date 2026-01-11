namespace Birdsoft.Security.Authentication.Tenancy;

using Birdsoft.Security.Abstractions.Tenancy;

public sealed class TenantContextAccessor
{
    private TenantContext? _current;

    public TenantContext? Current
    {
        get => _current;
        internal set => _current = value;
    }
}
