namespace Birdsoft.Security.Abstractions.Services;

using System.Threading;

public sealed class KeyMaterialChangeSignal : IKeyMaterialChangeSignal
{
    private long _version;

    public long Version => Interlocked.Read(ref _version);

    public void NotifyChanged() => Interlocked.Increment(ref _version);
}
