namespace Birdsoft.Security.Abstractions.Services;

/// <summary>
/// Simple in-memory signal used to invalidate cached key material.
/// </summary>
public interface IKeyMaterialChangeSignal
{
    long Version { get; }

    void NotifyChanged();
}
