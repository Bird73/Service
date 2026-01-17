namespace Birdsoft.Security.Authorization.Tests.Integration;

using Birdsoft.Security.Data.EfCore;
using Microsoft.EntityFrameworkCore;

public sealed class SqliteTestDatabase : IDisposable
{
    public SqliteTestDatabase(string? fileName = null)
    {
        FilePath = fileName ?? Path.Combine(Path.GetTempPath(), $"security-authz-{Guid.NewGuid():N}.db");
        ConnectionString = $"Data Source={FilePath}";
    }

    public string FilePath { get; }

    public string ConnectionString { get; }

    public SecurityDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<SecurityDbContext>()
            .UseSqlite(ConnectionString)
            .Options;

        return new SecurityDbContext(options);
    }

    public void Dispose()
    {
        TryDelete(FilePath);
        TryDelete(FilePath + "-shm");
        TryDelete(FilePath + "-wal");
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }
}
