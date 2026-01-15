namespace Birdsoft.Security.Authorization.Api.Persistence;

using System;
using Birdsoft.Security.Data.EfCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

public sealed class SecurityDbContextDesignTimeFactory : IDesignTimeDbContextFactory<SecurityDbContext>
{
    public SecurityDbContext CreateDbContext(string[] args)
    {
        var connectionString =
            Environment.GetEnvironmentVariable("SECURITY_DB_CONNECTION")
            ?? "Data Source=authz_design_time.db";

        var options = new DbContextOptionsBuilder<SecurityDbContext>()
            .UseSqlite(connectionString)
            .Options;

        return new SecurityDbContext(options);
    }
}
