# Data Access Layer (EF Core)

## Goals

- App/service layers depend on **interfaces only** (no EF Core / provider types)
- Default local development database: **SQLite**
- Future target database: **PostgreSQL** (swap provider, keep interfaces/implementations)

## Projects

- `Security.Abstractions`
  - DAL interfaces: `Birdsoft.Security.Abstractions.Repositories.*`
  - These interfaces are provider-agnostic and safe to keep stable.

- `Security.Data.EfCore`
  - EF Core implementation of DAL interfaces
  - Contains `SecurityDbContext` + entities + repository implementations
  - **Does not** reference any provider package (no SQLite/Npgsql)

- `Security.Authentication`
  - Configures the EF provider (SQLite today)
  - Wires repository-backed services when `ConnectionStrings:SecurityDb` is set

## Configuration

### SQLite (default for now)

Set a connection string:

```json
{
  "ConnectionStrings": {
    "SecurityDb": "Data Source=security.db"
  }
}
```

When running in `Development`, the Authentication host calls `EnsureCreated()` to create tables.

### PostgreSQL (future swap)

1. Add the provider package to the host project (recommended: `Security.Authentication`):
   - `Npgsql.EntityFrameworkCore.PostgreSQL`
2. Change provider wiring in the host:
   - From `UseSqlite(connectionString)`
   - To `UseNpgsql(connectionString)`

No changes are needed in:
- Repository interfaces in `Security.Abstractions`
- EF repositories/entities in `Security.Data.EfCore`

## Notes

- `IAccessTokenDenylistStore` is implemented with EF for now (good for dev). For production scale, Redis/distributed cache is recommended.
- If you want migrations (recommended for production), we can add a migrations project or use a provider-specific tooling approach.
