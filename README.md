# Security

This solution contains the Birdsoft Security modules and services.

## Projects

- `Security.Abstractions`: contracts + options + DAL interfaces (`Repositories/*`)
- `Security.Authentication`: Auth API host (`/api/v1/auth/*`)
- `Security.Authorization`: authorization evaluation library
- `Security.Authorization.Api`: Authz API host (`/api/v1/authz/check`)
- `Security.Data.EfCore`: EF Core data access layer (provider-agnostic)

## Data access (SQLite now, PostgreSQL later)

DAL interfaces live in `Security.Abstractions` and are implemented by EF Core in `Security.Data.EfCore`.

To enable SQLite persistence for Authentication, configure `ConnectionStrings:SecurityDb`:

```json
{
	"ConnectionStrings": {
		"SecurityDb": "Data Source=security.db"
	}
}
```

More details: see `docs/DataAccess.md`.
