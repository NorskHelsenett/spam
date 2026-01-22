# API service

The Go API uses `chi` for routing and `gorm` for PostgreSQL access.

## Configuration

Set either a full DSN or individual PostgreSQL environment variables before starting the service.

```
# Option 1: single connection string
export DATABASE_URL="host=localhost port=5432 user=spam password=spam dbname=spam sslmode=disable"

# Option 2: individual settings
export PGHOST=localhost
export PGPORT=5432
export PGUSER=spam
export PGPASSWORD=spam
export PGDATABASE=spam
export PGSSLMODE=disable
```

`HTTP_PORT` controls the port the server binds to. It defaults to `8080`.

## Run the server

```
cd api
go run ./cmd/server
```

The `GET /healthz` endpoint reports basic readiness information and will surface database connectivity issues.