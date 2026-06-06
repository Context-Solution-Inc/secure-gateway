package postgres_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lley154/secure-gateway/internal/authstore"
	"github.com/lley154/secure-gateway/internal/authstore/postgres"
	"github.com/lley154/secure-gateway/internal/authstore/storetest"
)

// TestPostgresStoreConformance runs the shared store conformance suite against a
// real Postgres. It is opt-in: set AUTH_TEST_DB_DSN to a disposable database
// (e.g. postgres://user:pass@localhost:5432/auth_test?sslmode=disable). When the
// env var is unset the test is skipped so CI stays green without a database.
func TestPostgresStoreConformance(t *testing.T) {
	dsn := os.Getenv("AUTH_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("AUTH_TEST_DB_DSN not set; skipping Postgres conformance test")
	}
	ctx := context.Background()
	storetest.Run(t, func(t *testing.T) authstore.Store {
		// Each sub-test gets a clean schema: connect, drop, migrate.
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		t.Cleanup(pool.Close)
		dropAll(t, ctx, pool)
		s := postgres.NewWithPool(pool)
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		return s
	})
}

func dropAll(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	const q = `DROP TABLE IF EXISTS webhook_events, refresh_tokens, pairings, devices, licenses, subscriptions, accounts CASCADE`
	if _, err := pool.Exec(ctx, q); err != nil {
		t.Fatalf("drop tables: %v", err)
	}
}
