package shared

import (
	"database/sql"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

// DB is the global database connection pool.
var DB *sql.DB

// InitDB opens a connection to the PostgreSQL database and creates
// the query_logs table if it does not already exist.
func InitDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Println("DATABASE_URL not set — query logging disabled")
		return
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Printf("db: failed to open connection: %v", err)
		return
	}

	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Printf("db: failed to ping: %v", err)
		return
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS query_logs (
			id           BIGSERIAL PRIMARY KEY,
			tool         TEXT NOT NULL,
			query_type   TEXT,
			verdict      TEXT,
			threat       BOOLEAN,
			source_count INTEGER,
			response_ms  INTEGER,
			host_count   INTEGER,
			port_count   INTEGER,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		log.Printf("db: failed to create table: %v", err)
		return
	}

	DB = db
	log.Println("db: connected and ready")
}

// LogQuery inserts a single query log entry. Runs in a goroutine so it
// never blocks the HTTP response. Safe to call when DB is nil.
func LogQuery(tool, queryType, verdict string, threat bool, sourceCount, responseMS, hostCount, portCount int) {
	if DB == nil {
		return
	}
	go func() {
		_, err := DB.Exec(`
			INSERT INTO query_logs
				(tool, query_type, verdict, threat, source_count, response_ms, host_count, port_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`,
			tool,
			nullableString(queryType),
			nullableString(verdict),
			threat,
			nullableInt(sourceCount),
			nullableInt(responseMS),
			nullableInt(hostCount),
			nullableInt(portCount),
		)
		if err != nil {
			log.Printf("db: failed to log query: %v", err)
		}
	}()
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullableInt(i int) interface{} {
	if i == 0 {
		return nil
	}
	return i
}
