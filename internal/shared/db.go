package shared

import (
	"context"
	"database/sql"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/lib/pq"
)

// DB is the global database connection pool.
var DB *sql.DB

const (
	queryLogQueueSize = 128
	queryLogWorkers   = 2
	queryLogTimeout   = 2 * time.Second
)

type queryLogEntry struct {
	tool, queryType, verdict                      string
	threat                                        bool
	sourceCount, responseMS, hostCount, portCount int
}

var (
	queryLogQueue   chan queryLogEntry
	queryLogStart   sync.Once
	queryLogDropped atomic.Uint64
)

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
	startQueryLogWorkers()
	log.Println("db: connected and ready")
}

func startQueryLogWorkers() {
	queryLogStart.Do(func() {
		queryLogQueue = make(chan queryLogEntry, queryLogQueueSize)
		for range queryLogWorkers {
			go func() {
				for entry := range queryLogQueue {
					writeQueryLog(entry)
				}
			}()
		}
	})
}

func writeQueryLog(entry queryLogEntry) {
	if DB == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), queryLogTimeout)
	defer cancel()
	_, err := DB.ExecContext(ctx, `
		INSERT INTO query_logs
			(tool, query_type, verdict, threat, source_count, response_ms, host_count, port_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`,
		nullableString(entry.tool),
		nullableString(entry.queryType),
		nullableString(entry.verdict),
		entry.threat,
		nullableInt(entry.sourceCount),
		nullableInt(entry.responseMS),
		nullableInt(entry.hostCount),
		nullableInt(entry.portCount),
	)
	if err != nil {
		log.Printf("db: failed to log aggregate query telemetry: %v", err)
	}
}

// LogQuery queues aggregate telemetry without ever retaining the submitted
// indicator. A full queue drops telemetry instead of creating unbounded work.
func LogQuery(tool, queryType, verdict string, threat bool, sourceCount, responseMS, hostCount, portCount int) {
	if DB == nil || queryLogQueue == nil {
		return
	}
	entry := queryLogEntry{tool, queryType, verdict, threat, sourceCount, responseMS, hostCount, portCount}
	select {
	case queryLogQueue <- entry:
	default:
		if dropped := queryLogDropped.Add(1); dropped == 1 || dropped%100 == 0 {
			log.Printf("db: dropped %d aggregate query telemetry events because the queue is full", dropped)
		}
	}
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
