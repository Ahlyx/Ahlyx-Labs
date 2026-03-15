package services

import (
	"net/http"
	"time"
)

// httpClient is reused across all service calls.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// sem limits the total number of concurrent outbound API calls to prevent
// connection pool exhaustion under load (mirrors asyncio.gather semantics
// while adding a bounded concurrency ceiling).
var sem = make(chan struct{}, 20)

func acquireSem() { sem <- struct{}{} }
func releaseSem() { <-sem }

func ptr[T any](v T) *T { return &v }
