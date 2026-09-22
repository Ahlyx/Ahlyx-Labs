package shared

import (
	"net/http"
	"regexp"
)

// OriginKind describes the browser origin's relationship to this deployment.
// It is used only for CORS and optional aggregate telemetry decisions.
type OriginKind int

const (
	OriginOther OriginKind = iota
	OriginProduction
	OriginPreview
)

var ahlyxPreviewOrigin = regexp.MustCompile(`^https://ahlyx-labs-[a-z0-9]+-ahlyx-labs\.vercel\.app$`)

// ClassifyOrigin recognizes the two production sites and Vercel's hashed
// deployment hostnames for this Ahlyx Labs project. It is not an access-control
// mechanism; origin headers are supplied by the client.
func ClassifyOrigin(origin string) OriginKind {
	switch origin {
	case "https://ahlyxlabs.com", "https://www.ahlyxlabs.com":
		return OriginProduction
	}
	if ahlyxPreviewOrigin.MatchString(origin) {
		return OriginPreview
	}
	return OriginOther
}

// IsAllowedBrowserOrigin reports whether CORS should expose API responses to
// the requesting browser origin.
func IsAllowedBrowserOrigin(origin string) bool {
	return ClassifyOrigin(origin) != OriginOther
}

// ShouldLogQueryTelemetry excludes only trusted preview browser requests from
// optional aggregate telemetry. Requests without Origin retain normal logging.
func ShouldLogQueryTelemetry(r *http.Request) bool {
	return ClassifyOrigin(r.Header.Get("Origin")) != OriginPreview
}
