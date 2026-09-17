package handlers

import "net/http"

// CapabilitiesHandler exposes non-secret UI capability flags. It never
// exposes provider credentials or configuration values beyond a feature's
// enabled/disabled state.
func CapabilitiesHandler(urlScanActiveSubmission bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]bool{
			"urlscan_active_submission": urlScanActiveSubmission,
		})
	}
}
