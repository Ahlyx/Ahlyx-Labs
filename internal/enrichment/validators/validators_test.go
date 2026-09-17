package validators

import "testing"

func TestIsValidURLRejectsEmbeddedCredentials(t *testing.T) {
	for _, value := range []string{"https://user:password@example.com", "https://user@example.com"} {
		if IsValidURL(value) {
			t.Errorf("IsValidURL(%q) = true; want false", value)
		}
	}
	if !IsValidURL("https://example.com/path") {
		t.Fatal("ordinary HTTPS URL was rejected")
	}
}
