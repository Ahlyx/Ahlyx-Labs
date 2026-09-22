package services

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestVirusTotalParsesUndetectedVotesForDomainURLAndHash(t *testing.T) {
	previousClient := httpClient
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(`{
				"data":{"attributes":{"last_analysis_stats":{
					"malicious":1,"harmless":0,"suspicious":0,"undetected":60
				}}}
			}`)),
			Header: make(http.Header),
		}, nil
	})}
	t.Cleanup(func() { httpClient = previousClient })

	domain, domainMeta := FetchVirusTotalDomain("key", "example.test")
	url, urlMeta := FetchVirusTotalURL("key", "https://example.test")
	hash, hashMeta := FetchVirusTotalHash("key", strings.Repeat("a", 64))

	if !domainMeta.Success || domain == nil || domain.UndetectedVotes == nil || *domain.UndetectedVotes != 60 {
		t.Fatalf("domain undetected votes = %+v, metadata=%+v", domain, domainMeta)
	}
	if !urlMeta.Success || url == nil || url.UndetectedVotes == nil || *url.UndetectedVotes != 60 {
		t.Fatalf("URL undetected votes = %+v, metadata=%+v", url, urlMeta)
	}
	if !hashMeta.Success || hash == nil || hash.UndetectedVotes == nil || *hash.UndetectedVotes != 60 {
		t.Fatalf("hash undetected votes = %+v, metadata=%+v", hash, hashMeta)
	}
}
