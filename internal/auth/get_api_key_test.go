package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// no auth header
	gotKey, gotErr := GetAPIKey(http.Header{})

	if gotKey != "" || !errors.Is(gotErr, ErrNoAuthHeaderIncluded) {
		t.Errorf("GetAPIKey() = %q, %v", gotKey, gotErr)
	}

	// malformed auth header
	gotKey, gotErr = GetAPIKey(http.Header{"Authorization": {"Bearer secret"}})
	if gotKey != "" || gotErr == nil {
		t.Errorf("GetAPIKey() = %q, %v; want malformed-header error", gotKey, gotErr)
	}

	// valid API key
	gotKey, gotErr = GetAPIKey(http.Header{"Authorization": {"ApiKey secret"}})
	if gotKey != "secret" || gotErr != nil {
		t.Errorf("GetAPIKey() = %q, %v; want %q, nil", gotKey, gotErr, "secret")
	}
}
