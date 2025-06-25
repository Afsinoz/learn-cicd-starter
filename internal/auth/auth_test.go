package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  http.Header
		wantKey string
		wantErr error // nil means we expect success
	}{
		{
			name:    "no Authorization header",
			header:  http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "wrong auth scheme",
			header: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer abc123")
				return h
			}(),
			wantErr: ErrMalformedAuthHeader,
		},
		{
			name: "missing key after scheme",
			header: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey")
				return h
			}(),
			wantErr: ErrMalformedAuthHeader,
		},
		{
			name: "valid header",
			header: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey my-secret-key")
				return h
			}(),
			wantKey: "my-secret-key",
		},
	}

	for _, tc := range tests {
		tc := tc // capture range var
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotKey, gotErr := GetAPIKey(tc.header)

			// Compare errors first.
			if !errors.Is(gotErr, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, gotErr)
			}

			// Only verify key when we expect success.
			if tc.wantErr == nil && gotKey != tc.wantKey {
				t.Fatalf("expected key %q, got %q", tc.wantKey, gotKey)
			}
		})
	}
}
