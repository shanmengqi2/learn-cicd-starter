package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErrMsg string
		wantErr    error
	}{
		{
			name: "returns api key from valid authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey super-secret-key"},
			},
			wantKey: "super-secret-key",
		},
		{
			name:       "returns sentinel error when authorization header is missing",
			headers:    http.Header{},
			wantErr:    ErrNoAuthHeaderIncluded,
			wantErrMsg: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "returns malformed header error when scheme is invalid",
			headers: http.Header{
				"Authorization": []string{"Bearer super-secret-key"},
			},
			wantErrMsg: "malformed authorization header",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotKey, err := GetAPIKey(tc.headers)

			if gotKey != tc.wantKey {
				t.Fatalf("expected key %q, got %q", tc.wantKey, gotKey)
			}

			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}

			if tc.wantErrMsg == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error %q, got nil", tc.wantErrMsg)
			}

			if err.Error() != tc.wantErrMsg {
				t.Fatalf("expected error %q, got %q", tc.wantErrMsg, err.Error())
			}
		})
	}
}
