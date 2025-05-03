package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey mysecretkey"},
			},
			expectedKey:   "mysecretkey",
			expectedError: nil,
		},
		{
			name:          "No Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"mysecretkey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed header - missing space",
			headers: http.Header{
				"Authorization": []string{"ApiKeymysecretkey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed header - wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer mysecretkey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Empty Authorization header value",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Authorization header with only prefix",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey:   "",  // The key is technically empty
			expectedError: nil, // This case might need clarification on expected behavior, assuming empty key is valid for now
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			// Compare error messages if both are non-nil
			if (err != nil && tt.expectedError == nil) || (err == nil && tt.expectedError != nil) || (err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}
