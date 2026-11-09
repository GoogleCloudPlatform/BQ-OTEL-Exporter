// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package googlehttp

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cloud.google.com/go/auth/credentials"
	"google.golang.org/api/option"
)

func TestHasAuthOption(t *testing.T) {
	cases := []struct {
		name     string
		opts     []option.ClientOption
		expected bool
	}{
		{
			name:     "empty options",
			opts:     nil,
			expected: false,
		},
		{
			name:     "non-auth option endpoint",
			opts:     []option.ClientOption{option.WithEndpoint("https://example.com")},
			expected: false,
		},
		{
			name:     "without authentication",
			opts:     []option.ClientOption{option.WithoutAuthentication()},
			expected: true,
		},
		{
			name:     "with api key",
			opts:     []option.ClientOption{option.WithAPIKey("fake-key")},
			expected: true,
		},
		{
			name:     "with auth credentials file",
			opts:     []option.ClientOption{option.WithAuthCredentialsFile(option.ServiceAccount, "/nonexistent/sa.json")},
			expected: true,
		},
		{
			name: "mixed options containing auth",
			opts: []option.ClientOption{
				option.WithEndpoint("https://example.com"),
				option.WithoutAuthentication(),
			},
			expected: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasAuthOption(tc.opts)
			if got != tc.expected {
				t.Fatalf("hasAuthOption(%v) = %v; want %v", tc.opts, got, tc.expected)
			}
		})
	}
}

func TestNewClientWithoutAuthentication(t *testing.T) {
	ctx := context.Background()
	client, endpoint, cleanup, err := NewClient(ctx, nil, option.WithoutAuthentication(), option.WithEndpoint("https://bigquery.googleapis.com/"))
	if err != nil {
		t.Fatalf("NewClient with WithoutAuthentication failed: %v", err)
	}
	defer cleanup()

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if endpoint == "" {
		t.Fatal("expected non-empty endpoint")
	}
}

func TestNewClientWithHTTPClient(t *testing.T) {
	ctx := context.Background()
	customClient := &http.Client{}
	client, _, cleanup, err := NewClient(ctx, nil, option.WithHTTPClient(customClient))
	if err != nil {
		t.Fatalf("NewClient with WithHTTPClient failed: %v", err)
	}
	defer cleanup()

	if client != customClient {
		t.Fatalf("expected client to match customClient; got %v, want %v", client, customClient)
	}
}

func TestLazyCredentialsEmptySliceAndMissingHome(t *testing.T) {
	t.Run("explicit empty slice does not fall back to ADC", func(t *testing.T) {
		creds, cleanup, err := Credentials(credentials.DetectOptions{
			Scopes: []string{"https://www.googleapis.com/auth/bigquery"},
		}, []byte{})
		if err != nil {
			t.Fatalf("Credentials() unexpected init error: %v", err)
		}
		defer cleanup()
		if _, err := creds.ProjectID(context.Background()); err == nil {
			t.Fatal("ProjectID() with explicit empty JSON slice succeeded; want parse error without ADC fallback")
		}
	})

	t.Run("empty HOME never reads CWD .config/gcloud", func(t *testing.T) {
		tmp := t.TempDir()
		adcDir := filepath.Join(tmp, ".config", "gcloud")
		if err := os.MkdirAll(adcDir, 0o700); err != nil {
			t.Fatal(err)
		}
		poison := `{"type":"authorized_user","client_id":"id","client_secret":"secret","refresh_token":"tok","quota_project_id":"poison-cwd-project"}`
		if err := os.WriteFile(filepath.Join(adcDir, "application_default_credentials.json"), []byte(poison), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Chdir(tmp)
		t.Setenv("HOME", "")
		t.Setenv("APPDATA", "")
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")

		creds, cleanup, err := Credentials(credentials.DetectOptions{
			Scopes: []string{"https://www.googleapis.com/auth/bigquery"},
		}, nil)
		if err != nil {
			t.Fatalf("Credentials() unexpected init error: %v", err)
		}
		defer cleanup()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		pid, _ := creds.QuotaProjectID(ctx)
		if pid == "poison-cwd-project" {
			t.Fatal("Credentials() read relative CWD .config/gcloud/application_default_credentials.json when HOME was empty")
		}
	})
}
