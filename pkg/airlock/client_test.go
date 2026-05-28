package airlock

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestNewClientBuildsAirlockRestBasePath(t *testing.T) {
	client, err := NewClient("gateway.example.com", "token")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	got := client.endpoint("/session/create")
	want := "https://gateway.example.com/airlock/rest/session/create"
	if got != want {
		t.Fatalf("endpoint mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestCreateSSLCertificateRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method mismatch: %s", r.Method)
		}
		if r.URL.Path != "/airlock/rest/configuration/ssl-certificates" {
			t.Fatalf("path mismatch: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("authorization header mismatch: %q", got)
		}

		var body Document[ResourceAny]
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body.Data.Type != SSLCertificateType {
			t.Fatalf("resource type mismatch: %q", body.Data.Type)
		}
		if body.Data.Attributes["name"] != "test-cert" {
			t.Fatalf("attribute mismatch: %#v", body.Data.Attributes)
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(Document[ResourceAny]{
			Data: ResourceAny{Type: SSLCertificateType, ID: "42", Attributes: body.Data.Attributes},
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	cert, err := client.CreateSSLCertificate(context.Background(), map[string]any{"name": "test-cert"})
	if err != nil {
		t.Fatalf("CreateSSLCertificate returned error: %v", err)
	}
	if cert.ID != "42" {
		t.Fatalf("created certificate ID mismatch: %q", cert.ID)
	}
}

func TestCreateSessionAndLoadActiveConfiguration(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if err := client.CreateSessionAndLoadActiveConfiguration(context.Background()); err != nil {
		t.Fatalf("CreateSessionAndLoadActiveConfiguration returned error: %v", err)
	}

	want := []string{
		"POST /airlock/rest/session/create",
		"POST /airlock/rest/configuration/configurations/load-active",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("call sequence mismatch\nwant: %#v\n got: %#v", want, calls)
	}
}

func TestEndpointPreservesQueryString(t *testing.T) {
	client, err := NewClient("gateway.example.com", "token")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	got := client.endpoint("/configuration/validator-messages?filter=meta.severity%3D%3DERROR")
	want := "https://gateway.example.com/airlock/rest/configuration/validator-messages?filter=meta.severity%3D%3DERROR"
	if got != want {
		t.Fatalf("endpoint mismatch\nwant: %s\n got: %s", want, got)
	}
}
