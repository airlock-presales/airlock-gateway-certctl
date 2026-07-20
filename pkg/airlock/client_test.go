package airlock

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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

func TestNewRequiresAPIKey(t *testing.T) {
	if _, err := New(Config{Address: "gateway.example.com"}); err == nil {
		t.Fatal("New accepted an empty API key")
	}
}

func TestConfigDoesNotJSONSerializeAPIKey(t *testing.T) {
	data, err := json.Marshal(Config{Address: "gateway.example.com", APIKey: "top-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "top-secret") {
		t.Fatalf("configuration leaked API key: %s", data)
	}
}

func TestStructuredConflictError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"errors":[{"code":"OUTDATED_CONFIGURATION"}],"meta":{"rid":"request-1"}}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	err = client.DoJSON(context.Background(), http.MethodPost, "/conflict", nil, nil)
	if !IsConflict(err) {
		t.Fatalf("expected conflict error, got %v", err)
	}
	var apiError *Error
	if !errors.As(err, &apiError) || len(apiError.Errors) != 1 || apiError.Errors[0].Code != "OUTDATED_CONFIGURATION" || apiError.Meta["rid"] != "request-1" {
		t.Fatalf("structured Airlock error was not decoded: %#v", apiError)
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
		if body.Data.Attributes["certType"] != "SERVER_CERT" {
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
	cert, err := client.CreateSSLCertificate(context.Background(), map[string]any{
		"certType": "SERVER_CERT", "certificate": "certificate", "privateKey": "private-key",
	})
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

func TestAddVirtualHostCertificateRelationshipUsesGateway86Path(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Fatalf("method mismatch: %s", r.Method)
		}
		if r.URL.Path != "/airlock/rest/configuration/virtual-hosts/6/relationships/ssl-certificate" {
			t.Fatalf("path mismatch: %s", r.URL.Path)
		}
		var body Document[ResourceIdentifier]
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		want := ResourceIdentifier{Type: SSLCertificateType, ID: "11"}
		if !reflect.DeepEqual(body.Data, want) {
			t.Fatalf("relationship body mismatch\nwant: %#v\n got: %#v", want, body.Data)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if err := client.AddVirtualHostCertificateRelationship(context.Background(), "6", "11"); err != nil {
		t.Fatalf("AddVirtualHostCertificateRelationship returned error: %v", err)
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
