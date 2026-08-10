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

func TestDefaultUserAgentContainsBuildVersion(t *testing.T) {
	client, err := NewClient("gateway.example.com", "token")
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.newRequest(context.Background(), http.MethodGet, "/system/status/node", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := request.UserAgent(), "airlock-certctl/"+BuildVersion(); got != want {
		t.Fatalf("User-Agent mismatch: want %q, got %q", want, got)
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
	err = client.Raw().DoJSON(context.Background(), http.MethodPost, "/conflict", nil, nil)
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

		var body Document[Resource[SSLCertificateAttributes]]
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body.Data.Type != SSLCertificateType {
			t.Fatalf("resource type mismatch: %q", body.Data.Type)
		}
		if body.Data.Attributes.CertType == nil || *body.Data.Attributes.CertType != ServerCertificate {
			t.Fatalf("attribute mismatch: %#v", body.Data.Attributes)
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(Document[SSLCertificateResource]{
			Data: SSLCertificateResource{Type: SSLCertificateType, ID: 42, Attributes: body.Data.Attributes},
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token")
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	certificate := "certificate"
	privateKey := "private-key"
	certificateType := ServerCertificate
	cert, err := client.CreateSSLCertificate(context.Background(), SSLCertificateAttributes{
		CertType: &certificateType, Certificate: &certificate, PrivateKey: &privateKey,
	})
	if err != nil {
		t.Fatalf("CreateSSLCertificate returned error: %v", err)
	}
	if cert.ID != 42 {
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
	if err := client.AddVirtualHostCertificateRelationship(context.Background(), 6, 11); err != nil {
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

func TestTypedCertificatePatchDistinguishesAbsentFromEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Data struct {
				Attributes map[string]json.RawMessage `json:"attributes"`
			} `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if _, exists := body.Data.Attributes["certificate"]; exists {
			t.Fatal("nil certificate field was serialized in PATCH")
		}
		value, exists := body.Data.Attributes["rootCaCertificate"]
		if !exists || string(value) != `""` {
			t.Fatalf("explicit empty root CA was not serialized: %s", value)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	empty := ""
	if _, err := client.UpdateSSLCertificate(context.Background(), 42, SSLCertificateAttributes{RootCACertificate: &empty}); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteJWKSRelationshipUsesGateway86Path(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/airlock/rest/configuration/ssl-certificates/42/relationships/json-web-key-sets/remotes"
		if r.URL.Path != want {
			t.Fatalf("relationship path mismatch: want %s, got %s", want, r.URL.Path)
		}
		var body Document[[]ResourceIdentifier]
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		wantIdentifier := ResourceIdentifier{Type: RemoteJWKSType, ID: "7"}
		if !reflect.DeepEqual(body.Data, []ResourceIdentifier{wantIdentifier}) {
			t.Fatalf("relationship body mismatch: %#v", body.Data)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ConnectSSLCertificateToRemoteJWKS(context.Background(), 42, 7); err != nil {
		t.Fatal(err)
	}
}

func TestTypedRelationshipRejectsEveryInvalidTarget(t *testing.T) {
	client, err := NewClient("gateway.example.com", "token")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ConnectSSLCertificateToRemoteJWKS(context.Background(), 42, 7, 0); err == nil {
		t.Fatal("mixed valid and invalid typed relationship IDs were accepted")
	}
	if err := client.ConnectSSLCertificateRelationship(context.Background(), 42, CertificateNodes, []ResourceIdentifier{{Type: NodeType, ID: "not-numeric"}}); err == nil {
		t.Fatal("invalid generic relationship ID was accepted")
	}
}

func TestTypedCertificateResponseRejectsInvalidIdentity(t *testing.T) {
	for name, response := range map[string]string{
		"wrong type":           `{"data":{"type":"virtual-host","id":"42"}}`,
		"invalid id":           `{"data":{"type":"ssl-certificate","id":"not-numeric"}}`,
		"unknown attribute":    `{"data":{"type":"ssl-certificate","id":"42","attributes":{"futureField":true}}}`,
		"unknown relationship": `{"data":{"type":"ssl-certificate","id":"42","relationships":{"future-resources":{"data":[]}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(response))
			}))
			defer server.Close()
			client, err := NewClient(server.URL, "token")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.GetSSLCertificate(context.Background(), 42); err == nil {
				t.Fatal("invalid typed response was accepted")
			}
		})
	}
}

func TestErrorStringDoesNotExposeRawResponseBody(t *testing.T) {
	err := newResponseError(http.StatusBadRequest, []byte(`{"errors":[{"code":"INVALID_VALUE","title":"top-secret"}],"privateKey":"top-secret"}`))
	if strings.Contains(err.Error(), "top-secret") {
		t.Fatalf("Error leaked server-provided secret data: %s", err)
	}
	if !strings.Contains(err.Error(), "INVALID_VALUE") {
		t.Fatalf("Error omitted safe diagnostic code: %s", err)
	}
}

func TestVerifyGatewayVersion(t *testing.T) {
	for version, wantError := range map[string]bool{
		"8": false, "8.0.0": false, "8.6.0": false, "8.99.4": false,
		"7.6.4": true, "9.0.0": true, "invalid": true,
	} {
		t.Run(version, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{"type": "node-status", "attributes": map[string]any{"version": version}},
				})
			}))
			defer server.Close()
			client, err := NewClient(server.URL, "token")
			if err != nil {
				t.Fatal(err)
			}
			err = client.VerifyGatewayVersion(context.Background())
			if (err != nil) != wantError {
				t.Fatalf("VerifyGatewayVersion(%s) error = %v, wantError %t", version, err, wantError)
			}
			if wantError {
				if !errors.Is(err, ErrUnsupportedGatewayVersion) {
					t.Fatalf("expected ErrUnsupportedGatewayVersion, got %v", err)
				}
				var versionError *GatewayVersionError
				if !errors.As(err, &versionError) {
					t.Fatalf("expected GatewayVersionError, got %T", err)
				}
			}
		})
	}
}
