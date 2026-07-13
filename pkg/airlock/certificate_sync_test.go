package airlock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestSyncSSLCertificateUpdatesPairInOneRequest(t *testing.T) {
	material := CertificateMaterial{
		CertType:          "SERVER_CERT",
		Certificate:       "new-certificate",
		CertificateChain:  []string{"intermediate"},
		PrivateKey:        "new-private-key",
		RootCACertificate: "root-ca",
	}
	var calls []string
	var patchAttributes map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if got := r.Header.Get("Authorization"); got != "Bearer api-key" {
			t.Fatalf("authorization mismatch: %q", got)
		}
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/ssl-certificates/42":
			switch r.Method {
			case http.MethodGet:
				writeCertificateDocument(t, w, "42", CertificateMaterial{
					CertType:    "SERVER_CERT",
					Certificate: "old-certificate",
					PrivateKey:  "old-private-key",
				})
			case http.MethodPatch:
				var document Document[ResourceAny]
				if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
					t.Fatalf("decode update: %v", err)
				}
				patchAttributes = document.Data.Attributes
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("unexpected certificate method: %s", r.Method)
			}
		case "/airlock/rest/configuration/validator-messages":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		case "/airlock/rest/configuration/configurations/activate":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode activation: %v", err)
			}
			options, _ := body["options"].(map[string]any)
			if options["autoMerge"] != true || options["failoverActivation"] != true || options["ignoreOutdatedConfiguration"] != false {
				t.Fatalf("unexpected activation options: %#v", options)
			}
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/session/terminate":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, APIKey: "api-key"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SyncSSLCertificate(context.Background(), "42", material, "rotate certificate")
	if err != nil {
		t.Fatalf("SyncSSLCertificate returned error: %v", err)
	}
	if !result.Changed || result.Created {
		t.Fatalf("unexpected result flags: %#v", result)
	}
	if got, want := result.Checksums.Certificate, testChecksum(material.Certificate); got != want {
		t.Fatalf("certificate checksum mismatch: want %s, got %s", want, got)
	}
	if got, want := result.Checksums.PrivateKey, testChecksum(material.PrivateKey); got != want {
		t.Fatalf("private-key checksum mismatch: want %s, got %s", want, got)
	}
	wantAttributes := normalizedAttributes(t, material.attributes())
	if !reflect.DeepEqual(patchAttributes, wantAttributes) {
		t.Fatalf("combined update mismatch\nwant: %#v\n got: %#v", wantAttributes, patchAttributes)
	}
	wantCalls := []string{
		"POST /airlock/rest/session/create",
		"POST /airlock/rest/configuration/configurations/load-active",
		"GET /airlock/rest/configuration/ssl-certificates/42",
		"PATCH /airlock/rest/configuration/ssl-certificates/42",
		"GET /airlock/rest/configuration/validator-messages",
		"POST /airlock/rest/configuration/configurations/activate",
		"POST /airlock/rest/session/terminate",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("call sequence mismatch\nwant: %#v\n got: %#v", wantCalls, calls)
	}
}

func TestSyncSSLCertificateSkipsEquivalentMaterial(t *testing.T) {
	material := CertificateMaterial{
		CertType:         "SERVER_CERT",
		Certificate:      "same-certificate",
		CertificateChain: []string{"same-chain"},
		PrivateKey:       "same-private-key",
	}
	var writes int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/ssl-certificates/42":
			if r.Method != http.MethodGet {
				writes++
			}
			writeCertificateDocument(t, w, "42", material)
		case "/airlock/rest/configuration/validator-messages", "/airlock/rest/configuration/configurations/activate":
			writes++
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/session/terminate":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, APIKey: "api-key"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SyncSSLCertificate(context.Background(), "42", material, "no change")
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Created {
		t.Fatalf("equivalent material reported a change: %#v", result)
	}
	if writes != 0 {
		t.Fatalf("equivalent material caused %d write/activation calls", writes)
	}
}

func TestSyncSSLCertificateCreatesWithoutResourceID(t *testing.T) {
	material := CertificateMaterial{
		Certificate: "certificate",
		PrivateKey:  "private-key",
	}
	var createdAttributes map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/ssl-certificates":
			switch r.Method {
			case http.MethodPost:
				var document Document[ResourceAny]
				if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
					t.Fatalf("decode create: %v", err)
				}
				createdAttributes = document.Data.Attributes
				w.WriteHeader(http.StatusCreated)
				writeCertificateDocument(t, w, "99", normalizeCertificateMaterial(material))
			default:
				t.Fatalf("unexpected collection method: %s", r.Method)
			}
		case "/airlock/rest/configuration/validator-messages":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		case "/airlock/rest/configuration/configurations/activate":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/session/terminate":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, APIKey: "api-key"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SyncSSLCertificate(context.Background(), "", material, "create certificate")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !result.Created || result.Resource.ID != "99" {
		t.Fatalf("unexpected create result: %#v", result)
	}
	want := normalizedAttributes(t, normalizeCertificateMaterial(material).attributes())
	if !reflect.DeepEqual(createdAttributes, want) {
		t.Fatalf("create attributes mismatch\nwant: %#v\n got: %#v", want, createdAttributes)
	}
}

func TestCertificateChecksumsUseSHA256(t *testing.T) {
	checksums := (CertificateMaterial{Certificate: "certificate", PrivateKey: "key"}).Checksums()
	if !strings.HasPrefix(checksums.Certificate, "sha256:") || len(checksums.Certificate) != len("sha256:")+64 {
		t.Fatalf("unexpected certificate checksum: %q", checksums.Certificate)
	}
	if checksums.Certificate != testChecksum("certificate") || checksums.PrivateKey != testChecksum("key") {
		t.Fatalf("unexpected checksums: %#v", checksums)
	}
}

func writeCertificateDocument(t *testing.T, w http.ResponseWriter, id string, material CertificateMaterial) {
	t.Helper()
	_ = json.NewEncoder(w).Encode(Document[ResourceAny]{
		Data: ResourceAny{
			Type:       SSLCertificateType,
			ID:         id,
			Attributes: material.attributes(),
		},
	})
}

func testChecksum(content string) string {
	digest := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func normalizedAttributes(t *testing.T, attributes map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(attributes)
	if err != nil {
		t.Fatal(err)
	}
	var normalized map[string]any
	if err := json.Unmarshal(data, &normalized); err != nil {
		t.Fatal(err)
	}
	return normalized
}
