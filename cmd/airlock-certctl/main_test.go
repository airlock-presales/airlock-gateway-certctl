package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestListLoadsActiveConfigurationBeforeListingCertificates(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			if r.Method != http.MethodPost {
				t.Fatalf("session create method mismatch: %s", r.Method)
			}
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			if r.Method != http.MethodPost {
				t.Fatalf("load-active method mismatch: %s", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/ssl-certificates":
			if r.Method != http.MethodGet {
				t.Fatalf("list method mismatch: %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		case "/airlock/rest/session/terminate":
			if r.Method != http.MethodPost {
				t.Fatalf("session terminate method mismatch: %s", r.Method)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	err := run([]string{"--host", server.URL, "--api-key", "token", "list"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v\nstderr: %s", err, stderr.String())
	}

	want := []string{
		"POST /airlock/rest/session/create",
		"POST /airlock/rest/configuration/configurations/load-active",
		"GET /airlock/rest/configuration/ssl-certificates",
		"POST /airlock/rest/session/terminate",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("call sequence mismatch\nwant: %#v\n got: %#v", want, calls)
	}
}

func TestListRedactsSensitiveValuesByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/ssl-certificates":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []any{
					map[string]any{
						"type": "ssl-certificate",
						"id":   "17",
						"attributes": map[string]any{
							"certificate": "public-certificate-pem",
							"privateKey":  "super-secret-private-key",
							"password":    "super-secret-password",
						},
					},
				},
			})
		case "/airlock/rest/session/terminate":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	err := run([]string{"--host", server.URL, "--api-key", "token", "list"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v\nstderr: %s", err, stderr.String())
	}

	out := stdout.String()
	for _, secret := range []string{"super-secret-private-key", "super-secret-password"} {
		if strings.Contains(out, secret) {
			t.Fatalf("sensitive value %q was not redacted from output: %s", secret, out)
		}
	}
	if !strings.Contains(out, "<redacted>") {
		t.Fatalf("expected redacted marker in output: %s", out)
	}
	if !strings.Contains(out, "public-certificate-pem") {
		t.Fatalf("expected non-sensitive certificate value to remain visible: %s", out)
	}
}

func TestListShowSecretsPrintsSensitiveValues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/ssl-certificates":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []any{
					map[string]any{
						"type": "ssl-certificate",
						"id":   "17",
						"attributes": map[string]any{
							"privateKey": "super-secret-private-key",
						},
					},
				},
			})
		case "/airlock/rest/session/terminate":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	err := run([]string{"--host", server.URL, "--api-key", "token", "--show-secrets", "list"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v\nstderr: %s", err, stderr.String())
	}

	if !strings.Contains(stdout.String(), "super-secret-private-key") {
		t.Fatalf("expected --show-secrets output to include private key: %s", stdout.String())
	}
}

func TestFindDomainFindsCertificateAndRelationships(t *testing.T) {
	certPEM := testCertificatePEM(t, []string{"www.example.com", "api.example.com"})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/ssl-certificates":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []any{
					map[string]any{
						"type": "ssl-certificate",
						"id":   "17",
						"attributes": map[string]any{
							"certType":    "SERVER_CERT",
							"certificate": certPEM,
						},
						"relationships": map[string]any{
							"virtual-hosts": map[string]any{
								"data": []any{map[string]any{"type": "virtual-host", "id": "13"}},
							},
						},
					},
				},
			})
		case "/airlock/rest/session/terminate":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	err := run([]string{"--host", server.URL, "--api-key", "token", "find-domain", "--domain", "www.example.com"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v\nstderr: %s", err, stderr.String())
	}

	var matches []domainCertificateMatch
	if err := json.Unmarshal(stdout.Bytes(), &matches); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if len(matches) != 1 || matches[0].ID != "17" {
		t.Fatalf("unexpected matches: %#v", matches)
	}
	if len(matches[0].DNSNames) != 2 || matches[0].DNSNames[0] != "www.example.com" {
		t.Fatalf("unexpected DNS names: %#v", matches[0].DNSNames)
	}
	if _, ok := matches[0].Relationships["virtual-hosts"]; !ok {
		t.Fatalf("expected virtual-hosts relationship: %#v", matches[0].Relationships)
	}
}

func TestAttrsFromPEMSplitsFullChainAndDoesNotRequireGateway(t *testing.T) {
	dir := t.TempDir()
	leaf := testCertificatePEM(t, []string{"www.example.com"})
	intermediate := testCertificatePEM(t, []string{"intermediate.example.com"})
	rootCA := testCertificatePEM(t, []string{"root-ca.example.com"})
	fullchain := filepath.Join(dir, "fullchain.pem")
	rootCAFile := filepath.Join(dir, "root-ca.pem")
	key := filepath.Join(dir, "privkey.pem")
	out := filepath.Join(dir, "attrs.json")

	if err := os.WriteFile(fullchain, []byte(leaf+intermediate), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootCAFile, []byte(rootCA), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := run([]string{"attrs-from-pem", "--cert", fullchain, "--key", key, "--root-ca", rootCAFile, "--out", out}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v\nstderr: %s", err, stderr.String())
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var attrs map[string]any
	if err := json.Unmarshal(data, &attrs); err != nil {
		t.Fatalf("decode attrs: %v", err)
	}
	if attrs["certType"] != "SERVER_CERT" {
		t.Fatalf("unexpected certType: %#v", attrs["certType"])
	}
	if !strings.Contains(attrs["certificate"].(string), "BEGIN CERTIFICATE") {
		t.Fatalf("certificate missing from attrs: %#v", attrs["certificate"])
	}
	chain, ok := attrs["certificateChain"].([]any)
	if !ok || len(chain) != 1 {
		t.Fatalf("expected one chain certificate, got %#v", attrs["certificateChain"])
	}
	if attrs["privateKey"] != "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n" {
		t.Fatalf("private key was not normalized as expected: %#v", attrs["privateKey"])
	}
	if attrs["rootCaCertificate"] != rootCA {
		t.Fatalf("root CA was not normalized as expected: %#v", attrs["rootCaCertificate"])
	}
}

func TestReplaceWithNewMovesRelationshipsDeletesOldAndActivates(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/ssl-certificates/old":
			switch r.Method {
			case http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{
						"type": "ssl-certificate",
						"id":   "old",
						"relationships": map[string]any{
							"virtual-hosts": map[string]any{
								"data": []any{map[string]any{"type": "virtual-host", "id": "13"}},
							},
						},
					},
				})
			case http.MethodDelete:
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("old cert expected GET or DELETE, got %s", r.Method)
			}
		case "/airlock/rest/configuration/ssl-certificates":
			if r.Method != http.MethodPost {
				t.Fatalf("create cert expected POST, got %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"type": "ssl-certificate",
					"id":   "new",
					"attributes": map[string]any{
						"privateKey": "new-secret",
					},
				},
			})
		case "/airlock/rest/configuration/ssl-certificates/new/relationships/virtual-hosts":
			if r.Method != http.MethodPatch {
				t.Fatalf("new relationship expected PATCH, got %s", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/ssl-certificates/old/relationships/virtual-hosts":
			if r.Method != http.MethodDelete {
				t.Fatalf("old relationship expected DELETE, got %s", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/validator-messages":
			if r.Method != http.MethodGet {
				t.Fatalf("validator expected GET, got %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		case "/airlock/rest/configuration/configurations/activate":
			if r.Method != http.MethodPost {
				t.Fatalf("activate expected POST, got %s", r.Method)
			}
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/session/terminate":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	attrsFile := filepath.Join(dir, "attrs.json")
	if err := os.WriteFile(attrsFile, []byte(`{"certificate":"public","privateKey":"new-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := run([]string{"--host", server.URL, "--api-key", "token", "replace-with-new", "--old-cert-id", "old", "--attrs", attrsFile, "--activate", "--activate-comment", "replace test cert"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run returned error: %v\nstderr: %s", err, stderr.String())
	}

	if strings.Contains(stdout.String(), "new-secret") {
		t.Fatalf("replace output leaked private key: %s", stdout.String())
	}
	want := []string{
		"POST /airlock/rest/session/create",
		"POST /airlock/rest/configuration/configurations/load-active",
		"GET /airlock/rest/configuration/ssl-certificates/old",
		"POST /airlock/rest/configuration/ssl-certificates",
		"PATCH /airlock/rest/configuration/ssl-certificates/new/relationships/virtual-hosts",
		"DELETE /airlock/rest/configuration/ssl-certificates/old/relationships/virtual-hosts",
		"DELETE /airlock/rest/configuration/ssl-certificates/old",
		"GET /airlock/rest/configuration/validator-messages",
		"POST /airlock/rest/configuration/configurations/activate",
		"POST /airlock/rest/session/terminate",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("call sequence mismatch\nwant: %#v\n got: %#v", want, calls)
	}
}

func testCertificatePEM(t *testing.T, dnsNames []string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Now().Add(-time.Hour)
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: dnsNames[0],
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(24 * time.Hour),
		DNSNames:  dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
