package airlock

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/youmark/pkcs8"
)

func TestParseCertificateBundleRejectsMismatchedKey(t *testing.T) {
	certificatePEM, _ := newTestPEMPair(t, "one.example")
	_, otherKeyPEM := newTestPEMPair(t, "two.example")
	_, err := ParseCertificateBundle(CertificateBundleInput{
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  otherKeyPEM,
	})
	if err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("expected local mismatch error, got %v", err)
	}
}

func TestParseCertificateBundleCanonicalChecksums(t *testing.T) {
	certificatePEM, keyPEM := newTestPEMPair(t, "checksum.example")
	first, err := ParseCertificateBundle(CertificateBundleInput{CertificatePEM: certificatePEM, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	certificateWithWhitespace := append(append([]byte("\n\t"), certificatePEM...), []byte("\r\n")...)
	second, err := ParseCertificateBundle(CertificateBundleInput{CertificatePEM: certificateWithWhitespace, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	if first.Certificate.Checksum != second.Certificate.Checksum || first.Checksum != second.Checksum {
		t.Fatalf("semantically equal PEM had different checksums: %q / %q", first.Checksum, second.Checksum)
	}
	if first.Certificate.Checksum == "" || first.Key.Checksum == "" || first.Checksum == "" {
		t.Fatal("expected certificate, key, and bundle checksums")
	}
}

func TestTypedValuesDoNotJSONSerializeSecrets(t *testing.T) {
	certificatePEM, keyPEM := newTestPEMPair(t, "secret.example")
	bundle, err := ParseCertificateBundle(CertificateBundleInput{
		CertificatePEM: certificatePEM, PrivateKeyPEM: keyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(struct {
		Bundle CertificateBundle
		Input  CertificateBundleInput
		Sync   SyncOptions
		Read   ReadOptions
	}{
		Bundle: bundle,
		Input:  CertificateBundleInput{PrivateKeyPEM: keyPEM, PrivateKeyPassphrase: []byte("input-secret")},
		Sync:   SyncOptions{ExistingKeyPassphrase: []byte("sync-secret")},
		Read:   ReadOptions{PrivateKeyPassphrase: []byte("read-secret")},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PRIVATE KEY", "input-secret", "sync-secret", "read-secret"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("JSON output leaked %q: %s", secret, data)
		}
	}
}

func TestParseEncryptedPKCS8Key(t *testing.T) {
	certificatePEM, keyPEM := newTestPEMPair(t, "encrypted.example")
	block, _ := pem.Decode(keyPEM)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	encryptedDER, err := pkcs8.MarshalPrivateKey(privateKey, []byte("correct horse"), pkcs8.DefaultOpts)
	if err != nil {
		t.Fatal(err)
	}
	encryptedPEM := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedDER})
	bundle, err := ParseCertificateBundle(CertificateBundleInput{
		CertificatePEM:       certificatePEM,
		PrivateKeyPEM:        encryptedPEM,
		PrivateKeyPassphrase: []byte("correct horse"),
	})
	if err != nil {
		t.Fatalf("parse encrypted key: %v", err)
	}
	if bundle.Key.Checksum == "" {
		t.Fatal("encrypted key has no checksum")
	}
	if _, err := ParseEncryptedKey(encryptedPEM, []byte("wrong")); err == nil {
		t.Fatal("wrong passphrase was accepted")
	}
	if _, err := ParseEncryptedKey(encryptedPEM, []byte{0xff}); err == nil {
		t.Fatal("non-UTF-8 passphrase was accepted")
	}
}

func TestSyncCertificateForVirtualHostCreatesAndBindsAtomically(t *testing.T) {
	bundle := newTestBundle(t, "test.airlock.local")
	defaultBundle := newTestBundle(t, "default.airlock.local")
	var calls []string
	var created sslCertificateAttributes
	var activation activationRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "typed-test", Path: "/"})
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/virtual-hosts":
			if got := r.URL.Query().Get("filter"); got != "name==test" {
				t.Fatalf("unexpected virtual-host filter %q", got)
			}
			_ = json.NewEncoder(w).Encode(Document[[]Resource[virtualHostAttributes]]{Data: []Resource[virtualHostAttributes]{
				{
					Type:       VirtualHostType,
					ID:         "6",
					Attributes: virtualHostAttributes{Name: "test", HostName: "test.airlock.local"},
					Relationships: map[string]Relationship{
						"ssl-certificate": {Data: ResourceIdentifier{Type: SSLCertificateType, ID: "-1000"}},
					},
				},
			}})
		case "/airlock/rest/configuration/ssl-certificates/-1000":
			_ = json.NewEncoder(w).Encode(Document[Resource[sslCertificateAttributes]]{Data: Resource[sslCertificateAttributes]{
				Type: SSLCertificateType, ID: "-1000", Attributes: attributesFromBundle(defaultBundle),
			}})
		case "/airlock/rest/configuration/ssl-certificates":
			var document Document[Resource[sslCertificateAttributes]]
			if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
				t.Fatal(err)
			}
			created = document.Data.Attributes
			document.Data.ID = "81"
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(document)
		case "/airlock/rest/configuration/ssl-certificates/81/relationships/virtual-hosts":
			var document Document[[]ResourceIdentifier]
			if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
				t.Fatal(err)
			}
			want := []ResourceIdentifier{{Type: VirtualHostType, ID: "6"}}
			if !reflect.DeepEqual(document.Data, want) {
				t.Fatalf("unexpected relationship: %#v", document.Data)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/validator-messages":
			_ = json.NewEncoder(w).Encode(Document[[]ResourceAny]{Data: []ResourceAny{}})
		case "/airlock/rest/configuration/configurations/activate":
			if err := json.NewDecoder(r.Body).Decode(&activation); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusNoContent)
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
	result, err := client.SyncCertificate(context.Background(), ForVirtualHost("test"), bundle, SyncOptions{ActivationComment: "rotate test"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Certificate.ID != 81 || !result.Changed || !result.Created || !result.Bound {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.VirtualHost == nil || result.VirtualHost.Name != "test" || result.VirtualHost.CertificateID == nil || *result.VirtualHost.CertificateID != 81 {
		t.Fatalf("unexpected virtual host: %#v", result.VirtualHost)
	}
	if created.CertType != "SERVER_CERT" || created.Certificate == "" || created.PrivateKey == "" {
		t.Fatalf("incomplete typed certificate attributes: %#v", created)
	}
	if activation.Comment != "rotate test" || activation.Options.AutoMerge || activation.Options.IgnoreOutdatedConfiguration || !activation.Options.FailoverActivation {
		t.Fatalf("unsafe activation request: %#v", activation)
	}
	wantCalls := []string{
		"POST /airlock/rest/session/create",
		"POST /airlock/rest/configuration/configurations/load-active",
		"GET /airlock/rest/configuration/virtual-hosts",
		"GET /airlock/rest/configuration/ssl-certificates/-1000",
		"POST /airlock/rest/configuration/ssl-certificates",
		"PATCH /airlock/rest/configuration/ssl-certificates/81/relationships/virtual-hosts",
		"GET /airlock/rest/configuration/validator-messages",
		"POST /airlock/rest/configuration/configurations/activate",
		"POST /airlock/rest/session/terminate",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("call sequence mismatch\nwant: %#v\n got: %#v", wantCalls, calls)
	}
}

func TestSyncCertificateForVirtualHostSkipsEquivalentBundle(t *testing.T) {
	bundle := newTestBundle(t, "same.airlock.local")
	attributes := attributesFromBundle(bundle)
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/virtual-hosts":
			_ = json.NewEncoder(w).Encode(Document[[]Resource[virtualHostAttributes]]{Data: []Resource[virtualHostAttributes]{
				{
					Type:          VirtualHostType,
					ID:            "6",
					Attributes:    virtualHostAttributes{Name: "test", HostName: "same.airlock.local"},
					Relationships: map[string]Relationship{"ssl-certificate": {Data: ResourceIdentifier{Type: SSLCertificateType, ID: "81"}}},
				},
			}})
		case "/airlock/rest/configuration/ssl-certificates/81":
			_ = json.NewEncoder(w).Encode(Document[Resource[sslCertificateAttributes]]{Data: Resource[sslCertificateAttributes]{
				Type: SSLCertificateType, ID: "81", Attributes: attributes,
			}})
		case "/airlock/rest/session/terminate":
			w.WriteHeader(http.StatusOK)
		default:
			writes.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, APIKey: "api-key"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SyncCertificate(context.Background(), ForVirtualHost("test"), bundle, SyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Created || result.Bound || result.Certificate.Checksum != bundle.Checksum {
		t.Fatalf("equivalent bundle was not a no-op: %#v", result)
	}
	if writes.Load() != 0 {
		t.Fatalf("equivalent bundle caused %d writes", writes.Load())
	}
}

func TestSyncLeafCertificateRetainsAndWritesMatchingKey(t *testing.T) {
	current := newTestBundle(t, "renew.airlock.local")
	renewed := newTestCertificateForKey(t, "renew.airlock.local", current.Key.privateKey.(*rsa.PrivateKey))
	var patched sslCertificateAttributes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/ssl-certificates/81":
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(Document[Resource[sslCertificateAttributes]]{Data: Resource[sslCertificateAttributes]{
					Type: SSLCertificateType, ID: "81", Attributes: attributesFromBundle(current),
				}})
				return
			}
			var document Document[Resource[sslCertificateAttributes]]
			if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
				t.Fatal(err)
			}
			patched = document.Data.Attributes
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/validator-messages":
			_ = json.NewEncoder(w).Encode(Document[[]ResourceAny]{Data: []ResourceAny{}})
		case "/airlock/rest/configuration/configurations/activate":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/session/terminate":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "api-key")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SyncLeafCertificate(context.Background(), ByCertificateID(81), renewed, SyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Created || result.Certificate.Certificate.Checksum != renewed.Checksum {
		t.Fatalf("unexpected leaf-only result: %#v", result)
	}
	if patched.PrivateKey != string(current.Key.PEM()) {
		t.Fatal("leaf-only synchronization did not retain the existing private key")
	}
	if patched.Certificate != string(renewed.PEM()) {
		t.Fatal("leaf-only synchronization did not send the renewed certificate")
	}
}

func TestSyncKeyRejectsMismatchWithoutWriting(t *testing.T) {
	current := newTestBundle(t, "key.airlock.local")
	other := newTestBundle(t, "other.airlock.local")
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/airlock/rest/session/create":
			w.WriteHeader(http.StatusOK)
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/configuration/ssl-certificates/81":
			if r.Method != http.MethodGet {
				writes.Add(1)
			}
			_ = json.NewEncoder(w).Encode(Document[Resource[sslCertificateAttributes]]{Data: Resource[sslCertificateAttributes]{
				Type: SSLCertificateType, ID: "81", Attributes: attributesFromBundle(current),
			}})
		case "/airlock/rest/session/terminate":
			w.WriteHeader(http.StatusOK)
		default:
			writes.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "api-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SyncKey(context.Background(), ByCertificateID(81), other.Key, SyncOptions{}); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("expected local key mismatch, got %v", err)
	}
	if writes.Load() != 0 {
		t.Fatalf("mismatched key caused %d writes", writes.Load())
	}
}

func TestConfigurationTransactionsUseIndependentSessions(t *testing.T) {
	var next atomic.Int32
	var mu sync.Mutex
	seen := make(map[string][]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/airlock/rest/session/create" {
			id := "session-" + string(rune('0'+next.Add(1)))
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: id, Path: "/"})
			w.WriteHeader(http.StatusOK)
			return
		}
		cookie, err := r.Cookie("JSESSIONID")
		if err != nil {
			t.Errorf("%s had no session cookie: %v", r.URL.Path, err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		seen[cookie.Value] = append(seen[cookie.Value], r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/airlock/rest/configuration/configurations/load-active":
			w.WriteHeader(http.StatusNoContent)
		case "/airlock/rest/session/terminate":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, APIKey: "api-key"})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			transaction, err := client.StartConfigurationTransaction(context.Background())
			if err == nil {
				err = transaction.Abort()
			}
			results <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("expected two independent session IDs, got %#v", seen)
	}
	for sessionID, paths := range seen {
		sort.Strings(paths)
		want := []string{"/airlock/rest/configuration/configurations/load-active", "/airlock/rest/session/terminate"}
		if !reflect.DeepEqual(paths, want) {
			t.Fatalf("session %s saw unexpected paths: %#v", sessionID, paths)
		}
	}
}

func TestActivationConflictPolicies(t *testing.T) {
	tests := []struct {
		name      string
		policy    ConflictPolicy
		ignore    bool
		autoMerge bool
	}{
		{name: "reject", policy: RejectConcurrentChanges},
		{name: "merge", policy: MergeNonConflictingChanges, autoMerge: true},
		{name: "overwrite", policy: OverwriteConcurrentChanges, ignore: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request activationRequest
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			client, err := NewClient(server.URL, "api-key")
			if err != nil {
				t.Fatal(err)
			}
			err = client.ActivateConfigurationWithOptions(context.Background(), "test", ActivationOptions{
				ConflictPolicy: test.policy,
			})
			if err != nil {
				t.Fatal(err)
			}
			if request.Options.IgnoreOutdatedConfiguration != test.ignore || request.Options.AutoMerge != test.autoMerge {
				t.Fatalf("unexpected options: %#v", request.Options)
			}
		})
	}
}

func newTestBundle(t *testing.T, dnsName string) CertificateBundle {
	t.Helper()
	certificatePEM, keyPEM := newTestPEMPair(t, dnsName)
	bundle, err := ParseCertificateBundle(CertificateBundleInput{CertificatePEM: certificatePEM, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func newTestPEMPair(t *testing.T, dnsName string) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func newTestCertificateForKey(t *testing.T, dnsName string, key *rsa.PrivateKey) Certificate {
	t.Helper()
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := ParseCertificate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}))
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
