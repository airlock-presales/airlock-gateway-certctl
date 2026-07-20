package airlock

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/youmark/pkcs8"
)

// TestLiveGatewayCertificateLifecycle is an opt-in integration test. It
// addresses a certificate only through the logical virtual-host name, deploys
// self-signed pairs, verifies idempotency and appliance-side conflict
// rejection, and restores the exact configuration active before the test.
// It never runs during ordinary `go test ./...` invocations.
func TestLiveGatewayCertificateLifecycle(t *testing.T) {
	if os.Getenv("AIRLOCK_LIVE_TEST") != "1" {
		t.Skip("set AIRLOCK_LIVE_TEST=1 to run the destructive live Gateway test")
	}

	host := strings.TrimSpace(os.Getenv("AIRLOCK_HOST"))
	apiKey := strings.TrimSpace(os.Getenv("AIRLOCK_API_KEY"))
	if host == "" || apiKey == "" {
		t.Fatal("AIRLOCK_HOST and AIRLOCK_API_KEY are required")
	}

	fqdn := envOrDefault("AIRLOCK_TEST_FQDN", "test.airlock.local")
	virtualHostName := envOrDefault("AIRLOCK_TEST_VIRTUAL_HOST", "test")
	serviceAddress := envOrDefault("AIRLOCK_TEST_SERVICE_ADDRESS", net.JoinHostPort(fqdn, "443"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client, err := New(Config{
		Address:            host,
		APIKey:             apiKey,
		Timeout:            90 * time.Second,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Log("connected client configuration prepared")

	first, firstSerial := liveCertificateBundle(t, fqdn)
	second, secondSerial := liveCertificateBundle(t, fqdn)
	third, _ := liveCertificateBundle(t, fqdn)
	encrypted, encryptedSerial := liveEncryptedCertificateBundle(t, fqdn)
	mismatchCertificatePEM, _, _ := livePEMPair(t, fqdn)
	_, mismatchKeyPEM, _ := livePEMPair(t, fqdn)

	var certificateID CertificateID
	var baselineConfigurationID string
	var baselineCertificate *ManagedCertificate
	var activated bool
	defer func() {
		if activated {
			restoreLiveConfiguration(t, client, baselineConfigurationID, certificateID, baselineCertificate, virtualHostName)
		}
	}()

	transaction, err := client.StartConfigurationTransaction(ctx)
	if err != nil {
		t.Fatalf("start create transaction: %v", err)
	}
	t.Log("configuration transaction started")
	baselineConfigurationID, err = currentLiveConfigurationID(ctx, transaction.client)
	if err != nil {
		_ = transaction.Abort()
		t.Fatalf("determine baseline configuration: %v", err)
	}
	t.Logf("baseline configuration is %s", baselineConfigurationID)
	baseline, baselineErr := transaction.GetCertificate(ForVirtualHost(VirtualHostName(virtualHostName)))
	if baselineErr == nil {
		baselineCertificate = &baseline
	} else if !strings.Contains(baselineErr.Error(), "has no SSL certificate") {
		_ = transaction.Abort()
		t.Fatalf("read baseline certificate: %v", baselineErr)
	}
	if err := transaction.Abort(); err != nil {
		t.Fatalf("finish baseline transaction: %v", err)
	}

	created, err := client.SyncCertificate(ctx, ForVirtualHost(VirtualHostName(virtualHostName)), first, SyncOptions{
		ActivationComment: "airlock-certctl live test: deploy certificate pair",
	})
	if err != nil {
		t.Fatalf("deploy certificate and key: %v", err)
	}
	certificateID = created.Certificate.ID
	if certificateID == 0 || !created.Changed {
		t.Fatalf("unexpected deploy result: id=%q created=%t changed=%t", certificateID, created.Created, created.Changed)
	}
	if created.Certificate.Checksum != first.Checksum {
		t.Fatalf("deployed bundle checksum does not match supplied material")
	}
	activated = true
	t.Logf("certificate pair deployed through virtual host %q as resource %s", virtualHostName, certificateID)

	if serviceAddress != "" {
		if err := waitForLiveCertificate(ctx, serviceAddress, fqdn, firstSerial); err != nil {
			t.Fatalf("verify initially served certificate: %v", err)
		}
	}

	unchanged, err := client.SyncCertificate(ctx, ForVirtualHost(VirtualHostName(virtualHostName)), first, SyncOptions{
		ActivationComment: "airlock-certctl live test: no-op",
	})
	if err != nil {
		t.Fatalf("repeat identical synchronization: %v", err)
	}
	if unchanged.Changed || unchanged.Created || unchanged.Bound {
		t.Fatalf("identical material was not treated as a no-op: %#v", unchanged)
	}
	t.Log("identical synchronization correctly completed without a write")

	firstConcurrent, err := client.StartConfigurationTransaction(ctx)
	if err != nil {
		t.Fatalf("start first concurrent transaction: %v", err)
	}
	secondConcurrent, err := client.StartConfigurationTransaction(ctx)
	if err != nil {
		_ = firstConcurrent.Abort()
		t.Fatalf("start second concurrent transaction: %v", err)
	}
	if _, err := firstConcurrent.SyncCertificate(ForVirtualHost(VirtualHostName(virtualHostName)), second); err != nil {
		_ = firstConcurrent.Abort()
		_ = secondConcurrent.Abort()
		t.Fatalf("stage first concurrent rotation: %v", err)
	}
	if _, err := secondConcurrent.SyncCertificate(ForVirtualHost(VirtualHostName(virtualHostName)), third); err != nil {
		_ = firstConcurrent.Abort()
		_ = secondConcurrent.Abort()
		t.Fatalf("stage second concurrent rotation: %v", err)
	}
	if err := firstConcurrent.Commit("airlock-certctl live test: first concurrent rotation"); err != nil {
		_ = secondConcurrent.Abort()
		t.Fatalf("commit first concurrent rotation: %v", err)
	}
	if err := secondConcurrent.Commit("airlock-certctl live test: stale concurrent rotation"); err == nil {
		t.Fatal("Airlock accepted activation from an outdated concurrent session")
	} else {
		t.Logf("Airlock rejected the stale transaction as expected: %v", err)
	}

	assertLiveBundle(t, ctx, client, virtualHostName, second)
	t.Log("winning certificate and private key read back and checksum-verified")
	if serviceAddress != "" {
		if err := waitForLiveCertificate(ctx, serviceAddress, fqdn, secondSerial); err != nil {
			t.Fatalf("verify rotated served certificate: %v", err)
		}
	}

	encryptedResult, err := client.SyncCertificate(ctx, ForVirtualHost(VirtualHostName(virtualHostName)), encrypted, SyncOptions{
		ActivationComment: "airlock-certctl live test: encrypted PKCS#8 key",
	})
	if err != nil {
		t.Fatalf("deploy encrypted PKCS#8 key: %v", err)
	}
	if !encryptedResult.Changed || encryptedResult.Certificate.Checksum != encrypted.Checksum {
		t.Fatalf("unexpected encrypted-key result: %#v", encryptedResult)
	}
	assertLiveBundle(t, ctx, client, virtualHostName, encrypted)
	t.Log("encrypted PKCS#8 key accepted, activated, and read back consistently")
	encryptedNoOp, err := client.SyncCertificate(ctx, ForVirtualHost(VirtualHostName(virtualHostName)), encrypted, SyncOptions{})
	if err != nil {
		t.Fatalf("repeat encrypted-key synchronization: %v", err)
	}
	if encryptedNoOp.Changed {
		t.Fatal("identical encrypted key and certificate were not treated as a no-op")
	}
	if serviceAddress != "" {
		if err := waitForLiveCertificate(ctx, serviceAddress, fqdn, encryptedSerial); err != nil {
			t.Fatalf("verify certificate deployed with encrypted key: %v", err)
		}
	}

	if _, err := ParseCertificateBundle(CertificateBundleInput{
		CertificatePEM: mismatchCertificatePEM,
		PrivateKeyPEM:  mismatchKeyPEM,
	}); err == nil {
		t.Fatal("mismatched certificate and private key were accepted")
	}
	t.Log("mismatched certificate/private-key pair rejected locally")
	assertLiveBundle(t, ctx, client, virtualHostName, encrypted)
	t.Log("Gateway material remained unchanged after mismatch rejection")
}

// TestLiveGatewayConcurrentReadSessions verifies that one Client can operate
// several independent Airlock working sessions concurrently.
func TestLiveGatewayConcurrentReadSessions(t *testing.T) {
	if os.Getenv("AIRLOCK_LIVE_TEST") != "1" {
		t.Skip("set AIRLOCK_LIVE_TEST=1 to run live Gateway tests")
	}
	host := strings.TrimSpace(os.Getenv("AIRLOCK_HOST"))
	apiKey := strings.TrimSpace(os.Getenv("AIRLOCK_API_KEY"))
	virtualHostName := VirtualHostName(envOrDefault("AIRLOCK_TEST_VIRTUAL_HOST", "test"))
	client, err := New(Config{Address: host, APIKey: apiKey, Timeout: 90 * time.Second, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const workers = 4
	errorsChannel := make(chan error, workers)
	started := time.Now()
	for range workers {
		go func() {
			_, err := client.GetCertificate(ctx, ForVirtualHost(virtualHostName))
			errorsChannel <- err
		}()
	}
	for range workers {
		if err := <-errorsChannel; err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%d independent read sessions completed in %s", workers, time.Since(started))
}

// TestLiveGatewayOpenAPIContract checks the typed surface against the schema
// actually published by the target appliance.
func TestLiveGatewayOpenAPIContract(t *testing.T) {
	if os.Getenv("AIRLOCK_LIVE_TEST") != "1" {
		t.Skip("set AIRLOCK_LIVE_TEST=1 to run live Gateway tests")
	}
	client, err := New(Config{
		Address:            strings.TrimSpace(os.Getenv("AIRLOCK_HOST")),
		APIKey:             strings.TrimSpace(os.Getenv("AIRLOCK_API_KEY")),
		Timeout:            90 * time.Second,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := client.DownloadOpenAPISpec(context.Background(), "json")
	if err != nil {
		t.Fatalf("download live OpenAPI schema: %v", err)
	}
	var schema struct {
		Paths      map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Enum []string `json:"enum"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("decode live OpenAPI schema: %v", err)
	}
	for _, path := range []string{
		"/configuration/ssl-certificates",
		"/configuration/ssl-certificates/{id}",
		"/configuration/ssl-certificates/{id}/relationships/virtual-hosts",
		"/configuration/virtual-hosts",
		"/configuration/configurations/activate",
	} {
		if _, exists := schema.Paths[path]; !exists {
			t.Errorf("live OpenAPI schema is missing required path %s", path)
		}
	}
	wantTypes := []string{string(ServerCertificate), string(ClientCertificate)}
	gotTypes := schema.Components.Schemas["SSLCertificateDto"].Properties["certType"].Enum
	if strings.Join(gotTypes, ",") != strings.Join(wantTypes, ",") {
		t.Errorf("live certType enum differs: want %v, got %v", wantTypes, gotTypes)
	}
	if t.Failed() {
		t.FailNow()
	}
	t.Log("live OpenAPI certificate contract matches the typed client")
}

func livePEMPair(t *testing.T, fqdn string) ([]byte, []byte, *big.Int) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("generate certificate serial: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: fqdn, Organization: []string{"airlock-certctl live test"}},
		DNSNames:     []string{fqdn},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), serial
}

func liveCertificateBundle(t *testing.T, fqdn string) (CertificateBundle, *big.Int) {
	t.Helper()
	certificatePEM, privateKeyPEM, serial := livePEMPair(t, fqdn)
	bundle, err := ParseCertificateBundle(CertificateBundleInput{
		Type:           ServerCertificate,
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  privateKeyPEM,
	})
	if err != nil {
		t.Fatalf("parse generated certificate bundle: %v", err)
	}
	return bundle, serial
}

func liveEncryptedCertificateBundle(t *testing.T, fqdn string) (CertificateBundle, *big.Int) {
	t.Helper()
	certificatePEM, privateKeyPEM, serial := livePEMPair(t, fqdn)
	block, _ := pem.Decode(privateKeyPEM)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse generated private key: %v", err)
	}
	passphrase := []byte("airlock-certctl-live-test")
	encryptedDER, err := pkcs8.MarshalPrivateKey(privateKey, passphrase, pkcs8.DefaultOpts)
	if err != nil {
		t.Fatalf("encrypt generated private key: %v", err)
	}
	bundle, err := ParseCertificateBundle(CertificateBundleInput{
		Type:                 ServerCertificate,
		CertificatePEM:       certificatePEM,
		PrivateKeyPEM:        pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedDER}),
		PrivateKeyPassphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("parse encrypted certificate bundle: %v", err)
	}
	return bundle, serial
}

func currentLiveConfigurationID(ctx context.Context, client *Client) (string, error) {
	var document Document[[]ResourceAny]
	if err := client.DoJSON(ctx, http.MethodGet, "/configuration/configurations", nil, &document, http.StatusOK); err != nil {
		return "", err
	}
	for _, configuration := range document.Data {
		if equalLiveString(configuration.Attributes["configType"], "CURRENTLY_ACTIVE") {
			return configuration.ID, nil
		}
	}
	return "", errors.New("currently active configuration not found")
}

func equalLiveString(value any, wanted string) bool {
	text, ok := value.(string)
	return ok && strings.EqualFold(strings.TrimSpace(text), strings.TrimSpace(wanted))
}

func assertLiveBundle(t *testing.T, ctx context.Context, client *Client, virtualHostName string, expected CertificateBundle) {
	t.Helper()
	actual, err := client.GetCertificateWithOptions(ctx, ForVirtualHost(VirtualHostName(virtualHostName)), ReadOptions{
		PrivateKeyPassphrase: expected.Key.passphrase,
	})
	if err != nil {
		t.Fatalf("read synchronized certificate by virtual-host name: %v", err)
	}
	if actual.Checksum != expected.Checksum || actual.Certificate.Checksum != expected.Certificate.Checksum || actual.Key.Checksum != expected.Key.Checksum {
		t.Fatal("Gateway certificate or private-key material differs from the supplied pair")
	}
}

func waitForLiveCertificate(ctx context.Context, address, fqdn string, serial *big.Int) error {
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		connection, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName:         fqdn,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // The live test intentionally deploys a self-signed certificate.
		})
		if err == nil {
			certificates := connection.ConnectionState().PeerCertificates
			_ = connection.Close()
			if len(certificates) != 0 && certificates[0].SerialNumber.Cmp(serial) == 0 {
				return nil
			}
			lastErr = fmt.Errorf("Gateway served a different certificate")
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), lastErr)
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("certificate serial was not served by %s for %s within one minute: %w", address, fqdn, lastErr)
}

func restoreLiveConfiguration(t *testing.T, client *Client, configurationID string, certificateID CertificateID, baselineCertificate *ManagedCertificate, virtualHostName string) {
	t.Helper()
	t.Logf("restoring baseline configuration %s", configurationID)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := client.CreateSessionAndLoadActiveConfiguration(ctx); err != nil {
		t.Errorf("restore: start session: %v", err)
		return
	}
	defer func() {
		if err := client.TerminateSession(context.Background()); err != nil {
			t.Errorf("restore: terminate session: %v", err)
		}
	}()
	if err := client.LoadConfiguration(ctx, configurationID, ""); err != nil {
		t.Errorf("restore: load configuration %s: %v", configurationID, err)
		return
	}
	messages, err := client.Validate(ctx)
	if err != nil {
		t.Errorf("restore: validate configuration: %v", err)
		return
	}
	if len(messages) != 0 {
		t.Errorf("restore: baseline configuration has validation errors: %#v", messages)
		return
	}
	body := map[string]any{
		"comment": "airlock-certctl live test: restore baseline",
		"options": map[string]any{
			"ignoreOutdatedConfiguration": true,
			"autoMerge":                   false,
			"failoverActivation":          true,
		},
	}
	if err := client.DoJSON(ctx, http.MethodPost, "/configuration/configurations/activate", body, nil, http.StatusOK, http.StatusNoContent); err != nil {
		t.Errorf("restore: activate baseline configuration: %v", err)
		return
	}
	if baselineCertificate == nil {
		if _, err := client.GetSSLCertificate(ctx, certificateID.String()); err == nil {
			t.Errorf("restore: test certificate %s still exists in baseline configuration", certificateID)
			return
		} else if !IsNotFound(err) {
			t.Errorf("restore: verify test certificate removal: %v", err)
			return
		}
	} else {
		// The current REST session loaded the restored configuration, so inspect
		// it directly rather than creating a nested high-level session.
		var document Document[Resource[sslCertificateAttributes]]
		path := "/configuration/ssl-certificates/" + baselineCertificate.ID.String()
		if err := client.DoJSON(ctx, http.MethodGet, path, nil, &document, http.StatusOK); err != nil {
			t.Errorf("restore: read baseline certificate for virtual host %q: %v", virtualHostName, err)
			return
		}
		restored, parseErr := managedCertificateFromResource(document.Data, nil)
		if parseErr != nil || restored.Checksum != baselineCertificate.Checksum {
			t.Errorf("restore: baseline certificate checksum differs: parse=%v", parseErr)
			return
		}
	}
	t.Log("baseline configuration restored")
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
