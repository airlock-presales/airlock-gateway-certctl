package airlock

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
)

// TestLiveGatewayCertificateLifecycle is an opt-in integration test. It creates
// and activates a short-lived self-signed certificate, binds it to the selected
// test virtual host, verifies idempotency and rotation, and restores the exact
// configuration that was active before the test.
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
	serviceAddress := strings.TrimSpace(os.Getenv("AIRLOCK_TEST_SERVICE_ADDRESS"))
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

	first, firstSerial := liveCertificateMaterial(t, fqdn)
	second, secondSerial := liveCertificateMaterial(t, fqdn)
	mismatched, _ := liveCertificateMaterial(t, fqdn)
	mismatched.PrivateKey = second.PrivateKey

	var certificateID string
	var virtualHostID string
	var baselineConfigurationID string
	var activated bool
	defer func() {
		if activated {
			restoreLiveConfiguration(t, client, baselineConfigurationID, certificateID)
		}
	}()

	transaction, err := client.StartConfigurationTransaction(ctx)
	if err != nil {
		t.Fatalf("start create transaction: %v", err)
	}
	t.Log("configuration transaction started")
	baselineConfigurationID, err = currentLiveConfigurationID(ctx, client)
	if err != nil {
		_ = transaction.Abort()
		t.Fatalf("determine baseline configuration: %v", err)
	}
	t.Logf("baseline configuration is %s", baselineConfigurationID)
	virtualHosts, err := listLiveVirtualHosts(ctx, client)
	if err != nil {
		_ = transaction.Abort()
		t.Fatalf("list virtual hosts: %v", err)
	}
	virtualHostID = findLiveVirtualHost(virtualHosts, virtualHostName, fqdn)
	if virtualHostID == "" {
		_ = transaction.Abort()
		t.Fatalf("virtual host %q for %q not found; available: %s", virtualHostName, fqdn, summarizeLiveVirtualHosts(virtualHosts))
	}
	t.Logf("test virtual host resolved to ID %s", virtualHostID)

	created, err := transaction.SyncSSLCertificate("", first)
	if err != nil {
		_ = transaction.Abort()
		t.Fatalf("create certificate and key: %v", err)
	}
	certificateID = created.Resource.ID
	if certificateID == "" || !created.Created || !created.Changed {
		_ = transaction.Abort()
		t.Fatalf("unexpected create result: id=%q created=%t changed=%t", certificateID, created.Created, created.Changed)
	}
	if created.Checksums != first.Checksums() {
		_ = transaction.Abort()
		t.Fatalf("create checksums do not match supplied material")
	}
	t.Logf("certificate pair created as resource %s", certificateID)
	if err := client.ConnectSSLCertificateToVirtualHosts(ctx, certificateID, virtualHostID); err != nil {
		_ = transaction.Abort()
		t.Fatalf("connect certificate to test virtual host: %v", err)
	}
	t.Log("certificate relationship staged")
	if err := transaction.Commit("airlock-certctl live test: create certificate pair"); err != nil {
		t.Fatalf("commit create transaction: %v", err)
	}
	activated = true
	t.Log("certificate pair and relationship activated")

	if serviceAddress != "" {
		if err := waitForLiveCertificate(ctx, serviceAddress, fqdn, firstSerial); err != nil {
			t.Fatalf("verify initially served certificate: %v", err)
		}
	}

	unchanged, err := client.SyncSSLCertificate(ctx, certificateID, first, "airlock-certctl live test: no-op")
	if err != nil {
		t.Fatalf("repeat identical synchronization: %v", err)
	}
	if unchanged.Changed || unchanged.Created {
		t.Fatalf("identical material was not treated as a no-op: created=%t changed=%t", unchanged.Created, unchanged.Changed)
	}
	t.Log("identical synchronization correctly completed without a write")

	rotated, err := client.SyncSSLCertificate(ctx, certificateID, second, "airlock-certctl live test: rotate certificate pair")
	if err != nil {
		t.Fatalf("rotate certificate and key: %v", err)
	}
	if rotated.Created || !rotated.Changed || rotated.Resource.ID != certificateID {
		t.Fatalf("unexpected rotation result: id=%q created=%t changed=%t", rotated.Resource.ID, rotated.Created, rotated.Changed)
	}
	if rotated.Checksums != second.Checksums() {
		t.Fatalf("rotation checksums do not match supplied material")
	}
	t.Log("certificate and private key rotated in place")

	assertLiveMaterial(t, ctx, client, certificateID, second)
	t.Log("rotated material read back and verified")
	if serviceAddress != "" {
		if err := waitForLiveCertificate(ctx, serviceAddress, fqdn, secondSerial); err != nil {
			t.Fatalf("verify rotated served certificate: %v", err)
		}
	}

	if _, err := client.SyncSSLCertificate(ctx, certificateID, mismatched, "airlock-certctl live test: reject mismatch"); err == nil {
		t.Fatal("mismatched certificate and private key were accepted")
	}
	t.Log("mismatched certificate/private-key pair rejected")
	assertLiveMaterial(t, ctx, client, certificateID, second)
	t.Log("Gateway material remained unchanged after mismatch rejection")
}

func liveCertificateMaterial(t *testing.T, fqdn string) (CertificateMaterial, *big.Int) {
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
	return CertificateMaterial{
		CertType:         "SERVER_CERT",
		Certificate:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})),
		CertificateChain: []string{},
		PrivateKey:       string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})),
	}, serial
}

func listLiveVirtualHosts(ctx context.Context, client *Client) ([]ResourceAny, error) {
	var document Document[[]ResourceAny]
	if err := client.DoJSON(ctx, http.MethodGet, "/configuration/virtual-hosts", nil, &document, http.StatusOK); err != nil {
		return nil, err
	}
	return document.Data, nil
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

func findLiveVirtualHost(resources []ResourceAny, name, fqdn string) string {
	for _, resource := range resources {
		if equalLiveString(resource.Attributes["name"], name) || containsLiveString(resource.Attributes, fqdn) {
			return resource.ID
		}
	}
	return ""
}

func containsLiveString(value any, wanted string) bool {
	switch typed := value.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), strings.TrimSpace(wanted))
	case []any:
		for _, item := range typed {
			if containsLiveString(item, wanted) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if containsLiveString(item, wanted) {
				return true
			}
		}
	}
	return false
}

func equalLiveString(value any, wanted string) bool {
	text, ok := value.(string)
	return ok && strings.EqualFold(strings.TrimSpace(text), strings.TrimSpace(wanted))
}

func summarizeLiveVirtualHosts(resources []ResourceAny) string {
	items := make([]string, 0, len(resources))
	for _, resource := range resources {
		name, _ := resource.Attributes["name"].(string)
		items = append(items, fmt.Sprintf("%s:%s", resource.ID, name))
	}
	return strings.Join(items, ", ")
}

func assertLiveMaterial(t *testing.T, ctx context.Context, client *Client, certificateID string, expected CertificateMaterial) {
	t.Helper()
	transaction, err := client.StartConfigurationTransaction(ctx)
	if err != nil {
		t.Fatalf("start verification transaction: %v", err)
	}
	resource, err := client.GetSSLCertificate(ctx, certificateID)
	abortErr := transaction.Abort()
	if err != nil {
		t.Fatalf("read synchronized certificate: %v", err)
	}
	if abortErr != nil {
		t.Fatalf("finish verification transaction: %v", abortErr)
	}
	actual, err := materialFromResource(resource)
	if err != nil {
		t.Fatalf("decode synchronized certificate: %v", err)
	}
	if !certificateMaterialEqual(actual, normalizeCertificateMaterial(expected)) {
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

func restoreLiveConfiguration(t *testing.T, client *Client, configurationID, certificateID string) {
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
	if _, err := client.GetSSLCertificate(ctx, certificateID); err == nil {
		t.Errorf("restore: test certificate %s still exists in baseline configuration", certificateID)
		return
	} else if !IsNotFound(err) {
		t.Errorf("restore: verify test certificate removal: %v", err)
		return
	}
	t.Log("baseline configuration restored")
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
