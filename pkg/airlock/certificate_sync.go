package airlock

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// CertificateMaterial is the Airlock Gateway ssl-certificate attribute set
// relevant to certificate and private-key synchronization.
type CertificateMaterial struct {
	CertType          string   `json:"certType"`
	Certificate       string   `json:"certificate"`
	CertificateChain  []string `json:"certificateChain"`
	PrivateKey        string   `json:"privateKey"`
	RootCACertificate string   `json:"rootCaCertificate"`
}

// CertificateChecksums contains SHA-256 checksums of the exact certificate
// and private-key bytes sent to Airlock Gateway.
type CertificateChecksums struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"privateKey,omitempty"`
}

// Checksums calculates stable checksums for equivalence checks and reporting.
func (m CertificateMaterial) Checksums() CertificateChecksums {
	return CertificateChecksums{
		Certificate: checksum(m.Certificate),
		PrivateKey:  checksum(m.PrivateKey),
	}
}

// CertificateSyncResult describes the result of synchronizing one Airlock
// Gateway ssl-certificate resource.
type CertificateSyncResult struct {
	Resource  ResourceAny          `json:"resource"`
	Checksums CertificateChecksums `json:"checksums"`
	Changed   bool                 `json:"changed"`
	Created   bool                 `json:"created"`
}

// ConfigurationTransaction owns one Airlock REST session with the active
// configuration loaded. Changes only become active when Commit succeeds.
type ConfigurationTransaction struct {
	client  *Client
	ctx     context.Context
	mu      sync.Mutex
	changed bool
	closed  bool
}

// StartConfigurationTransaction creates a REST session and loads the active
// Airlock Gateway configuration.
func (c *Client) StartConfigurationTransaction(ctx context.Context) (*ConfigurationTransaction, error) {
	if ctx == nil {
		return nil, errors.New("context must not be nil")
	}
	c.configMu.Lock()
	if err := c.CreateSessionAndLoadActiveConfiguration(ctx); err != nil {
		c.configMu.Unlock()
		return nil, err
	}
	return &ConfigurationTransaction{client: c, ctx: ctx}, nil
}

// SyncSSLCertificate synchronizes one certificate/private-key pair and commits
// it in a single Airlock configuration session. An empty resourceID creates a
// new ssl-certificate and returns the ID assigned by Airlock Gateway.
func (c *Client) SyncSSLCertificate(
	ctx context.Context,
	resourceID string,
	material CertificateMaterial,
	activationComment string,
) (CertificateSyncResult, error) {
	transaction, err := c.StartConfigurationTransaction(ctx)
	if err != nil {
		return CertificateSyncResult{}, err
	}

	result, err := transaction.SyncSSLCertificate(resourceID, material)
	if err != nil {
		return CertificateSyncResult{}, errors.Join(err, transaction.Abort())
	}
	if err := transaction.Commit(activationComment); err != nil {
		return CertificateSyncResult{}, err
	}
	return result, nil
}

// SyncSSLCertificate checksum-compares and creates or updates an Airlock
// ssl-certificate. Certificate and private key are always written together in
// one JSON:API request when any material differs.
func (t *ConfigurationTransaction) SyncSSLCertificate(
	resourceID string,
	material CertificateMaterial,
) (CertificateSyncResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return CertificateSyncResult{}, errors.New("configuration transaction is closed")
	}
	material = normalizeCertificateMaterial(material)
	if material.Certificate == "" {
		return CertificateSyncResult{}, errors.New("certificate must not be empty")
	}
	if err := validateCertificateKeyPair(material.Certificate, material.PrivateKey); err != nil {
		return CertificateSyncResult{}, err
	}

	current, err := t.findCertificate(resourceID)
	if err != nil {
		return CertificateSyncResult{}, err
	}
	result := CertificateSyncResult{Checksums: material.Checksums()}
	if current != nil {
		result.Resource = *current
		currentMaterial, err := materialFromResource(*current)
		if err != nil {
			return CertificateSyncResult{}, err
		}
		if certificateMaterialEqual(currentMaterial, material) {
			return result, nil
		}
	}

	attributes := material.attributes()
	if current == nil {
		created, err := t.client.CreateSSLCertificate(t.ctx, attributes)
		if err != nil {
			return CertificateSyncResult{}, err
		}
		result.Resource = created
		result.Created = true
	} else {
		updated, err := t.client.UpdateSSLCertificate(t.ctx, current.ID, attributes)
		if err != nil {
			return CertificateSyncResult{}, err
		}
		if updated.ID == "" {
			updated = *current
			updated.Attributes = attributes
		}
		result.Resource = updated
	}
	result.Changed = true
	t.changed = true
	return result, nil
}

// Commit validates and activates all changes, then terminates the REST session.
// If nothing changed, it only terminates the session.
func (t *ConfigurationTransaction) Commit(activationComment string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return errors.New("configuration transaction is closed")
	}
	if t.changed {
		messages, err := t.client.Validate(t.ctx)
		if err != nil {
			return t.finish(err)
		}
		if len(messages) != 0 {
			return t.finish(validationMessagesError(messages))
		}
		if err := t.client.ActivateConfiguration(t.ctx, activationComment); err != nil {
			return t.finish(err)
		}
	}
	return t.finish(nil)
}

// Abort terminates the REST session without activating staged changes.
func (t *ConfigurationTransaction) Abort() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	return t.finish(nil)
}

func (t *ConfigurationTransaction) finish(operationErr error) error {
	terminateErr := t.client.TerminateSession(t.ctx)
	t.closed = true
	t.client.configMu.Unlock()
	return errors.Join(operationErr, terminateErr)
}

func (t *ConfigurationTransaction) findCertificate(resourceID string) (*ResourceAny, error) {
	if resourceID == "" {
		return nil, nil
	}
	resource, err := t.client.GetSSLCertificate(t.ctx, resourceID)
	if err == nil {
		return &resource, nil
	}
	if IsNotFound(err) {
		return nil, nil
	}
	return nil, err
}

func normalizeCertificateMaterial(material CertificateMaterial) CertificateMaterial {
	if material.CertType == "" {
		material.CertType = "SERVER_CERT"
	}
	if material.CertificateChain == nil {
		material.CertificateChain = []string{}
	}
	return material
}

func (m CertificateMaterial) attributes() map[string]any {
	attributes := map[string]any{
		"certType":          m.CertType,
		"certificate":       m.Certificate,
		"certificateChain":  m.CertificateChain,
		"privateKey":        m.PrivateKey,
		"rootCaCertificate": m.RootCACertificate,
	}
	return attributes
}

func materialFromResource(resource ResourceAny) (CertificateMaterial, error) {
	data, err := json.Marshal(resource.Attributes)
	if err != nil {
		return CertificateMaterial{}, fmt.Errorf("marshal SSL certificate attributes: %w", err)
	}
	var material CertificateMaterial
	if err := json.Unmarshal(data, &material); err != nil {
		return CertificateMaterial{}, fmt.Errorf("decode SSL certificate attributes: %w", err)
	}
	return normalizeCertificateMaterial(material), nil
}

func certificateMaterialEqual(a, b CertificateMaterial) bool {
	if a.CertType != b.CertType ||
		checksum(a.Certificate) != checksum(b.Certificate) ||
		checksum(a.PrivateKey) != checksum(b.PrivateKey) ||
		a.RootCACertificate != b.RootCACertificate ||
		len(a.CertificateChain) != len(b.CertificateChain) {
		return false
	}
	for index := range a.CertificateChain {
		if a.CertificateChain[index] != b.CertificateChain[index] {
			return false
		}
	}
	return true
}

func checksum(content string) string {
	if content == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateCertificateKeyPair(certificate, privateKey string) error {
	if privateKey == "" || !strings.Contains(certificate, "-----BEGIN CERTIFICATE-----") ||
		!strings.Contains(privateKey, "PRIVATE KEY-----") ||
		strings.Contains(privateKey, "-----BEGIN ENCRYPTED PRIVATE KEY-----") {
		return nil
	}
	if _, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey)); err != nil {
		return fmt.Errorf("certificate and private key do not match: %w", err)
	}
	return nil
}

func validationMessagesError(messages []ValidationMessage) error {
	details := make([]string, 0, len(messages))
	for _, message := range messages {
		detail := strings.TrimSpace(message.Detail)
		if detail == "" {
			detail = message.ID
		}
		details = append(details, detail)
	}
	return fmt.Errorf("Airlock Gateway configuration validation failed: %s", strings.Join(details, "; "))
}
