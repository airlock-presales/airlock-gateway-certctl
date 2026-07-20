package airlock

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// CertificateID is the numeric identifier Airlock assigns to an
// ssl-certificate resource. Negative IDs are valid for built-in resources.
type CertificateID int64

func (id CertificateID) String() string { return strconv.FormatInt(int64(id), 10) }

// VirtualHostID is the numeric identifier Airlock assigns to a virtual host.
type VirtualHostID int64

func (id VirtualHostID) String() string { return strconv.FormatInt(int64(id), 10) }

// VirtualHostName is the stable, user-visible logical name of a virtual host.
type VirtualHostName string

// CertificateTarget selects an Airlock certificate without exposing the
// selector implementation. Prefer ForVirtualHost for plug-and-play lifecycle
// management; ByCertificateID is available for unbound resources.
type CertificateTarget interface {
	certificateTarget()
}

type virtualHostTarget struct{ name VirtualHostName }
type certificateIDTarget struct{ id CertificateID }

func (virtualHostTarget) certificateTarget()   {}
func (certificateIDTarget) certificateTarget() {}

// ForVirtualHost addresses the certificate currently bound to the exact
// logical Airlock virtual-host name. If none is bound, synchronization creates
// and binds one in the same Gateway configuration transaction.
func ForVirtualHost(name VirtualHostName) CertificateTarget {
	return virtualHostTarget{name: name}
}

// ByCertificateID addresses an unbound or otherwise explicitly selected
// Airlock ssl-certificate resource.
func ByCertificateID(id CertificateID) CertificateTarget {
	return certificateIDTarget{id: id}
}

// VirtualHost is the typed subset of an Airlock virtual host needed for
// certificate management.
type VirtualHost struct {
	ID            VirtualHostID   `json:"id"`
	Name          VirtualHostName `json:"name"`
	HostName      string          `json:"hostName"`
	AliasNames    []string        `json:"aliasNames,omitempty"`
	CertificateID *CertificateID  `json:"certificateId,omitempty"`
}

// ManagedCertificate is a typed view of an Airlock ssl-certificate resource.
type ManagedCertificate struct {
	ID          CertificateID   `json:"id"`
	Type        CertificateType `json:"type"`
	Certificate Certificate     `json:"certificate"`
	Key         Key             `json:"key"`
	Chain       []Certificate   `json:"chain,omitempty"`
	RootCA      *Certificate    `json:"rootCA,omitempty"`
	Checksum    Checksum        `json:"checksum"`
}

// SyncOptions controls validation and activation of a certificate change.
// The zero value is safe: reject concurrent changes and activate on failover.
type SyncOptions struct {
	ActivationComment         string
	ConflictPolicy            ConflictPolicy
	DisableFailoverActivation bool
	// ExistingKeyPassphrase is required by leaf-only/key-only operations when
	// the currently stored Airlock key is encrypted. It is never persisted.
	ExistingKeyPassphrase []byte `json:"-"`
}

// ReadOptions supplies transient information needed to decode device state.
type ReadOptions struct {
	// PrivateKeyPassphrase is required when Airlock returns an encrypted key;
	// the Configuration REST API intentionally never returns the passphrase.
	PrivateKeyPassphrase []byte `json:"-"`
}

func (o SyncOptions) activationOptions() ActivationOptions {
	policy := o.ConflictPolicy
	if policy == "" {
		policy = RejectConcurrentChanges
	}
	return ActivationOptions{
		ConflictPolicy:            policy,
		DisableFailoverActivation: o.DisableFailoverActivation,
	}
}

// SyncResult reports the typed state selected by target after synchronization.
type SyncResult struct {
	Certificate ManagedCertificate `json:"certificate"`
	VirtualHost *VirtualHost       `json:"virtualHost,omitempty"`
	Changed     bool               `json:"changed"`
	Created     bool               `json:"created"`
	Bound       bool               `json:"bound"`
}

type sslCertificateAttributes struct {
	Certificate       string   `json:"certificate"`
	PrivateKey        string   `json:"privateKey"`
	Passphrase        string   `json:"passphrase,omitempty"`
	CertificateChain  []string `json:"certificateChain"`
	RootCACertificate string   `json:"rootCaCertificate"`
	CertType          string   `json:"certType"`
}

type virtualHostAttributes struct {
	Name       string   `json:"name"`
	HostName   string   `json:"hostName"`
	AliasNames []string `json:"aliasNames"`
}

// SyncCertificate validates, checksum-compares, and atomically activates a
// certificate/private-key pair. ForVirtualHost removes all caller-side
// resource-ID management.
func (c *Client) SyncCertificate(ctx context.Context, target CertificateTarget, bundle CertificateBundle, options SyncOptions) (SyncResult, error) {
	if err := validateTarget(target); err != nil {
		return SyncResult{}, err
	}
	if err := bundle.validate(); err != nil {
		return SyncResult{}, err
	}
	transaction, err := c.StartConfigurationTransaction(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	result, err := transaction.SyncCertificate(target, bundle)
	if err != nil {
		return SyncResult{}, errors.Join(err, transaction.Abort())
	}
	if err := transaction.CommitWithOptions(options.ActivationComment, options.activationOptions()); err != nil {
		return SyncResult{}, err
	}
	return result, nil
}

// SyncLeafCertificate replaces only the leaf certificate while retaining the
// currently configured key, chain, root CA, and certificate type. The new leaf
// must match the existing key. Airlock still receives the complete pair in one
// request, so no mismatched intermediate device state is possible.
func (c *Client) SyncLeafCertificate(ctx context.Context, target CertificateTarget, certificate Certificate, options SyncOptions) (SyncResult, error) {
	if err := validateTarget(target); err != nil {
		return SyncResult{}, err
	}
	if !certificate.valid() {
		return SyncResult{}, errors.New("certificate was not created by ParseCertificate")
	}
	transaction, err := c.StartConfigurationTransaction(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	result, err := transaction.SyncLeafCertificate(target, certificate, ReadOptions{PrivateKeyPassphrase: options.ExistingKeyPassphrase})
	if err != nil {
		return SyncResult{}, errors.Join(err, transaction.Abort())
	}
	if err := transaction.CommitWithOptions(options.ActivationComment, options.activationOptions()); err != nil {
		return SyncResult{}, err
	}
	return result, nil
}

// SyncKey replaces only the private key while retaining the currently
// configured certificate and CA material. It rejects a key that does not match
// the existing certificate before writing to the Gateway.
func (c *Client) SyncKey(ctx context.Context, target CertificateTarget, key Key, options SyncOptions) (SyncResult, error) {
	if err := validateTarget(target); err != nil {
		return SyncResult{}, err
	}
	if !key.valid() {
		return SyncResult{}, errors.New("key was not created by ParseKey or ParseEncryptedKey")
	}
	transaction, err := c.StartConfigurationTransaction(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	result, err := transaction.SyncKey(target, key, ReadOptions{PrivateKeyPassphrase: options.ExistingKeyPassphrase})
	if err != nil {
		return SyncResult{}, errors.Join(err, transaction.Abort())
	}
	if err := transaction.CommitWithOptions(options.ActivationComment, options.activationOptions()); err != nil {
		return SyncResult{}, err
	}
	return result, nil
}

// GetCertificate resolves and reads a certificate in an isolated Airlock REST
// session. No configuration is activated.
func (c *Client) GetCertificate(ctx context.Context, target CertificateTarget) (ManagedCertificate, error) {
	return c.GetCertificateWithOptions(ctx, target, ReadOptions{})
}

// GetCertificateWithOptions reads a certificate and uses a transient
// passphrase when its private key is encrypted on Airlock Gateway.
func (c *Client) GetCertificateWithOptions(ctx context.Context, target CertificateTarget, options ReadOptions) (ManagedCertificate, error) {
	if err := validateTarget(target); err != nil {
		return ManagedCertificate{}, err
	}
	transaction, err := c.StartConfigurationTransaction(ctx)
	if err != nil {
		return ManagedCertificate{}, err
	}
	certificate, err := transaction.GetCertificateWithOptions(target, options)
	return certificate, errors.Join(err, transaction.Abort())
}

// SyncCertificate stages one typed certificate/private-key unit in this
// transaction. Call Commit or Abort exactly once afterwards.
func (t *ConfigurationTransaction) SyncCertificate(target CertificateTarget, bundle CertificateBundle) (SyncResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.syncCertificateLocked(target, bundle)
}

// SyncLeafCertificate stages a leaf-only change while always writing a
// complete, locally matched certificate/private-key pair.
func (t *ConfigurationTransaction) SyncLeafCertificate(target CertificateTarget, certificate Certificate, options ReadOptions) (SyncResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return SyncResult{}, errors.New("configuration transaction is closed")
	}
	if err := validateTarget(target); err != nil {
		return SyncResult{}, err
	}
	if !certificate.valid() {
		return SyncResult{}, errors.New("certificate was not created by ParseCertificate")
	}
	current, _, err := t.resolveCertificate(target)
	if err != nil {
		return SyncResult{}, err
	}
	if current == nil {
		return SyncResult{}, errors.New("cannot synchronize only a leaf certificate because the target has no existing certificate and key")
	}
	managed, err := managedCertificateFromResource(*current, options.PrivateKeyPassphrase)
	if err != nil {
		return SyncResult{}, err
	}
	bundle, err := NewCertificateBundle(certificate, managed.Key, BundleOptions{
		Type: managed.Type, Chain: managed.Chain, RootCA: managed.RootCA,
	})
	if err != nil {
		return SyncResult{}, err
	}
	return t.syncCertificateLocked(target, bundle)
}

// SyncKey stages a key-only change while always writing a complete, locally
// matched certificate/private-key pair.
func (t *ConfigurationTransaction) SyncKey(target CertificateTarget, key Key, options ReadOptions) (SyncResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return SyncResult{}, errors.New("configuration transaction is closed")
	}
	if err := validateTarget(target); err != nil {
		return SyncResult{}, err
	}
	if !key.valid() {
		return SyncResult{}, errors.New("key was not created by ParseKey or ParseEncryptedKey")
	}
	current, _, err := t.resolveCertificate(target)
	if err != nil {
		return SyncResult{}, err
	}
	if current == nil {
		return SyncResult{}, errors.New("cannot synchronize only a key because the target has no existing certificate")
	}
	managed, err := managedCertificateFromResource(*current, options.PrivateKeyPassphrase)
	if err != nil {
		return SyncResult{}, err
	}
	bundle, err := NewCertificateBundle(managed.Certificate, key, BundleOptions{
		Type: managed.Type, Chain: managed.Chain, RootCA: managed.RootCA,
	})
	if err != nil {
		return SyncResult{}, err
	}
	return t.syncCertificateLocked(target, bundle)
}

func (t *ConfigurationTransaction) syncCertificateLocked(target CertificateTarget, bundle CertificateBundle) (SyncResult, error) {
	if t.closed {
		return SyncResult{}, errors.New("configuration transaction is closed")
	}
	if err := validateTarget(target); err != nil {
		return SyncResult{}, err
	}
	if err := bundle.validate(); err != nil {
		return SyncResult{}, err
	}

	current, virtualHost, err := t.resolveCertificate(target)
	if err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{VirtualHost: virtualHost}
	needsBinding := virtualHost != nil && virtualHost.CertificateID == nil
	if current != nil {
		managed, managedErr := managedCertificateFromResource(*current, bundle.Key.passphrase)
		if managedErr != nil && !encryptedPrivateKeyPEM(current.Attributes.PrivateKey) {
			return SyncResult{}, managedErr
		}
		currentID, err := parseCertificateID(current.ID)
		if err != nil {
			return SyncResult{}, err
		}
		if managedErr == nil {
			result.Certificate = managed
			if managed.Checksum == bundle.Checksum {
				return result, nil
			}
		}
		// Negative IDs are Airlock built-in/default entities. The Gateway
		// returns DEFAULT_ENTITY_MODIFICATION when they are patched. Create a
		// normal certificate and replace the Virtual Host binding instead.
		if currentID < 0 && virtualHost != nil {
			current = nil
			needsBinding = true
		}
	}

	attributes := attributesFromBundle(bundle)
	if current == nil {
		created, err := t.createCertificate(attributes)
		if err != nil {
			return SyncResult{}, err
		}
		if created.Attributes.Certificate == "" {
			created.Attributes = attributes
		} else if created.Attributes.Passphrase == "" {
			created.Attributes.Passphrase = attributes.Passphrase
		}
		current = &created
		result.Created = true
	} else {
		updated, err := t.updateCertificate(current.ID, attributes)
		if err != nil {
			return SyncResult{}, err
		}
		if updated.ID == "" {
			updated = Resource[sslCertificateAttributes]{
				Type:          current.Type,
				ID:            current.ID,
				Attributes:    attributes,
				Relationships: current.Relationships,
			}
		}
		if updated.Attributes.Certificate == "" {
			updated.Attributes = attributes
		} else if updated.Attributes.Passphrase == "" {
			updated.Attributes.Passphrase = attributes.Passphrase
		}
		current = &updated
	}

	if needsBinding {
		if err := t.client.ConnectSSLCertificateToVirtualHosts(t.ctx, current.ID, virtualHost.ID.String()); err != nil {
			return SyncResult{}, fmt.Errorf("bind certificate to virtual host %q: %w", virtualHost.Name, err)
		}
		certificateID, err := parseCertificateID(current.ID)
		if err != nil {
			return SyncResult{}, err
		}
		virtualHost.CertificateID = &certificateID
		result.Bound = true
	}

	managed, err := managedCertificateFromResource(*current, bundle.Key.passphrase)
	if err != nil {
		return SyncResult{}, err
	}
	result.Certificate = managed
	result.Changed = true
	t.changed = true
	return result, nil
}

// GetCertificate reads a typed certificate within this transaction.
func (t *ConfigurationTransaction) GetCertificate(target CertificateTarget) (ManagedCertificate, error) {
	return t.GetCertificateWithOptions(target, ReadOptions{})
}

// GetCertificateWithOptions reads typed state using a transient passphrase for
// encrypted keys.
func (t *ConfigurationTransaction) GetCertificateWithOptions(target CertificateTarget, options ReadOptions) (ManagedCertificate, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return ManagedCertificate{}, errors.New("configuration transaction is closed")
	}
	if err := validateTarget(target); err != nil {
		return ManagedCertificate{}, err
	}
	resource, _, err := t.resolveCertificate(target)
	if err != nil {
		return ManagedCertificate{}, err
	}
	if resource == nil {
		return ManagedCertificate{}, errors.New("target has no SSL certificate")
	}
	return managedCertificateFromResource(*resource, options.PrivateKeyPassphrase)
}

func validateTarget(target CertificateTarget) error {
	if target == nil {
		return errors.New("certificate target must not be nil")
	}
	switch value := target.(type) {
	case virtualHostTarget:
		if strings.TrimSpace(string(value.name)) == "" {
			return errors.New("virtual-host name must not be empty")
		}
	case certificateIDTarget:
		if value.id == 0 {
			return errors.New("certificate ID must not be zero")
		}
	default:
		return fmt.Errorf("unsupported certificate target %T", target)
	}
	return nil
}

func (t *ConfigurationTransaction) resolveCertificate(target CertificateTarget) (*Resource[sslCertificateAttributes], *VirtualHost, error) {
	switch value := target.(type) {
	case certificateIDTarget:
		resource, err := t.getCertificate(value.id)
		if err != nil {
			return nil, nil, err
		}
		return &resource, nil, nil
	case virtualHostTarget:
		virtualHost, err := t.getVirtualHostByName(value.name)
		if err != nil {
			return nil, nil, err
		}
		if virtualHost.CertificateID == nil {
			return nil, &virtualHost, nil
		}
		resource, err := t.getCertificate(*virtualHost.CertificateID)
		if err != nil {
			return nil, nil, fmt.Errorf("get certificate %s bound to virtual host %q: %w", virtualHost.CertificateID.String(), virtualHost.Name, err)
		}
		return &resource, &virtualHost, nil
	default:
		return nil, nil, fmt.Errorf("unsupported certificate target %T", target)
	}
}

func (t *ConfigurationTransaction) getVirtualHostByName(name VirtualHostName) (VirtualHost, error) {
	var document Document[[]Resource[virtualHostAttributes]]
	path := "/configuration/virtual-hosts?filter=" + url.QueryEscape("name=="+string(name))
	if err := t.client.DoJSON(t.ctx, http.MethodGet, path, nil, &document, http.StatusOK); err != nil {
		return VirtualHost{}, err
	}
	matches := make([]VirtualHost, 0, 1)
	for _, resource := range document.Data {
		if resource.Attributes.Name != string(name) {
			continue
		}
		virtualHost, err := virtualHostFromResource(resource)
		if err != nil {
			return VirtualHost{}, err
		}
		matches = append(matches, virtualHost)
	}
	if len(matches) == 0 {
		return VirtualHost{}, fmt.Errorf("virtual host %q not found on Airlock Gateway", name)
	}
	if len(matches) > 1 {
		return VirtualHost{}, fmt.Errorf("virtual host name %q is ambiguous on Airlock Gateway (%d matches)", name, len(matches))
	}
	return matches[0], nil
}

func virtualHostFromResource(resource Resource[virtualHostAttributes]) (VirtualHost, error) {
	id, err := parseVirtualHostID(resource.ID)
	if err != nil {
		return VirtualHost{}, err
	}
	certificateID, err := relationshipCertificateID(resource.Relationships["ssl-certificate"])
	if err != nil {
		return VirtualHost{}, fmt.Errorf("decode SSL certificate relationship for virtual host %q: %w", resource.Attributes.Name, err)
	}
	return VirtualHost{
		ID:            id,
		Name:          VirtualHostName(resource.Attributes.Name),
		HostName:      resource.Attributes.HostName,
		AliasNames:    append([]string(nil), resource.Attributes.AliasNames...),
		CertificateID: certificateID,
	}, nil
}

func relationshipCertificateID(relationship Relationship) (*CertificateID, error) {
	if relationship.Data == nil {
		return nil, nil
	}
	data, err := json.Marshal(relationship.Data)
	if err != nil {
		return nil, err
	}
	if string(data) == "null" || string(data) == "[]" {
		return nil, nil
	}
	var one ResourceIdentifier
	if err := json.Unmarshal(data, &one); err == nil && one.ID != "" {
		id, err := parseCertificateID(one.ID)
		return &id, err
	}
	var many []ResourceIdentifier
	if err := json.Unmarshal(data, &many); err != nil {
		return nil, errors.New("unexpected relationship representation")
	}
	if len(many) == 0 {
		return nil, nil
	}
	if len(many) > 1 {
		return nil, fmt.Errorf("virtual host has %d SSL certificates", len(many))
	}
	id, err := parseCertificateID(many[0].ID)
	return &id, err
}

func (t *ConfigurationTransaction) getCertificate(id CertificateID) (Resource[sslCertificateAttributes], error) {
	var document Document[Resource[sslCertificateAttributes]]
	path := "/configuration/ssl-certificates/" + url.PathEscape(id.String())
	if err := t.client.DoJSON(t.ctx, http.MethodGet, path, nil, &document, http.StatusOK); err != nil {
		return Resource[sslCertificateAttributes]{}, err
	}
	return document.Data, nil
}

func (t *ConfigurationTransaction) createCertificate(attributes sslCertificateAttributes) (Resource[sslCertificateAttributes], error) {
	body := Document[Resource[sslCertificateAttributes]]{Data: Resource[sslCertificateAttributes]{Type: SSLCertificateType, Attributes: attributes}}
	var document Document[Resource[sslCertificateAttributes]]
	if err := t.client.DoJSON(t.ctx, http.MethodPost, "/configuration/ssl-certificates", body, &document, http.StatusOK, http.StatusCreated); err != nil {
		return Resource[sslCertificateAttributes]{}, err
	}
	if _, err := parseCertificateID(document.Data.ID); err != nil {
		return Resource[sslCertificateAttributes]{}, fmt.Errorf("invalid certificate ID returned by Airlock Gateway: %w", err)
	}
	return document.Data, nil
}

func (t *ConfigurationTransaction) updateCertificate(id string, attributes sslCertificateAttributes) (Resource[sslCertificateAttributes], error) {
	body := Document[Resource[sslCertificateAttributes]]{Data: Resource[sslCertificateAttributes]{Type: SSLCertificateType, ID: id, Attributes: attributes}}
	var document Document[Resource[sslCertificateAttributes]]
	path := "/configuration/ssl-certificates/" + url.PathEscape(id)
	if err := t.client.DoJSON(t.ctx, http.MethodPatch, path, body, &document, http.StatusOK, http.StatusNoContent); err != nil {
		return Resource[sslCertificateAttributes]{}, err
	}
	return document.Data, nil
}

func attributesFromBundle(bundle CertificateBundle) sslCertificateAttributes {
	chain := make([]string, len(bundle.Chain))
	for i, item := range bundle.Chain {
		chain[i] = string(item.PEM())
	}
	root := ""
	if bundle.RootCA != nil {
		root = string(bundle.RootCA.PEM())
	}
	return sslCertificateAttributes{
		Certificate:       string(bundle.Certificate.PEM()),
		PrivateKey:        string(bundle.Key.PEM()),
		Passphrase:        string(bundle.Key.passphrase),
		CertificateChain:  chain,
		RootCACertificate: root,
		CertType:          string(bundle.Type),
	}
}

func managedCertificateFromResource(resource Resource[sslCertificateAttributes], passphrase []byte) (ManagedCertificate, error) {
	id, err := parseCertificateID(resource.ID)
	if err != nil {
		return ManagedCertificate{}, err
	}
	if len(passphrase) == 0 {
		passphrase = []byte(resource.Attributes.Passphrase)
	}
	input := CertificateBundleInput{
		Type:                 CertificateType(resource.Attributes.CertType),
		CertificatePEM:       []byte(resource.Attributes.Certificate),
		PrivateKeyPEM:        []byte(resource.Attributes.PrivateKey),
		PrivateKeyPassphrase: passphrase,
		RootCAPEM:            []byte(resource.Attributes.RootCACertificate),
	}
	for _, item := range resource.Attributes.CertificateChain {
		input.CertificateChainPEM = append(input.CertificateChainPEM, []byte(item))
	}
	bundle, err := ParseCertificateBundle(input)
	if err != nil {
		return ManagedCertificate{}, fmt.Errorf("decode Airlock SSL certificate %s: %w", resource.ID, err)
	}
	return ManagedCertificate{
		ID:          id,
		Type:        bundle.Type,
		Certificate: bundle.Certificate,
		Key:         bundle.Key,
		Chain:       bundle.Chain,
		RootCA:      bundle.RootCA,
		Checksum:    bundle.Checksum,
	}, nil
}

func encryptedPrivateKeyPEM(value string) bool {
	block, _ := pem.Decode([]byte(value))
	return block != nil && (block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] != "" || block.Headers["DEK-Info"] != "")
}

func parseCertificateID(value string) (CertificateID, error) {
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid Airlock certificate ID %q", value)
	}
	return CertificateID(id), nil
}

func parseVirtualHostID(value string) (VirtualHostID, error) {
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid Airlock virtual-host ID %q", value)
	}
	return VirtualHostID(id), nil
}
