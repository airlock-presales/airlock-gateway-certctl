package airlock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	// SSLCertificateType is the JSON:API resource type used by Airlock Gateway.
	SSLCertificateType = "ssl-certificate"

	VirtualHostType  = "virtual-host"
	BackEndGroupType = "back-end-group"
	RemoteJWKSType   = "json-web-key-set-remote"
	NodeType         = "node"
)

// BackEndGroupID is the numeric identifier of an Airlock back-end group.
type BackEndGroupID int64

// String returns the JSON:API string representation of the ID.
func (id BackEndGroupID) String() string { return strconv.FormatInt(int64(id), 10) }

// RemoteJWKSID is the numeric identifier of a remote JSON Web Key Set.
type RemoteJWKSID int64

// String returns the JSON:API string representation of the ID.
func (id RemoteJWKSID) String() string { return strconv.FormatInt(int64(id), 10) }

// NodeID is the numeric identifier of an Airlock Gateway node.
type NodeID int64

// String returns the JSON:API string representation of the ID.
func (id NodeID) String() string { return strconv.FormatInt(int64(id), 10) }

// CertificateRelationship identifies one of the relationship collections
// supported by an Airlock 8.6 ssl-certificate resource.
type CertificateRelationship string

const (
	// CertificateVirtualHosts identifies certificate-to-virtual-host links.
	CertificateVirtualHosts CertificateRelationship = "virtual-hosts"
	// CertificateBackEndGroups identifies certificate-to-back-end-group links.
	CertificateBackEndGroups CertificateRelationship = "back-end-groups"
	// CertificateRemoteJWKS identifies certificate-to-remote-JWKS links.
	CertificateRemoteJWKS CertificateRelationship = "json-web-key-sets/remotes"
	// CertificateNodes identifies certificate-to-node links.
	CertificateNodes CertificateRelationship = "nodes"
)

func (relationship CertificateRelationship) resourceType() (string, error) {
	switch relationship {
	case CertificateVirtualHosts:
		return VirtualHostType, nil
	case CertificateBackEndGroups:
		return BackEndGroupType, nil
	case CertificateRemoteJWKS:
		return RemoteJWKSType, nil
	case CertificateNodes:
		return NodeType, nil
	default:
		return "", fmt.Errorf("unsupported SSL certificate relationship %q", relationship)
	}
}

// SSLCertificateAttributes is the typed Airlock 8.6 wire representation used
// by create and patch operations. Pointers preserve PATCH semantics: nil means
// absent, while a pointer to an empty value explicitly clears that attribute.
// For validated certificate/key synchronization, prefer SyncCertificate.
type SSLCertificateAttributes struct {
	CertType          *CertificateType `json:"certType,omitempty"`
	Certificate       *string          `json:"certificate,omitempty"`
	CertificateChain  *[]string        `json:"certificateChain,omitempty"`
	Passphrase        *string          `json:"passphrase,omitempty"`
	PrivateKey        *string          `json:"privateKey,omitempty"`
	RootCACertificate *string          `json:"rootCaCertificate,omitempty"`
}

// UnmarshalJSON rejects attributes outside the closed Airlock 8.6 schema.
// This turns an appliance-side schema change into an explicit contract error
// instead of silently discarding fields.
func (attributes *SSLCertificateAttributes) UnmarshalJSON(data []byte) error {
	type attributesAlias SSLCertificateAttributes
	var decoded attributesAlias
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("decode SSL certificate attributes: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("decode SSL certificate attributes: multiple JSON values")
		}
		return fmt.Errorf("decode SSL certificate attributes: %w", err)
	}
	*attributes = SSLCertificateAttributes(decoded)
	return nil
}

// Validate checks the closed Airlock 8.6 attribute contract without parsing
// PEM material. Use ParseCertificateBundle when cryptographic validation is
// required.
func (attributes SSLCertificateAttributes) Validate() error {
	if err := attributes.validateIfPresent(); err != nil {
		return err
	}
	if attributes.Certificate == nil && attributes.CertificateChain == nil &&
		attributes.Passphrase == nil && attributes.PrivateKey == nil &&
		attributes.RootCACertificate == nil && attributes.CertType == nil {
		return errors.New("SSL certificate attributes must contain at least one field")
	}
	return nil
}

func (attributes SSLCertificateAttributes) validateIfPresent() error {
	if attributes.CertType != nil {
		return attributes.CertType.validate()
	}
	return nil
}

// SSLCertificateResource is the typed JSON:API resource returned by normal
// certificate CRUD methods. Relationship names are a closed enum and IDs are
// parsed before a response reaches the caller.
type SSLCertificateResource struct {
	Type          string                                   `json:"type"`
	ID            CertificateID                            `json:"-"`
	Attributes    SSLCertificateAttributes                 `json:"attributes,omitempty"`
	Relationships map[CertificateRelationship]Relationship `json:"relationships,omitempty"`
	Links         map[string]any                           `json:"links,omitempty"`
	Meta          map[string]any                           `json:"meta,omitempty"`
}

type sslCertificateResourceWire struct {
	Type          string                                   `json:"type"`
	ID            string                                   `json:"id,omitempty"`
	Attributes    SSLCertificateAttributes                 `json:"attributes,omitempty"`
	Relationships map[CertificateRelationship]Relationship `json:"relationships,omitempty"`
	Links         map[string]any                           `json:"links,omitempty"`
	Meta          map[string]any                           `json:"meta,omitempty"`
}

func (resource *SSLCertificateResource) UnmarshalJSON(data []byte) error {
	var wire sslCertificateResourceWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.Type != "" && wire.Type != SSLCertificateType {
		return fmt.Errorf("unexpected JSON:API resource type %q, want %q", wire.Type, SSLCertificateType)
	}
	if err := wire.Attributes.validateIfPresent(); err != nil {
		return err
	}
	for relationship := range wire.Relationships {
		if _, err := relationship.resourceType(); err != nil {
			return err
		}
	}
	var id CertificateID
	if wire.ID != "" {
		parsed, err := ParseCertificateID(wire.ID)
		if err != nil {
			return err
		}
		id = parsed
	}
	*resource = SSLCertificateResource{
		Type:          wire.Type,
		ID:            id,
		Attributes:    wire.Attributes,
		Relationships: wire.Relationships,
		Links:         wire.Links,
		Meta:          wire.Meta,
	}
	return nil
}

func (resource SSLCertificateResource) MarshalJSON() ([]byte, error) {
	id := ""
	if resource.ID != 0 {
		id = resource.ID.String()
	}
	return json.Marshal(sslCertificateResourceWire{
		Type:          resource.Type,
		ID:            id,
		Attributes:    resource.Attributes,
		Relationships: resource.Relationships,
		Links:         resource.Links,
		Meta:          resource.Meta,
	})
}

// ListSSLCertificatesOptions controls certificate listing. RawFilter is kept
// explicit because Airlock's complete filter grammar is appliance-defined.
type ListSSLCertificatesOptions struct {
	Type      *CertificateType
	RawFilter string
}

func (options ListSSLCertificatesOptions) filter() (string, error) {
	raw := strings.TrimSpace(options.RawFilter)
	if options.Type != nil && raw != "" {
		return "", errors.New("certificate type and raw filter cannot be combined")
	}
	if options.Type != nil {
		if err := options.Type.validate(); err != nil {
			return "", err
		}
		return "certType==" + string(*options.Type), nil
	}
	return raw, nil
}

// ListSSLCertificates returns typed SSL certificate resources.
func (c *Client) ListSSLCertificates(ctx context.Context, options ListSSLCertificatesOptions) ([]SSLCertificateResource, error) {
	filter, err := options.filter()
	if err != nil {
		return nil, err
	}
	path := "/configuration/ssl-certificates"
	if filter != "" {
		path += "?filter=" + url.QueryEscape(filter)
	}
	var document Document[[]SSLCertificateResource]
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &document, http.StatusOK); err != nil {
		return nil, err
	}
	return document.Data, nil
}

// GetSSLCertificate returns one typed SSL certificate resource.
func (c *Client) GetSSLCertificate(ctx context.Context, id CertificateID) (SSLCertificateResource, error) {
	if err := validateCertificateID(id); err != nil {
		return SSLCertificateResource{}, err
	}
	var document Document[SSLCertificateResource]
	if err := c.doJSON(ctx, http.MethodGet, "/configuration/ssl-certificates/"+url.PathEscape(id.String()), nil, &document, http.StatusOK); err != nil {
		return SSLCertificateResource{}, err
	}
	return document.Data, nil
}

// CreateSSLCertificate creates a typed SSL certificate resource. It validates
// the wire shape, but callers wanting local PEM/key validation should use
// ParseCertificateBundle and SyncCertificate.
func (c *Client) CreateSSLCertificate(ctx context.Context, attributes SSLCertificateAttributes) (SSLCertificateResource, error) {
	if err := attributes.Validate(); err != nil {
		return SSLCertificateResource{}, err
	}
	body := NewResourceDocument(SSLCertificateType, "", attributes)
	var document Document[SSLCertificateResource]
	if err := c.doJSON(ctx, http.MethodPost, "/configuration/ssl-certificates", body, &document, http.StatusOK, http.StatusCreated); err != nil {
		return SSLCertificateResource{}, err
	}
	return document.Data, nil
}

// UpdateSSLCertificate patches a typed SSL certificate resource. Nil fields
// are omitted and pointers to empty values explicitly clear attributes.
func (c *Client) UpdateSSLCertificate(ctx context.Context, id CertificateID, attributes SSLCertificateAttributes) (SSLCertificateResource, error) {
	if err := validateCertificateID(id); err != nil {
		return SSLCertificateResource{}, err
	}
	if err := attributes.Validate(); err != nil {
		return SSLCertificateResource{}, err
	}
	body := NewResourceDocument(SSLCertificateType, id.String(), attributes)
	var document Document[SSLCertificateResource]
	if err := c.doJSON(ctx, http.MethodPatch, "/configuration/ssl-certificates/"+url.PathEscape(id.String()), body, &document, http.StatusOK, http.StatusNoContent); err != nil {
		return SSLCertificateResource{}, err
	}
	return document.Data, nil
}

// DeleteSSLCertificate deletes an SSL certificate resource.
func (c *Client) DeleteSSLCertificate(ctx context.Context, id CertificateID) error {
	if err := validateCertificateID(id); err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, "/configuration/ssl-certificates/"+url.PathEscape(id.String()), nil, nil, http.StatusNoContent)
}

// ConnectSSLCertificateRelationship is the typed generic relationship escape
// hatch. Prefer the target-specific methods below in application code.
func (c *Client) ConnectSSLCertificateRelationship(ctx context.Context, certificateID CertificateID, relationship CertificateRelationship, refs []ResourceIdentifier) error {
	return c.changeSSLCertificateRelationship(ctx, http.MethodPatch, certificateID, relationship, refs)
}

// DisconnectSSLCertificateRelationship removes typed relationship targets.
func (c *Client) DisconnectSSLCertificateRelationship(ctx context.Context, certificateID CertificateID, relationship CertificateRelationship, refs []ResourceIdentifier) error {
	return c.changeSSLCertificateRelationship(ctx, http.MethodDelete, certificateID, relationship, refs)
}

func (c *Client) changeSSLCertificateRelationship(ctx context.Context, method string, certificateID CertificateID, relationship CertificateRelationship, refs []ResourceIdentifier) error {
	if err := validateCertificateID(certificateID); err != nil {
		return err
	}
	resourceType, err := relationship.resourceType()
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		return errors.New("at least one relationship target is required")
	}
	for _, ref := range refs {
		if ref.Type != resourceType || strings.TrimSpace(ref.ID) == "" {
			return fmt.Errorf("invalid %s relationship target %#v", relationship, ref)
		}
		if _, err := parsePositiveID(string(relationship), ref.ID); err != nil {
			return err
		}
	}
	body := NewRelationshipDocument(refs)
	path := "/configuration/ssl-certificates/" + url.PathEscape(certificateID.String()) + "/relationships/" + string(relationship)
	return c.doJSON(ctx, method, path, body, nil, http.StatusNoContent)
}

// ConnectSSLCertificateToVirtualHosts connects a certificate to virtual hosts.
func (c *Client) ConnectSSLCertificateToVirtualHosts(ctx context.Context, certificateID CertificateID, virtualHostIDs ...VirtualHostID) error {
	return c.ConnectSSLCertificateRelationship(ctx, certificateID, CertificateVirtualHosts, virtualHostIdentifiers(virtualHostIDs))
}

// DisconnectSSLCertificateFromVirtualHosts disconnects a certificate from virtual hosts.
func (c *Client) DisconnectSSLCertificateFromVirtualHosts(ctx context.Context, certificateID CertificateID, virtualHostIDs ...VirtualHostID) error {
	return c.DisconnectSSLCertificateRelationship(ctx, certificateID, CertificateVirtualHosts, virtualHostIdentifiers(virtualHostIDs))
}

// ConnectSSLCertificateToBackEndGroups connects a certificate to back-end groups.
func (c *Client) ConnectSSLCertificateToBackEndGroups(ctx context.Context, certificateID CertificateID, ids ...BackEndGroupID) error {
	return c.ConnectSSLCertificateRelationship(ctx, certificateID, CertificateBackEndGroups, backEndGroupIdentifiers(ids))
}

// DisconnectSSLCertificateFromBackEndGroups disconnects a certificate from back-end groups.
func (c *Client) DisconnectSSLCertificateFromBackEndGroups(ctx context.Context, certificateID CertificateID, ids ...BackEndGroupID) error {
	return c.DisconnectSSLCertificateRelationship(ctx, certificateID, CertificateBackEndGroups, backEndGroupIdentifiers(ids))
}

// ConnectSSLCertificateToRemoteJWKS connects a certificate to remote JSON Web Key Sets.
func (c *Client) ConnectSSLCertificateToRemoteJWKS(ctx context.Context, certificateID CertificateID, ids ...RemoteJWKSID) error {
	return c.ConnectSSLCertificateRelationship(ctx, certificateID, CertificateRemoteJWKS, remoteJWKSIdentifiers(ids))
}

// DisconnectSSLCertificateFromRemoteJWKS disconnects a certificate from remote JSON Web Key Sets.
func (c *Client) DisconnectSSLCertificateFromRemoteJWKS(ctx context.Context, certificateID CertificateID, ids ...RemoteJWKSID) error {
	return c.DisconnectSSLCertificateRelationship(ctx, certificateID, CertificateRemoteJWKS, remoteJWKSIdentifiers(ids))
}

// ConnectSSLCertificateToNodes connects a certificate to Gateway nodes.
func (c *Client) ConnectSSLCertificateToNodes(ctx context.Context, certificateID CertificateID, ids ...NodeID) error {
	return c.ConnectSSLCertificateRelationship(ctx, certificateID, CertificateNodes, nodeIdentifiers(ids))
}

// DisconnectSSLCertificateFromNodes disconnects a certificate from Gateway nodes.
func (c *Client) DisconnectSSLCertificateFromNodes(ctx context.Context, certificateID CertificateID, ids ...NodeID) error {
	return c.DisconnectSSLCertificateRelationship(ctx, certificateID, CertificateNodes, nodeIdentifiers(ids))
}

// AddVirtualHostCertificateRelationship sets the to-one SSL certificate
// relationship exposed by an Airlock 8.6 virtual host.
func (c *Client) AddVirtualHostCertificateRelationship(ctx context.Context, virtualHostID VirtualHostID, certificateID CertificateID) error {
	if err := validatePositiveID("virtual-host", int64(virtualHostID)); err != nil {
		return err
	}
	if err := validateCertificateID(certificateID); err != nil {
		return err
	}
	body := Document[ResourceIdentifier]{Data: ResourceIdentifier{Type: SSLCertificateType, ID: certificateID.String()}}
	path := "/configuration/virtual-hosts/" + url.PathEscape(virtualHostID.String()) + "/relationships/ssl-certificate"
	return c.doJSON(ctx, http.MethodPatch, path, body, nil, http.StatusNoContent)
}

// RemoveVirtualHostCertificateRelationship removes the to-one SSL certificate
// relationship exposed by an Airlock 8.6 virtual host.
func (c *Client) RemoveVirtualHostCertificateRelationship(ctx context.Context, virtualHostID VirtualHostID, certificateID CertificateID) error {
	if err := validatePositiveID("virtual-host", int64(virtualHostID)); err != nil {
		return err
	}
	if err := validateCertificateID(certificateID); err != nil {
		return err
	}
	body := Document[ResourceIdentifier]{Data: ResourceIdentifier{Type: SSLCertificateType, ID: certificateID.String()}}
	path := "/configuration/virtual-hosts/" + url.PathEscape(virtualHostID.String()) + "/relationships/ssl-certificate"
	return c.doJSON(ctx, http.MethodDelete, path, body, nil, http.StatusNoContent)
}

func validateCertificateID(id CertificateID) error {
	if id == 0 {
		return errors.New("certificate ID must not be zero")
	}
	return nil
}

func validatePositiveID(name string, id int64) error {
	if id <= 0 {
		return fmt.Errorf("%s ID must be positive", name)
	}
	return nil
}

func parsePositiveID(name, value string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid %s ID %q", name, value)
	}
	return id, nil
}

// ParseBackEndGroupID parses and validates a positive back-end-group ID.
func ParseBackEndGroupID(value string) (BackEndGroupID, error) {
	id, err := parsePositiveID("back-end-group", value)
	return BackEndGroupID(id), err
}

// ParseRemoteJWKSID parses and validates a positive remote-JWKS ID.
func ParseRemoteJWKSID(value string) (RemoteJWKSID, error) {
	id, err := parsePositiveID("remote JWKS", value)
	return RemoteJWKSID(id), err
}

// ParseNodeID parses and validates a positive Gateway node ID.
func ParseNodeID(value string) (NodeID, error) {
	id, err := parsePositiveID("node", value)
	return NodeID(id), err
}

func virtualHostIdentifiers(ids []VirtualHostID) []ResourceIdentifier {
	items := make([]ResourceIdentifier, 0, len(ids))
	for _, id := range ids {
		items = append(items, ResourceIdentifier{Type: VirtualHostType, ID: id.String()})
	}
	return items
}

func backEndGroupIdentifiers(ids []BackEndGroupID) []ResourceIdentifier {
	items := make([]ResourceIdentifier, 0, len(ids))
	for _, id := range ids {
		items = append(items, ResourceIdentifier{Type: BackEndGroupType, ID: id.String()})
	}
	return items
}

func remoteJWKSIdentifiers(ids []RemoteJWKSID) []ResourceIdentifier {
	items := make([]ResourceIdentifier, 0, len(ids))
	for _, id := range ids {
		items = append(items, ResourceIdentifier{Type: RemoteJWKSType, ID: id.String()})
	}
	return items
}

func nodeIdentifiers(ids []NodeID) []ResourceIdentifier {
	items := make([]ResourceIdentifier, 0, len(ids))
	for _, id := range ids {
		items = append(items, ResourceIdentifier{Type: NodeType, ID: id.String()})
	}
	return items
}
