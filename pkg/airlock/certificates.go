package airlock

import (
	"context"
	"net/http"
	"net/url"
)

const (
	// SSLCertificateType is the JSON:API resource type used by the Airlock Gateway configuration API.
	SSLCertificateType = "ssl-certificate"

	VirtualHostType  = "virtual-host"
	BackEndGroupType = "back-end-group"
	RemoteJWKSType   = "remote-jwks"
	NodeType         = "node"
)

// ListSSLCertificates returns all SSL certificate resources. filter may be empty or a Gateway filter expression.
func (c *Client) ListSSLCertificates(ctx context.Context, filter string) ([]ResourceAny, error) {
	path := "/configuration/ssl-certificates"
	if filter != "" {
		path += "?filter=" + url.QueryEscape(filter)
	}
	var doc Document[[]ResourceAny]
	if err := c.DoJSON(ctx, http.MethodGet, path, nil, &doc, http.StatusOK); err != nil {
		return nil, err
	}
	return doc.Data, nil
}

// GetSSLCertificate returns one SSL certificate resource by ID.
func (c *Client) GetSSLCertificate(ctx context.Context, id string) (ResourceAny, error) {
	var doc Document[ResourceAny]
	if err := c.DoJSON(ctx, http.MethodGet, "/configuration/ssl-certificates/"+url.PathEscape(id), nil, &doc, http.StatusOK); err != nil {
		return ResourceAny{}, err
	}
	return doc.Data, nil
}

// CreateSSLCertificate creates an SSL certificate resource from the supplied JSON:API attributes.
// Keep the attributes map aligned with the live Gateway OpenAPI schema for your Gateway version.
func (c *Client) CreateSSLCertificate(ctx context.Context, attrs map[string]any) (ResourceAny, error) {
	body := NewResourceDocument(SSLCertificateType, "", attrs)
	var doc Document[ResourceAny]
	if err := c.DoJSON(ctx, http.MethodPost, "/configuration/ssl-certificates", body, &doc, http.StatusOK, http.StatusCreated); err != nil {
		return ResourceAny{}, err
	}
	return doc.Data, nil
}

// UpdateSSLCertificate patches an SSL certificate resource by ID.
func (c *Client) UpdateSSLCertificate(ctx context.Context, id string, attrs map[string]any) (ResourceAny, error) {
	body := NewResourceDocument(SSLCertificateType, id, attrs)
	var doc Document[ResourceAny]
	if err := c.DoJSON(ctx, http.MethodPatch, "/configuration/ssl-certificates/"+url.PathEscape(id), body, &doc, http.StatusOK, http.StatusNoContent); err != nil {
		return ResourceAny{}, err
	}
	return doc.Data, nil
}

// DeleteSSLCertificate deletes an SSL certificate resource by ID.
func (c *Client) DeleteSSLCertificate(ctx context.Context, id string) error {
	return c.DoJSON(ctx, http.MethodDelete, "/configuration/ssl-certificates/"+url.PathEscape(id), nil, nil, http.StatusNoContent)
}

// AddSSLCertificateRelationship adds relationship connections from an SSL certificate to another resource collection.
func (c *Client) AddSSLCertificateRelationship(ctx context.Context, certID, relationship string, refs []ResourceIdentifier) error {
	body := NewRelationshipDocument(refs)
	path := "/configuration/ssl-certificates/" + url.PathEscape(certID) + "/relationships/" + url.PathEscape(relationship)
	return c.DoJSON(ctx, http.MethodPatch, path, body, nil, http.StatusNoContent)
}

// RemoveSSLCertificateRelationship removes relationship connections from an SSL certificate to another resource collection.
func (c *Client) RemoveSSLCertificateRelationship(ctx context.Context, certID, relationship string, refs []ResourceIdentifier) error {
	body := NewRelationshipDocument(refs)
	path := "/configuration/ssl-certificates/" + url.PathEscape(certID) + "/relationships/" + url.PathEscape(relationship)
	return c.DoJSON(ctx, http.MethodDelete, path, body, nil, http.StatusNoContent)
}

// ConnectSSLCertificateToVirtualHosts connects one SSL certificate to one or more virtual hosts.
func (c *Client) ConnectSSLCertificateToVirtualHosts(ctx context.Context, certID string, virtualHostIDs ...string) error {
	return c.AddSSLCertificateRelationship(ctx, certID, "virtual-hosts", identifiers(VirtualHostType, virtualHostIDs))
}

// DisconnectSSLCertificateFromVirtualHosts removes connections from one SSL certificate to one or more virtual hosts.
func (c *Client) DisconnectSSLCertificateFromVirtualHosts(ctx context.Context, certID string, virtualHostIDs ...string) error {
	return c.RemoveSSLCertificateRelationship(ctx, certID, "virtual-hosts", identifiers(VirtualHostType, virtualHostIDs))
}

// ConnectSSLCertificateToBackEndGroups connects one SSL certificate to one or more back-end groups.
func (c *Client) ConnectSSLCertificateToBackEndGroups(ctx context.Context, certID string, backEndGroupIDs ...string) error {
	return c.AddSSLCertificateRelationship(ctx, certID, "back-end-groups", identifiers(BackEndGroupType, backEndGroupIDs))
}

// DisconnectSSLCertificateFromBackEndGroups removes connections from one SSL certificate to one or more back-end groups.
func (c *Client) DisconnectSSLCertificateFromBackEndGroups(ctx context.Context, certID string, backEndGroupIDs ...string) error {
	return c.RemoveSSLCertificateRelationship(ctx, certID, "back-end-groups", identifiers(BackEndGroupType, backEndGroupIDs))
}

// ConnectSSLCertificateToRemoteJWKS connects one SSL certificate to one or more remote JWKS resources.
func (c *Client) ConnectSSLCertificateToRemoteJWKS(ctx context.Context, certID string, jwksIDs ...string) error {
	return c.AddSSLCertificateRelationship(ctx, certID, "remote-jwks", identifiers(RemoteJWKSType, jwksIDs))
}

// DisconnectSSLCertificateFromRemoteJWKS removes connections from one SSL certificate to one or more remote JWKS resources.
func (c *Client) DisconnectSSLCertificateFromRemoteJWKS(ctx context.Context, certID string, jwksIDs ...string) error {
	return c.RemoveSSLCertificateRelationship(ctx, certID, "remote-jwks", identifiers(RemoteJWKSType, jwksIDs))
}

// ConnectSSLCertificateToNodes connects one SSL certificate to one or more Gateway nodes.
func (c *Client) ConnectSSLCertificateToNodes(ctx context.Context, certID string, nodeIDs ...string) error {
	return c.AddSSLCertificateRelationship(ctx, certID, "nodes", identifiers(NodeType, nodeIDs))
}

// DisconnectSSLCertificateFromNodes removes connections from one SSL certificate to one or more Gateway nodes.
func (c *Client) DisconnectSSLCertificateFromNodes(ctx context.Context, certID string, nodeIDs ...string) error {
	return c.RemoveSSLCertificateRelationship(ctx, certID, "nodes", identifiers(NodeType, nodeIDs))
}

// AddVirtualHostCertificateRelationship adds SSL certificate connections on the virtual-host relationship endpoint.
func (c *Client) AddVirtualHostCertificateRelationship(ctx context.Context, virtualHostID string, certIDs ...string) error {
	body := NewRelationshipDocument(identifiers(SSLCertificateType, certIDs))
	path := "/configuration/virtual-hosts/" + url.PathEscape(virtualHostID) + "/relationships/ssl-certificate"
	return c.DoJSON(ctx, http.MethodPatch, path, body, nil, http.StatusNoContent)
}

// RemoveVirtualHostCertificateRelationship removes SSL certificate connections on the virtual-host relationship endpoint.
func (c *Client) RemoveVirtualHostCertificateRelationship(ctx context.Context, virtualHostID string, certIDs ...string) error {
	body := NewRelationshipDocument(identifiers(SSLCertificateType, certIDs))
	path := "/configuration/virtual-hosts/" + url.PathEscape(virtualHostID) + "/relationships/ssl-certificate"
	return c.DoJSON(ctx, http.MethodDelete, path, body, nil, http.StatusNoContent)
}

func identifiers(resourceType string, ids []string) []ResourceIdentifier {
	items := make([]ResourceIdentifier, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		items = append(items, ResourceIdentifier{Type: resourceType, ID: id})
	}
	return items
}
