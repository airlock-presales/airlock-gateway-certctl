package airlock

import "encoding/json"

// Document is a small JSON:API envelope used by the Airlock Gateway configuration API.
type Document[T any] struct {
	Data     T                 `json:"data,omitempty"`
	Included []json.RawMessage `json:"included,omitempty"`
	Errors   []APIErrorBody    `json:"errors,omitempty"`
	Meta     map[string]any    `json:"meta,omitempty"`
}

// Resource represents a JSON:API resource with typed attributes.
type Resource[A any] struct {
	Type          string                  `json:"type"`
	ID            string                  `json:"id,omitempty"`
	Attributes    A                       `json:"attributes,omitempty"`
	Relationships map[string]Relationship `json:"relationships,omitempty"`
	Links         map[string]any          `json:"links,omitempty"`
	Meta          map[string]any          `json:"meta,omitempty"`
}

// ResourceAny is a JSON:API resource using untyped attributes. It exists for
// callers of Client.Raw only. Normal certificate operations use
// SSLCertificateResource and never return ResourceAny.
type ResourceAny = Resource[map[string]any]

// Relationship is a JSON:API relationship whose data is decoded explicitly by
// the typed resource owning it. RawMessage avoids propagating any-typed data
// through the normal certificate API.
type Relationship struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Links map[string]any  `json:"links,omitempty"`
	Meta  map[string]any  `json:"meta,omitempty"`
}

// ResourceIdentifier is the minimal JSON:API object used in relationship endpoints.
type ResourceIdentifier struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// APIErrorBody models JSON:API error objects when the Gateway returns them.
type APIErrorBody struct {
	ID     string         `json:"id,omitempty"`
	Status string         `json:"status,omitempty"`
	Code   string         `json:"code,omitempty"`
	Title  string         `json:"title,omitempty"`
	Detail string         `json:"detail,omitempty"`
	Source map[string]any `json:"source,omitempty"`
	Meta   map[string]any `json:"meta,omitempty"`
}

// NewResourceDocument wraps typed attributes in the JSON:API envelope expected
// by create and update operations.
func NewResourceDocument[A any](resourceType, id string, attrs A) Document[Resource[A]] {
	return Document[Resource[A]]{
		Data: Resource[A]{
			Type:       resourceType,
			ID:         id,
			Attributes: attrs,
		},
	}
}

// NewRelationshipDocument wraps resource identifiers for relationship PATCH/DELETE calls.
func NewRelationshipDocument(items []ResourceIdentifier) Document[[]ResourceIdentifier] {
	return Document[[]ResourceIdentifier]{Data: items}
}
