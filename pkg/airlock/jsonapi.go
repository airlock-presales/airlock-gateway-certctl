package airlock

// Document is a small JSON:API envelope used by the Airlock Gateway configuration API.
type Document[T any] struct {
	Data     T              `json:"data,omitempty"`
	Included []ResourceAny  `json:"included,omitempty"`
	Errors   []APIErrorBody `json:"errors,omitempty"`
	Meta     map[string]any `json:"meta,omitempty"`
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

// ResourceAny is a JSON:API resource using untyped attributes.
type ResourceAny = Resource[map[string]any]

// Relationship is intentionally generic because Airlock exposes many relationship shapes.
type Relationship struct {
	Data  any            `json:"data,omitempty"`
	Links map[string]any `json:"links,omitempty"`
	Meta  map[string]any `json:"meta,omitempty"`
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

// NewResourceDocument wraps attributes in the JSON:API document/resource envelope expected by create/update calls.
func NewResourceDocument(resourceType, id string, attrs map[string]any) Document[ResourceAny] {
	return Document[ResourceAny]{
		Data: ResourceAny{
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
