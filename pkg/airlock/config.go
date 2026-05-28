package airlock

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// CreateSession creates an authenticated Gateway REST session using the configured API key.
func (c *Client) CreateSession(ctx context.Context) error {
	return c.DoJSON(ctx, http.MethodPost, "/session/create", nil, nil, http.StatusOK)
}

// TerminateSession terminates the current Gateway REST session.
func (c *Client) TerminateSession(ctx context.Context) error {
	return c.DoJSON(ctx, http.MethodPost, "/session/terminate", nil, nil, http.StatusOK)
}

// CreateSessionAndLoadActiveConfiguration creates an authenticated Gateway REST session
// and immediately loads the currently active configuration for editing/reading.
//
// Airlock Gateway configuration endpoints require a configuration to be loaded in
// the session first. This helper mirrors the common Python usage pattern:
// create_session(...); load_active_config(...). If loading the active configuration
// fails, the helper best-effort terminates the session before returning the error.
func (c *Client) CreateSessionAndLoadActiveConfiguration(ctx context.Context) error {
	if err := c.CreateSession(ctx); err != nil {
		return err
	}
	if err := c.LoadActiveConfiguration(ctx); err != nil {
		_ = c.TerminateSession(ctx)
		return err
	}
	return nil
}

// Version returns the Gateway version from /system/status/node when available.
func (c *Client) Version(ctx context.Context) (string, error) {
	var doc Document[ResourceAny]
	if err := c.DoJSON(ctx, http.MethodGet, "/system/status/node", nil, &doc, http.StatusOK); err != nil {
		return "", err
	}
	if doc.Data.Attributes == nil {
		return "", nil
	}
	version, _ := doc.Data.Attributes["version"].(string)
	return version, nil
}

// LoadConfiguration loads a saved configuration by ID. hostName may be empty for the Gateway default.
func (c *Client) LoadConfiguration(ctx context.Context, configID, hostName string) error {
	body := map[string]any{}
	if hostName != "" {
		body["hostname"] = hostName
	}
	return c.DoJSON(ctx, http.MethodPost, "/configuration/configurations/"+url.PathEscape(configID)+"/load", body, nil, http.StatusNoContent)
}

// LoadEmptyConfiguration loads an empty configuration. hostName may be empty for the Gateway default.
func (c *Client) LoadEmptyConfiguration(ctx context.Context, hostName string) error {
	body := map[string]any{}
	if hostName != "" {
		body["hostname"] = hostName
	}
	return c.DoJSON(ctx, http.MethodPost, "/configuration/configurations/load-empty-config", body, nil, http.StatusNoContent)
}

// LoadActiveConfiguration loads the currently active configuration for editing.
func (c *Client) LoadActiveConfiguration(ctx context.Context) error {
	return c.DoJSON(ctx, http.MethodPost, "/configuration/configurations/load-active", nil, nil, http.StatusNoContent)
}

// SaveConfiguration saves the currently loaded configuration and returns the saved configuration ID.
func (c *Client) SaveConfiguration(ctx context.Context, comment string) (string, error) {
	var body any
	if comment != "" {
		body = map[string]any{"comment": comment}
	}
	var doc Document[ResourceAny]
	if err := c.DoJSON(ctx, http.MethodPost, "/configuration/configurations/save", body, &doc, http.StatusOK); err != nil {
		return "", err
	}
	return doc.Data.ID, nil
}

// ValidationMessage contains one Gateway validation error/warning message.
type ValidationMessage struct {
	ID       string
	Severity string
	Detail   string
	Raw      ResourceAny
}

// Validate returns Gateway validator messages with severity ERROR.
func (c *Client) Validate(ctx context.Context) ([]ValidationMessage, error) {
	var doc Document[[]ResourceAny]
	path := "/configuration/validator-messages?filter=" + url.QueryEscape("meta.severity==ERROR")
	if err := c.DoJSON(ctx, http.MethodGet, path, nil, &doc, http.StatusOK); err != nil {
		return nil, err
	}

	messages := make([]ValidationMessage, 0, len(doc.Data))
	for _, item := range doc.Data {
		msg := ValidationMessage{ID: item.ID, Raw: item}
		if item.Meta != nil {
			msg.Severity, _ = item.Meta["severity"].(string)
		}
		if item.Attributes != nil {
			msg.Detail, _ = item.Attributes["detail"].(string)
		}
		messages = append(messages, msg)
	}
	return messages, nil
}

// ActivateConfiguration validates and activates the currently loaded configuration.
func (c *Client) ActivateConfiguration(ctx context.Context, comment string) error {
	var body any
	if comment != "" {
		body = map[string]any{
			"comment": comment,
			"options": map[string]any{
				"ignoreOutdatedConfiguration": true,
				"failoverActivation":          false,
			},
		}
	}
	return c.DoJSON(ctx, http.MethodPost, "/configuration/configurations/activate", body, nil, http.StatusOK)
}

// DownloadOpenAPISpec downloads the live OpenAPI spec exposed by the Gateway Configuration Center.
// format must be "json" or "yaml".
func (c *Client) DownloadOpenAPISpec(ctx context.Context, format string) ([]byte, error) {
	path := "/v3/api-docs"
	switch format {
	case "", "json":
		// default path is JSON
	case "yaml", "yml":
		path += ".yaml"
	default:
		return nil, fmt.Errorf("unsupported OpenAPI format %q", format)
	}

	var buf bytes.Buffer
	if err := c.DoRaw(ctx, http.MethodGet, path, "", nil, &buf, http.StatusOK); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
