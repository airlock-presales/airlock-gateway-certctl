package airlock

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultUserAgent = "airlock-certctl/0.1"

var (
	// ErrAuthentication identifies HTTP 401 and 403 Gateway responses.
	ErrAuthentication = errors.New("Airlock Gateway authentication failed")
	// ErrNotFound identifies an absent Gateway resource.
	ErrNotFound = errors.New("Airlock Gateway resource not found")
	// ErrConflict identifies an appliance-side configuration conflict.
	ErrConflict = errors.New("Airlock Gateway configuration conflict")
)

// Error represents a non-expected HTTP response from Airlock Gateway.
type Error struct {
	StatusCode int
	Body       string
	Errors     []APIErrorBody
	Meta       map[string]any
}

func (e *Error) Error() string {
	details := make([]string, 0, len(e.Errors))
	for _, item := range e.Errors {
		parts := make([]string, 0, 2)
		if item.Code != "" {
			parts = append(parts, item.Code)
		}
		if item.Title != "" {
			parts = append(parts, item.Title)
		}
		if len(parts) != 0 {
			details = append(details, strings.Join(parts, ": "))
		}
	}
	if len(details) != 0 {
		return fmt.Sprintf("airlock REST API returned HTTP %d (%s)", e.StatusCode, strings.Join(details, "; "))
	}
	// Never include the raw response body in Error(): an appliance may echo a
	// rejected request containing a private key or passphrase. Body remains
	// available to callers that deliberately need diagnostic details.
	return fmt.Sprintf("airlock REST API returned HTTP %d", e.StatusCode)
}

// Is supports errors.Is with ErrAuthentication, ErrNotFound, and ErrConflict.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrAuthentication:
		return e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound
	case ErrConflict:
		return e.StatusCode == http.StatusConflict
	default:
		return false
	}
}

// IsNotFound reports whether err is an Airlock 404 response.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsAuthentication reports whether Airlock rejected the configured API key.
func IsAuthentication(err error) bool {
	return errors.Is(err, ErrAuthentication)
}

// IsConflict reports whether Airlock rejected an operation because of a
// conflict, including activation of an outdated configuration working copy.
func IsConflict(err error) bool {
	return errors.Is(err, ErrConflict)
}

func newResponseError(statusCode int, data []byte) *Error {
	result := &Error{StatusCode: statusCode, Body: string(data)}
	var document struct {
		Errors []APIErrorBody `json:"errors"`
		Meta   map[string]any `json:"meta"`
	}
	if json.Unmarshal(data, &document) == nil {
		result.Errors = document.Errors
		result.Meta = document.Meta
	}
	return result
}

// Client provides typed Airlock Gateway certificate lifecycle operations.
// Low-level JSON:API methods are also available as an advanced escape hatch.
type Client struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
	userAgent  string
}

// RawClient exposes the untyped transport escape hatch. Prefer the typed
// methods on Client for supported Gateway operations; RawClient is intended
// for endpoints that are not yet part of the release contract.
type RawClient struct {
	client *Client
}

// Raw returns an explicitly untyped view of the client.
func (c *Client) Raw() *RawClient { return &RawClient{client: c} }

// Option customizes a Client.
type Option func(*Client) error

// WithHTTPClient installs a custom HTTP client. The caller is responsible for cookies and TLS settings.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) error {
		if httpClient == nil {
			return errors.New("http client must not be nil")
		}
		c.httpClient = httpClient
		return nil
	}
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) error {
		if timeout <= 0 {
			return errors.New("timeout must be positive")
		}
		c.httpClient.Timeout = timeout
		return nil
	}
}

// WithUserAgent overrides the default user agent.
func WithUserAgent(userAgent string) Option {
	return func(c *Client) error {
		if strings.TrimSpace(userAgent) == "" {
			return errors.New("user agent must not be empty")
		}
		c.userAgent = userAgent
		return nil
	}
}

// WithInsecureSkipVerify disables TLS certificate verification.
// Use this only for lab systems or when the management interface uses a temporary self-signed certificate.
func WithInsecureSkipVerify() Option {
	return func(c *Client) error {
		transport, err := cloneHTTPTransport(c.httpClient.Transport)
		if err != nil {
			return err
		}
		tlsConfig := cloneTLSConfig(transport.TLSClientConfig)
		tlsConfig.InsecureSkipVerify = true //nolint:gosec
		transport.TLSClientConfig = tlsConfig
		c.httpClient.Transport = transport
		return nil
	}
}

// WithTrustedCertificate adds a PEM encoded CA certificate to the TLS trust
// store. trustedCertificate may contain PEM data directly or name a PEM file.
func WithTrustedCertificate(trustedCertificate string) Option {
	return func(c *Client) error {
		value := strings.TrimSpace(trustedCertificate)
		if value == "" {
			return errors.New("trusted certificate must not be empty")
		}

		pemData := []byte(value)
		if !strings.Contains(value, "-----BEGIN CERTIFICATE-----") {
			data, err := os.ReadFile(value)
			if err != nil {
				return fmt.Errorf("read trusted certificate: %w", err)
			}
			pemData = data
		}

		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if ok := roots.AppendCertsFromPEM(pemData); !ok {
			return errors.New("trusted certificate does not contain a valid PEM certificate")
		}

		transport, err := cloneHTTPTransport(c.httpClient.Transport)
		if err != nil {
			return err
		}
		tlsConfig := cloneTLSConfig(transport.TLSClientConfig)
		tlsConfig.RootCAs = roots
		transport.TLSClientConfig = tlsConfig
		c.httpClient.Transport = transport
		return nil
	}
}

// NewClient creates an Airlock Gateway REST client. host can be a hostname, host:port, or full URL.
func NewClient(host, apiKey string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(host) == "" {
		return nil, errors.New("host must not be empty")
	}

	raw := strings.TrimSpace(host)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse host URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid host URL %q", host)
	}

	parsed.Path = appendBasePath(parsed.Path, "/airlock/rest")
	parsed.RawQuery = ""
	parsed.Fragment = ""

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}

	client := &Client{
		baseURL: parsed,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Jar:       jar,
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
		},
		userAgent: defaultUserAgent,
	}

	for _, opt := range opts {
		if err := opt(client); err != nil {
			return nil, err
		}
	}

	return client, nil
}

// newSessionClient creates an independent view of the client with its own
// cookie jar. Airlock identifies a configuration working copy through the
// JSESSIONID cookie, so sharing a jar between concurrent transactions would
// mix their server-side state. The transport is deliberately shared: Go HTTP
// transports are concurrency-safe and sharing it preserves connection pools.
func (c *Client) newSessionClient() (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create transaction cookie jar: %w", err)
	}
	httpClient := *c.httpClient
	httpClient.Jar = jar
	baseURL := *c.baseURL
	return &Client{
		baseURL:    &baseURL,
		apiKey:     c.apiKey,
		httpClient: &httpClient,
		userAgent:  c.userAgent,
	}, nil
}

func appendBasePath(current, suffix string) string {
	current = strings.TrimRight(current, "/")
	if current == "" {
		return suffix
	}
	if strings.HasSuffix(current, suffix) {
		return current
	}
	return current + suffix
}

func cloneHTTPTransport(roundTripper http.RoundTripper) (*http.Transport, error) {
	if roundTripper == nil {
		return http.DefaultTransport.(*http.Transport).Clone(), nil
	}
	transport, ok := roundTripper.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("TLS options require *http.Transport, got %T", roundTripper)
	}
	return transport.Clone(), nil
}

func cloneTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return config.Clone()
}

func (c *Client) endpoint(path string) string {
	u := *c.baseURL
	if path == "" {
		return u.String()
	}
	pathOnly, rawQuery, _ := strings.Cut(path, "?")
	if !strings.HasPrefix(pathOnly, "/") {
		pathOnly = "/" + pathOnly
	}
	u.Path = strings.TrimRight(c.baseURL.Path, "/") + pathOnly
	u.RawQuery = rawQuery
	return u.String()
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), body)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	return req, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, in any, out any, expected ...int) error {
	var body io.Reader
	if in != nil {
		payload, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		body = bytes.NewReader(payload)
	}

	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if !statusExpected(res.StatusCode, expected...) {
		data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return newResponseError(res.StatusCode, data)
	}

	if out == nil {
		_, _ = io.Copy(io.Discard, res.Body)
		return nil
	}

	decoder := json.NewDecoder(res.Body)
	if err := decoder.Decode(out); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode response body: %w", err)
	}
	return nil
}

func (c *Client) doRaw(ctx context.Context, method, path, contentType string, in io.Reader, out io.Writer, expected ...int) error {
	req, err := c.newRequest(ctx, method, path, in)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if !statusExpected(res.StatusCode, expected...) {
		data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return newResponseError(res.StatusCode, data)
	}

	if out != nil {
		_, err = io.Copy(out, res.Body)
		return err
	}
	_, _ = io.Copy(io.Discard, res.Body)
	return nil
}

// DoJSON performs an untyped JSON request. Callers must provide the exact
// Gateway path, request shape, response shape, and accepted status codes.
func (r *RawClient) DoJSON(ctx context.Context, method, path string, in any, out any, expected ...int) error {
	if r == nil || r.client == nil {
		return errors.New("raw Airlock client must not be nil")
	}
	return r.client.doJSON(ctx, method, path, in, out, expected...)
}

// DoRaw performs an untyped streaming request.
func (r *RawClient) DoRaw(ctx context.Context, method, path, contentType string, in io.Reader, out io.Writer, expected ...int) error {
	if r == nil || r.client == nil {
		return errors.New("raw Airlock client must not be nil")
	}
	return r.client.doRaw(ctx, method, path, contentType, in, out, expected...)
}

func statusExpected(status int, expected ...int) bool {
	if len(expected) == 0 {
		return status >= 200 && status < 300
	}
	for _, code := range expected {
		if status == code {
			return true
		}
	}
	return false
}
