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

// Error represents a non-expected HTTP response from Airlock Gateway.
type Error struct {
	StatusCode int
	Body       string
	Errors     []APIErrorBody
	Meta       map[string]any
}

func (e *Error) Error() string {
	body := strings.TrimSpace(e.Body)
	if body == "" {
		return fmt.Sprintf("airlock REST API returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("airlock REST API returned HTTP %d: %s", e.StatusCode, body)
}

// IsNotFound reports whether err is an Airlock 404 response.
func IsNotFound(err error) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// IsConflict reports whether Airlock rejected an operation because of a
// conflict, including activation of an outdated configuration working copy.
func IsConflict(err error) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict
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

// DoJSON performs a JSON request and decodes the JSON response into out when out is non-nil.
func (c *Client) DoJSON(ctx context.Context, method, path string, in any, out any, expected ...int) error {
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

// DoRaw performs a non-JSON request and streams the response body into out when out is non-nil.
func (c *Client) DoRaw(ctx context.Context, method, path, contentType string, in io.Reader, out io.Writer, expected ...int) error {
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
