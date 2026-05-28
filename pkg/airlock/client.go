package airlock

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const defaultUserAgent = "airlock-certctl/0.1"

// Error represents a non-expected HTTP response from Airlock Gateway.
type Error struct {
	StatusCode int
	Body       string
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

// Client is a small Airlock Gateway REST client.
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
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
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
			Timeout: 30 * time.Second,
			Jar:     jar,
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
		return &Error{StatusCode: res.StatusCode, Body: string(data)}
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
		return &Error{StatusCode: res.StatusCode, Body: string(data)}
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
