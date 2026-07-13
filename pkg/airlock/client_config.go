package airlock

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config contains Airlock Gateway connection and authentication settings.
type Config struct {
	Address            string
	Port               string
	APIKey             string
	Timeout            time.Duration
	InsecureSkipVerify bool
	TrustedCertificate string
	HTTPClient         *http.Client
	UserAgent          string
}

// New creates an Airlock Gateway REST client from Config.
func New(config Config) (*Client, error) {
	address, err := configuredAddress(config.Address, config.Port)
	if err != nil {
		return nil, err
	}

	options := make([]Option, 0, 5)
	if config.HTTPClient != nil {
		options = append(options, WithHTTPClient(config.HTTPClient))
	}
	if config.Timeout > 0 {
		options = append(options, WithTimeout(config.Timeout))
	}
	if config.UserAgent != "" {
		options = append(options, WithUserAgent(config.UserAgent))
	}
	if config.TrustedCertificate != "" {
		options = append(options, WithTrustedCertificate(config.TrustedCertificate))
	}
	if config.InsecureSkipVerify {
		options = append(options, WithInsecureSkipVerify())
	}
	return NewClient(address, config.APIKey, options...)
}

func configuredAddress(address, port string) (string, error) {
	raw := strings.TrimSpace(address)
	if raw == "" {
		return "", errors.New("Airlock Gateway address must not be empty")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", errors.New("invalid Airlock Gateway address")
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(parsed.Hostname(), port)
	}
	return parsed.String(), nil
}
