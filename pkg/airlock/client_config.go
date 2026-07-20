package airlock

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config contains Airlock Gateway connection and authentication settings.
type Config struct {
	Address            string        `json:"address"`
	Port               uint16        `json:"port,omitempty"`
	APIKey             string        `json:"-"`
	Timeout            time.Duration `json:"timeout,omitempty"`
	InsecureSkipVerify bool          `json:"insecureSkipVerify,omitempty"`
	TrustedCertificate string        `json:"trustedCertificate,omitempty"`
	HTTPClient         *http.Client  `json:"-"`
	UserAgent          string        `json:"userAgent,omitempty"`
}

// New creates an Airlock Gateway REST client from Config.
func New(config Config) (*Client, error) {
	if strings.TrimSpace(config.APIKey) == "" {
		return nil, errors.New("missing Airlock Gateway API key")
	}
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

func configuredAddress(address string, port uint16) (string, error) {
	raw := strings.TrimSpace(address)
	if raw == "" {
		return "", errors.New("missing Airlock Gateway address")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", errors.New("invalid Airlock Gateway address")
	}
	if port != 0 {
		parsed.Host = net.JoinHostPort(parsed.Hostname(), strconv.FormatUint(uint64(port), 10))
	}
	return parsed.String(), nil
}
