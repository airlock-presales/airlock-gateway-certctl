package airlock

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/youmark/pkcs8"
)

// Checksum is a SHA-256 digest of canonical certificate or key material.
// Canonical DER is hashed rather than the PEM text, so harmless whitespace and
// line-ending changes made by the Gateway do not cause a false rotation.
type Checksum string

func newChecksum(data []byte) Checksum {
	digest := sha256.Sum256(data)
	return Checksum("sha256:" + hex.EncodeToString(digest[:]))
}

// Certificate is a validated X.509 certificate. Construct it with
// ParseCertificate; its PEM bytes are immutable from the caller's perspective.
type Certificate struct {
	Checksum    Checksum  `json:"checksum"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	DNSNames    []string  `json:"dnsNames,omitempty"`
	IPAddresses []net.IP  `json:"ipAddresses,omitempty"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`

	pem    []byte
	parsed *x509.Certificate
}

// ParseCertificate validates exactly one PEM-encoded X.509 certificate.
func ParseCertificate(data []byte) (Certificate, error) {
	block, rest := pem.Decode(bytes.TrimSpace(data))
	if block == nil || block.Type != "CERTIFICATE" {
		return Certificate{}, errors.New("certificate must contain one PEM CERTIFICATE block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return Certificate{}, errors.New("certificate must contain exactly one PEM CERTIFICATE block")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{}, fmt.Errorf("parse X.509 certificate: %w", err)
	}
	return certificateFromParsed(parsed), nil
}

func certificateFromParsed(parsed *x509.Certificate) Certificate {
	return Certificate{
		Checksum:    newChecksum(parsed.Raw),
		Subject:     parsed.Subject.String(),
		Issuer:      parsed.Issuer.String(),
		DNSNames:    append([]string(nil), parsed.DNSNames...),
		IPAddresses: cloneIPs(parsed.IPAddresses),
		NotBefore:   parsed.NotBefore,
		NotAfter:    parsed.NotAfter,
		pem:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parsed.Raw}),
		parsed:      parsed,
	}
}

// PEM returns a copy of the canonical PEM representation.
func (c Certificate) PEM() []byte { return append([]byte(nil), c.pem...) }

func (c Certificate) valid() bool {
	return c.parsed != nil && len(c.pem) != 0 && c.Checksum == newChecksum(c.parsed.Raw)
}

func cloneIPs(values []net.IP) []net.IP {
	result := make([]net.IP, len(values))
	for i, value := range values {
		result[i] = append(net.IP(nil), value...)
	}
	return result
}

// Key is a validated private key. Checksum is derived from canonical,
// unencrypted PKCS#8 DER. The original PEM and passphrase are retained only so
// Airlock can receive the format supplied by the caller.
type Key struct {
	Checksum Checksum `json:"checksum"`

	pem        []byte
	passphrase []byte
	privateKey crypto.PrivateKey
}

// ParseKey validates an unencrypted PEM private key.
func ParseKey(data []byte) (Key, error) { return ParseEncryptedKey(data, nil) }

// ParseEncryptedKey validates an encrypted or unencrypted PEM private key.
// PKCS#1 RSA, SEC1 EC, PKCS#8, and encrypted PKCS#8 inputs are supported.
func ParseEncryptedKey(data, passphrase []byte) (Key, error) {
	if !utf8.Valid(passphrase) {
		return Key{}, errors.New("private-key passphrase must be valid UTF-8 for the Airlock JSON API")
	}
	trimmed := bytes.TrimSpace(data)
	block, rest := pem.Decode(trimmed)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return Key{}, errors.New("private key must contain one PEM PRIVATE KEY block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return Key{}, errors.New("private key must contain exactly one PEM PRIVATE KEY block")
	}

	privateKey, err := parsePrivateKeyBlock(block, passphrase)
	if err != nil {
		return Key{}, err
	}
	if _, ok := privateKey.(crypto.Signer); !ok {
		return Key{}, fmt.Errorf("unsupported private key type %T", privateKey)
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return Key{}, fmt.Errorf("canonicalize private key: %w", err)
	}
	return Key{
		Checksum:   newChecksum(canonical),
		pem:        append(append([]byte(nil), trimmed...), '\n'),
		passphrase: append([]byte(nil), passphrase...),
		privateKey: privateKey,
	}, nil
}

func parsePrivateKeyBlock(block *pem.Block, passphrase []byte) (crypto.PrivateKey, error) {
	der := block.Bytes
	if block.Headers["Proc-Type"] != "" || block.Headers["DEK-Info"] != "" {
		return nil, errors.New("legacy RFC 1423 PEM encryption is insecure and unsupported; convert the key to encrypted PKCS#8")
	}

	if block.Type == "ENCRYPTED PRIVATE KEY" {
		if len(passphrase) == 0 {
			return nil, errors.New("private key is encrypted but no passphrase was supplied")
		}
		key, err := pkcs8.ParsePKCS8PrivateKey(der, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt PKCS#8 private key: %w", err)
		}
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("private key is not valid PKCS#1, SEC1, or PKCS#8 data")
}

// PEM returns a copy of the original PEM representation.
func (k Key) PEM() []byte { return append([]byte(nil), k.pem...) }

func (k Key) valid() bool {
	if k.privateKey == nil || len(k.pem) == 0 {
		return false
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(k.privateKey)
	return err == nil && k.Checksum == newChecksum(canonical)
}

// CertificateType is the certType enum published by Airlock Gateway 8.6.
type CertificateType string

const (
	ServerCertificate CertificateType = "SERVER_CERT"
	ClientCertificate CertificateType = "CLIENT_CERT"
)

func (t CertificateType) validate() error {
	switch t {
	case ServerCertificate, ClientCertificate:
		return nil
	default:
		return fmt.Errorf("unsupported certificate type %q", t)
	}
}

// CertificateBundle is a locally validated certificate/private-key unit. It
// is the atomic value synchronized to an Airlock ssl-certificate resource.
type CertificateBundle struct {
	Type        CertificateType `json:"type"`
	Certificate Certificate     `json:"certificate"`
	Key         Key             `json:"key"`
	Chain       []Certificate   `json:"chain,omitempty"`
	RootCA      *Certificate    `json:"rootCA,omitempty"`
	Checksum    Checksum        `json:"checksum"`
}

// BundleOptions adds the Airlock certificate type and optional CA material.
type BundleOptions struct {
	Type   CertificateType
	Chain  []Certificate
	RootCA *Certificate
}

// NewCertificateBundle verifies all material and rejects a certificate/key
// mismatch before any request can be sent to Airlock Gateway.
func NewCertificateBundle(certificate Certificate, key Key, options BundleOptions) (CertificateBundle, error) {
	if !certificate.valid() {
		return CertificateBundle{}, errors.New("certificate was not created by ParseCertificate")
	}
	if !key.valid() {
		return CertificateBundle{}, errors.New("key was not created by ParseKey or ParseEncryptedKey")
	}
	certificateType := options.Type
	if certificateType == "" {
		certificateType = ServerCertificate
	}
	if err := certificateType.validate(); err != nil {
		return CertificateBundle{}, err
	}
	for i, item := range options.Chain {
		if !item.valid() {
			return CertificateBundle{}, fmt.Errorf("chain certificate %d was not created by ParseCertificate", i)
		}
	}
	if options.RootCA != nil && !options.RootCA.valid() {
		return CertificateBundle{}, errors.New("root CA was not created by ParseCertificate")
	}
	if err := certificateMatchesKey(certificate, key); err != nil {
		return CertificateBundle{}, err
	}
	if err := validateCertificateChain(certificate, options.Chain, options.RootCA); err != nil {
		return CertificateBundle{}, err
	}

	bundle := CertificateBundle{
		Type:        certificateType,
		Certificate: certificate,
		Key:         key,
		Chain:       append([]Certificate(nil), options.Chain...),
		RootCA:      options.RootCA,
	}
	bundle.Checksum = bundleChecksum(bundle)
	return bundle, nil
}

// ParseCertificateBundle is a convenience constructor for PEM inputs.
type CertificateBundleInput struct {
	Type                 CertificateType
	CertificatePEM       []byte
	PrivateKeyPEM        []byte `json:"-"`
	PrivateKeyPassphrase []byte `json:"-"`
	CertificateChainPEM  [][]byte
	RootCAPEM            []byte
}

// ParseCertificateBundle parses and validates all PEM inputs as one unit.
func ParseCertificateBundle(input CertificateBundleInput) (CertificateBundle, error) {
	certificate, err := ParseCertificate(input.CertificatePEM)
	if err != nil {
		return CertificateBundle{}, err
	}
	key, err := ParseEncryptedKey(input.PrivateKeyPEM, input.PrivateKeyPassphrase)
	if err != nil {
		return CertificateBundle{}, err
	}
	chain := make([]Certificate, 0, len(input.CertificateChainPEM))
	for i, data := range input.CertificateChainPEM {
		item, err := ParseCertificate(data)
		if err != nil {
			return CertificateBundle{}, fmt.Errorf("parse chain certificate %d: %w", i, err)
		}
		chain = append(chain, item)
	}
	var root *Certificate
	if len(bytes.TrimSpace(input.RootCAPEM)) != 0 {
		item, err := ParseCertificate(input.RootCAPEM)
		if err != nil {
			return CertificateBundle{}, fmt.Errorf("parse root CA: %w", err)
		}
		root = &item
	}
	return NewCertificateBundle(certificate, key, BundleOptions{Type: input.Type, Chain: chain, RootCA: root})
}

func certificateMatchesKey(certificate Certificate, key Key) error {
	signer, ok := key.privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("unsupported private key type %T", key.privateKey)
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.parsed.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal certificate public key: %w", err)
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("marshal private-key public key: %w", err)
	}
	if !bytes.Equal(certificatePublic, keyPublic) {
		return errors.New("certificate and private key do not match")
	}
	return nil
}

func validateCertificateChain(leaf Certificate, chain []Certificate, root *Certificate) error {
	child := leaf.parsed
	for i, issuer := range chain {
		if !issuer.parsed.IsCA {
			return fmt.Errorf("chain certificate %d is not a CA certificate", i)
		}
		if err := child.CheckSignatureFrom(issuer.parsed); err != nil {
			return fmt.Errorf("chain certificate %d does not sign the preceding certificate: %w", i, err)
		}
		child = issuer.parsed
	}
	if root == nil {
		return nil
	}
	if !root.parsed.IsCA {
		return errors.New("root CA certificate is not a CA certificate")
	}
	if err := child.CheckSignatureFrom(root.parsed); err != nil {
		return fmt.Errorf("root CA does not sign the preceding certificate: %w", err)
	}
	return nil
}

func bundleChecksum(bundle CertificateBundle) Checksum {
	hash := sha256.New()
	writeHashPart := func(data []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(data)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(data)
	}
	writeHashPart([]byte(bundle.Type))
	writeHashPart([]byte(bundle.Certificate.Checksum))
	writeHashPart([]byte(bundle.Key.Checksum))
	for _, item := range bundle.Chain {
		writeHashPart([]byte(item.Checksum))
	}
	if bundle.RootCA != nil {
		writeHashPart([]byte(bundle.RootCA.Checksum))
	} else {
		writeHashPart(nil)
	}
	return Checksum("sha256:" + hex.EncodeToString(hash.Sum(nil)))
}

func (b CertificateBundle) validate() error {
	if _, err := NewCertificateBundle(b.Certificate, b.Key, BundleOptions{Type: b.Type, Chain: b.Chain, RootCA: b.RootCA}); err != nil {
		return err
	}
	if b.Checksum != bundleChecksum(b) {
		return errors.New("certificate bundle checksum is invalid; construct it with NewCertificateBundle or ParseCertificateBundle")
	}
	return nil
}
