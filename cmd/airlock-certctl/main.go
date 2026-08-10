package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/airlock-presales/airlock-gateway-certctl/pkg/airlock"
)

type globalOptions struct {
	host        string
	port        int
	apiKey      string
	insecure    bool
	showSecrets bool
	timeout     time.Duration
}

type mutateOptions struct {
	configID        string
	loadActive      bool
	saveComment     string
	activate        bool
	activateComment string
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	globals, command, rest, err := parseGlobals(args, stderr)
	if err != nil {
		return err
	}
	if command == "" {
		usage(stdout)
		return nil
	}

	switch command {
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	case "attrs-from-pem":
		return runAttrsFromPEM(rest, stdout, stderr)
	}

	ctx := context.Background()
	client, err := newClient(globals)
	if err != nil {
		return err
	}

	switch command {
	case "list":
		fs := flag.NewFlagSet("list", flag.ContinueOnError)
		fs.SetOutput(stderr)
		filter := fs.String("filter", "", "optional Airlock filter expression, e.g. name==www.example.com")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return withSession(ctx, client, func() error {
			certs, err := client.ListSSLCertificates(ctx, airlock.ListSSLCertificatesOptions{RawFilter: *filter})
			if err != nil {
				return err
			}
			return printResourceJSON(stdout, certs, globals.showSecrets)
		})

	case "get":
		fs := flag.NewFlagSet("get", flag.ContinueOnError)
		fs.SetOutput(stderr)
		id := fs.String("id", "", "SSL certificate ID")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *id == "" {
			return errors.New("get requires --id")
		}
		certificateID, err := airlock.ParseCertificateID(*id)
		if err != nil {
			return err
		}
		return withSession(ctx, client, func() error {
			cert, err := client.GetSSLCertificate(ctx, certificateID)
			if err != nil {
				return err
			}
			return printResourceJSON(stdout, cert, globals.showSecrets)
		})

	case "find-domain":
		fs := flag.NewFlagSet("find-domain", flag.ContinueOnError)
		fs.SetOutput(stderr)
		domain := fs.String("domain", "", "DNS name or IP address to search in certificate SAN/CN")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *domain == "" {
			return errors.New("find-domain requires --domain")
		}
		return withSession(ctx, client, func() error {
			certs, err := client.ListSSLCertificates(ctx, airlock.ListSSLCertificatesOptions{})
			if err != nil {
				return err
			}
			matches := findCertificatesForDomain(certs, *domain)
			return printJSON(stdout, matches)
		})

	case "create":
		fs := flag.NewFlagSet("create", flag.ContinueOnError)
		fs.SetOutput(stderr)
		attrsFile := fs.String("attrs", "", "JSON file containing SSL certificate attributes; use - for stdin")
		mut := addMutateFlags(fs)
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *attrsFile == "" {
			return errors.New("create requires --attrs")
		}
		attrs, err := readSSLCertificateAttributes(*attrsFile)
		if err != nil {
			return err
		}
		return withSession(ctx, client, func() error {
			if err := prepareConfig(ctx, client, mut); err != nil {
				return err
			}
			cert, err := client.CreateSSLCertificate(ctx, attrs)
			if err != nil {
				return err
			}
			if err := finishConfig(ctx, client, mut); err != nil {
				return err
			}
			return printResourceJSON(stdout, cert, globals.showSecrets)
		})

	case "update":
		fs := flag.NewFlagSet("update", flag.ContinueOnError)
		fs.SetOutput(stderr)
		id := fs.String("id", "", "SSL certificate ID")
		attrsFile := fs.String("attrs", "", "JSON file containing SSL certificate attributes; use - for stdin")
		mut := addMutateFlags(fs)
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *id == "" || *attrsFile == "" {
			return errors.New("update requires --id and --attrs")
		}
		certificateID, err := airlock.ParseCertificateID(*id)
		if err != nil {
			return err
		}
		attrs, err := readSSLCertificateAttributes(*attrsFile)
		if err != nil {
			return err
		}
		return withSession(ctx, client, func() error {
			if err := prepareConfig(ctx, client, mut); err != nil {
				return err
			}
			cert, err := client.UpdateSSLCertificate(ctx, certificateID, attrs)
			if err != nil {
				return err
			}
			if err := finishConfig(ctx, client, mut); err != nil {
				return err
			}
			return printResourceJSON(stdout, cert, globals.showSecrets)
		})

	case "replace-with-new":
		fs := flag.NewFlagSet("replace-with-new", flag.ContinueOnError)
		fs.SetOutput(stderr)
		oldID := fs.String("old-cert-id", "", "old SSL certificate ID whose relationships should be moved")
		attrsFile := fs.String("attrs", "", "JSON file containing new SSL certificate attributes; use - for stdin")
		deleteOld := fs.Bool("delete-old", true, "delete the old certificate after moving relationships")
		mut := addMutateFlags(fs)
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *oldID == "" || *attrsFile == "" {
			return errors.New("replace-with-new requires --old-cert-id and --attrs")
		}
		oldCertificateID, err := airlock.ParseCertificateID(*oldID)
		if err != nil {
			return err
		}
		attrs, err := readSSLCertificateAttributes(*attrsFile)
		if err != nil {
			return err
		}
		return withSession(ctx, client, func() error {
			if err := prepareConfig(ctx, client, mut); err != nil {
				return err
			}
			result, err := replaceCertificateWithNew(ctx, client, oldCertificateID, attrs, *deleteOld)
			if err != nil {
				return err
			}
			if err := finishConfig(ctx, client, mut); err != nil {
				return err
			}
			return printResourceJSON(stdout, result, globals.showSecrets)
		})

	case "delete":
		fs := flag.NewFlagSet("delete", flag.ContinueOnError)
		fs.SetOutput(stderr)
		id := fs.String("id", "", "SSL certificate ID")
		mut := addMutateFlags(fs)
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *id == "" {
			return errors.New("delete requires --id")
		}
		certificateID, err := airlock.ParseCertificateID(*id)
		if err != nil {
			return err
		}
		return withSession(ctx, client, func() error {
			if err := prepareConfig(ctx, client, mut); err != nil {
				return err
			}
			if err := client.DeleteSSLCertificate(ctx, certificateID); err != nil {
				return err
			}
			if err := finishConfig(ctx, client, mut); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(stdout, "deleted")
			return nil
		})

	case "connect-vh", "disconnect-vh":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		certID := fs.String("cert-id", "", "SSL certificate ID")
		virtualHostIDs := fs.String("virtual-host-ids", "", "comma-separated virtual host IDs")
		mut := addMutateFlags(fs)
		if err := fs.Parse(rest); err != nil {
			return err
		}
		ids := splitCSV(*virtualHostIDs)
		if *certID == "" || len(ids) == 0 {
			return errors.New(command + " requires --cert-id and --virtual-host-ids")
		}
		certificateID, err := airlock.ParseCertificateID(*certID)
		if err != nil {
			return err
		}
		parsedVirtualHostIDs, err := parseVirtualHostIDs(ids)
		if err != nil {
			return err
		}
		return withSession(ctx, client, func() error {
			if err := prepareConfig(ctx, client, mut); err != nil {
				return err
			}
			var err error
			if command == "connect-vh" {
				err = client.ConnectSSLCertificateToVirtualHosts(ctx, certificateID, parsedVirtualHostIDs...)
			} else {
				err = client.DisconnectSSLCertificateFromVirtualHosts(ctx, certificateID, parsedVirtualHostIDs...)
			}
			if err != nil {
				return err
			}
			if err := finishConfig(ctx, client, mut); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(stdout, "ok")
			return nil
		})

	case "connect", "disconnect":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(stderr)
		certID := fs.String("cert-id", "", "SSL certificate ID")
		relationship := fs.String("relationship", "virtual-hosts", "relationship name: virtual-hosts, back-end-groups, remote-jwks, or nodes")
		idsValue := fs.String("ids", "", "comma-separated target resource IDs")
		mut := addMutateFlags(fs)
		if err := fs.Parse(rest); err != nil {
			return err
		}
		ids := splitCSV(*idsValue)
		if *certID == "" || len(ids) == 0 {
			return errors.New(command + " requires --cert-id and --ids")
		}
		certificateID, err := airlock.ParseCertificateID(*certID)
		if err != nil {
			return err
		}
		return withSession(ctx, client, func() error {
			if err := prepareConfig(ctx, client, mut); err != nil {
				return err
			}
			err = changeCertificateRelationship(ctx, client, command == "connect", certificateID, *relationship, ids)
			if err != nil {
				return err
			}
			if err := finishConfig(ctx, client, mut); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(stdout, "ok")
			return nil
		})

	case "validate":
		return withSession(ctx, client, func() error {
			messages, err := client.Validate(ctx)
			if err != nil {
				return err
			}
			return printJSON(stdout, messages)
		})

	case "save":
		fs := flag.NewFlagSet("save", flag.ContinueOnError)
		fs.SetOutput(stderr)
		comment := fs.String("comment", "", "save comment")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return withSession(ctx, client, func() error {
			id, err := client.SaveConfiguration(ctx, *comment)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(stdout, id)
			return nil
		})

	case "activate":
		fs := flag.NewFlagSet("activate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		comment := fs.String("comment", "", "activation comment")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return withSession(ctx, client, func() error {
			messages, err := client.Validate(ctx)
			if err != nil {
				return err
			}
			if len(messages) > 0 {
				_ = printJSON(stderr, messages)
				return errors.New("configuration validation failed")
			}
			if err := client.ActivateConfiguration(ctx, *comment); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(stdout, "activated")
			return nil
		})

	case "schema":
		fs := flag.NewFlagSet("schema", flag.ContinueOnError)
		fs.SetOutput(stderr)
		format := fs.String("format", "json", "OpenAPI format: json or yaml")
		outFile := fs.String("out", "", "write schema to file instead of stdout")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return withSession(ctx, client, func() error {
			data, err := client.DownloadOpenAPISpec(ctx, *format)
			if err != nil {
				return err
			}
			if *outFile != "" {
				return os.WriteFile(*outFile, data, 0600)
			}
			_, err = stdout.Write(data)
			return err
		})

	case "version":
		return withSession(ctx, client, func() error {
			version, err := client.Version(ctx)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(stdout, version)
			return nil
		})

	case "help", "-h", "--help":
		usage(stdout)
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", command)
	}
}

func parseGlobals(args []string, stderr io.Writer) (globalOptions, string, []string, error) {
	opts := globalOptions{
		host:    os.Getenv("AIRLOCK_HOST"),
		apiKey:  os.Getenv("AIRLOCK_API_KEY"),
		timeout: 30 * time.Second,
	}
	if port := os.Getenv("AIRLOCK_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			opts.port = p
		}
	}
	if insecure := strings.ToLower(os.Getenv("AIRLOCK_INSECURE_SKIP_VERIFY")); insecure == "1" || insecure == "true" || insecure == "yes" {
		opts.insecure = true
	}

	fs := flag.NewFlagSet("airlock-certctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.host, "host", opts.host, "Airlock Gateway Configuration Center host or URL; env AIRLOCK_HOST")
	fs.IntVar(&opts.port, "port", opts.port, "optional management port; env AIRLOCK_PORT")
	fs.StringVar(&opts.apiKey, "api-key", opts.apiKey, "Airlock API key; env AIRLOCK_API_KEY")
	fs.BoolVar(&opts.insecure, "insecure-skip-verify", opts.insecure, "disable TLS verification")
	fs.BoolVar(&opts.showSecrets, "show-secrets", false, "print sensitive values such as privateKey; disabled by default")
	fs.DurationVar(&opts.timeout, "timeout", opts.timeout, "HTTP timeout")

	if err := fs.Parse(args); err != nil {
		return opts, "", nil, err
	}
	remaining := fs.Args()
	if len(remaining) == 0 {
		return opts, "", nil, nil
	}
	return opts, remaining[0], remaining[1:], nil
}

func newClient(opts globalOptions) (*airlock.Client, error) {
	if opts.host == "" {
		return nil, errors.New("missing --host or AIRLOCK_HOST")
	}
	if opts.apiKey == "" {
		return nil, errors.New("missing --api-key or AIRLOCK_API_KEY")
	}

	host := opts.host
	if opts.port > 0 {
		host = withPort(host, opts.port)
	}
	clientOpts := []airlock.Option{airlock.WithTimeout(opts.timeout)}
	if opts.insecure {
		clientOpts = append(clientOpts, airlock.WithInsecureSkipVerify())
	}
	return airlock.NewClient(host, opts.apiKey, clientOpts...)
}

func withSession(ctx context.Context, client *airlock.Client, fn func() error) error {
	if err := client.CreateSessionAndLoadActiveConfiguration(ctx); err != nil {
		return err
	}
	defer func() { _ = client.TerminateSession(ctx) }()
	return fn()
}

func addMutateFlags(fs *flag.FlagSet) *mutateOptions {
	mut := &mutateOptions{loadActive: true}
	fs.StringVar(&mut.configID, "config-id", "", "load a specific configuration ID after the initial active-configuration load")
	fs.BoolVar(&mut.loadActive, "load-active", mut.loadActive, "deprecated compatibility flag; the active configuration is loaded automatically for every command")
	fs.StringVar(&mut.saveComment, "save-comment", "", "save the configuration with this comment after the change")
	fs.BoolVar(&mut.activate, "activate", false, "validate and activate after the change")
	fs.StringVar(&mut.activateComment, "activate-comment", "", "activation comment")
	return mut
}

func prepareConfig(ctx context.Context, client *airlock.Client, mut *mutateOptions) error {
	if mut.configID != "" {
		return client.LoadConfiguration(ctx, mut.configID, "")
	}
	return nil
}

func finishConfig(ctx context.Context, client *airlock.Client, mut *mutateOptions) error {
	if mut.activate {
		messages, err := client.Validate(ctx)
		if err != nil {
			return err
		}
		if len(messages) > 0 {
			return errors.New("configuration validation failed; run validate for details")
		}
		return client.ActivateConfiguration(ctx, mut.activateComment)
	}
	if mut.saveComment != "" {
		_, err := client.SaveConfiguration(ctx, mut.saveComment)
		return err
	}
	return nil
}

type domainCertificateMatch struct {
	Type             string                                                   `json:"type"`
	ID               string                                                   `json:"id"`
	CertType         airlock.CertificateType                                  `json:"certType,omitempty"`
	CommonName       string                                                   `json:"commonName,omitempty"`
	DNSNames         []string                                                 `json:"dnsNames,omitempty"`
	IPAddresses      []string                                                 `json:"ipAddresses,omitempty"`
	NotBefore        time.Time                                                `json:"notBefore"`
	NotAfter         time.Time                                                `json:"notAfter"`
	IssuerCommonName string                                                   `json:"issuerCommonName,omitempty"`
	SerialNumber     string                                                   `json:"serialNumber,omitempty"`
	Relationships    map[airlock.CertificateRelationship]airlock.Relationship `json:"relationships,omitempty"`
}

type replaceCertificateResult struct {
	OldCertificateID   string                                  `json:"oldCertificateId"`
	NewCertificate     airlock.SSLCertificateResource          `json:"newCertificate"`
	MovedRelationships map[string][]airlock.ResourceIdentifier `json:"movedRelationships,omitempty"`
	DeletedOld         bool                                    `json:"deletedOld"`
}

func runAttrsFromPEM(args []string, stdout, stderr io.Writer) error {
	_ = stdout
	fs := flag.NewFlagSet("attrs-from-pem", flag.ContinueOnError)
	fs.SetOutput(stderr)
	certFile := fs.String("cert", "", "leaf certificate PEM; if it contains a full chain, the first certificate is used as leaf")
	keyFile := fs.String("key", "", "private key PEM")
	chainFile := fs.String("chain", "", "optional intermediate certificate chain PEM")
	rootCAFile := fs.String("root-ca", "", "optional root CA certificate PEM")
	certType := fs.String("cert-type", "SERVER_CERT", "Airlock certType attribute")
	outFile := fs.String("out", "", "output JSON attributes file; required because it contains private key material")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certFile == "" || *keyFile == "" || *outFile == "" {
		return errors.New("attrs-from-pem requires --cert, --key, and --out")
	}

	certs, err := readCertificatePEMBlocks(*certFile)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return fmt.Errorf("%s does not contain a PEM CERTIFICATE block", *certFile)
	}

	chain := certs[1:]
	if *chainFile != "" {
		chain, err = readCertificatePEMBlocks(*chainFile)
		if err != nil {
			return err
		}
	}

	privateKey, err := readNormalizedPEMFile(*keyFile)
	if err != nil {
		return err
	}

	rootCA := ""
	if *rootCAFile != "" {
		rootCA, err = readNormalizedPEMFile(*rootCAFile)
		if err != nil {
			return err
		}
	}

	typeValue := airlock.CertificateType(*certType)
	attrs := airlock.SSLCertificateAttributes{
		CertType:          &typeValue,
		Certificate:       &certs[0],
		CertificateChain:  &chain,
		PrivateKey:        &privateKey,
		RootCACertificate: &rootCA,
	}

	data, err := json.MarshalIndent(attrs, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(*outFile, data, 0600)
}

func readNormalizedPEMFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)) + "\n", nil
}

func readCertificatePEMBlocks(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []string
	remaining := data
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, string(pem.EncodeToMemory(block)))
		}
		remaining = rest
	}
	return certs, nil
}

func findCertificatesForDomain(certs []airlock.SSLCertificateResource, domain string) []domainCertificateMatch {
	matches := make([]domainCertificateMatch, 0)
	for _, resource := range certs {
		if resource.Attributes.Certificate == nil {
			continue
		}
		pemText := *resource.Attributes.Certificate
		cert, err := firstCertificateFromPEM(pemText)
		if err != nil {
			continue
		}
		if !certificateMatchesDomain(cert, domain) {
			continue
		}
		match := domainCertificateMatch{
			Type:             resource.Type,
			ID:               resource.ID.String(),
			CommonName:       cert.Subject.CommonName,
			DNSNames:         cert.DNSNames,
			NotBefore:        cert.NotBefore,
			NotAfter:         cert.NotAfter,
			IssuerCommonName: cert.Issuer.CommonName,
			SerialNumber:     cert.SerialNumber.String(),
			Relationships:    resource.Relationships,
		}
		if resource.Attributes.CertType != nil {
			match.CertType = *resource.Attributes.CertType
		}
		for _, ip := range cert.IPAddresses {
			match.IPAddresses = append(match.IPAddresses, ip.String())
		}
		matches = append(matches, match)
	}
	return matches
}

func firstCertificateFromPEM(pemText string) (*x509.Certificate, error) {
	remaining := []byte(pemText)
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		remaining = rest
	}
	return nil, errors.New("no PEM certificate found")
}

func certificateMatchesDomain(cert *x509.Certificate, domain string) bool {
	target := normalizeHostForMatch(domain)
	if target == "" {
		return false
	}
	if ip := net.ParseIP(target); ip != nil {
		for _, candidate := range cert.IPAddresses {
			if candidate.Equal(ip) {
				return true
			}
		}
		return false
	}
	for _, name := range cert.DNSNames {
		if hostnameMatchesPattern(name, target) {
			return true
		}
	}
	return hostnameMatchesPattern(cert.Subject.CommonName, target)
}

func hostnameMatchesPattern(pattern, host string) bool {
	pattern = normalizeHostForMatch(pattern)
	host = normalizeHostForMatch(host)
	if pattern == "" || host == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		if !strings.HasSuffix(host, "."+suffix) {
			return false
		}
		return len(strings.Split(host, ".")) == len(strings.Split(suffix, "."))+1
	}
	return false
}

func normalizeHostForMatch(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func replaceCertificateWithNew(ctx context.Context, client *airlock.Client, oldID airlock.CertificateID, attrs airlock.SSLCertificateAttributes, deleteOld bool) (replaceCertificateResult, error) {
	oldCert, err := client.GetSSLCertificate(ctx, oldID)
	if err != nil {
		return replaceCertificateResult{}, err
	}
	newCert, err := client.CreateSSLCertificate(ctx, attrs)
	if err != nil {
		return replaceCertificateResult{}, err
	}

	moved := make(map[string][]airlock.ResourceIdentifier)
	for _, relationship := range []airlock.CertificateRelationship{
		airlock.CertificateVirtualHosts,
		airlock.CertificateBackEndGroups,
		airlock.CertificateRemoteJWKS,
		airlock.CertificateNodes,
	} {
		refs := resourceIdentifiersFromRelationship(oldCert.Relationships[relationship])
		if len(refs) == 0 {
			continue
		}
		if err := client.ConnectSSLCertificateRelationship(ctx, newCert.ID, relationship, refs); err != nil {
			return replaceCertificateResult{}, err
		}
		if err := client.DisconnectSSLCertificateRelationship(ctx, oldID, relationship, refs); err != nil {
			return replaceCertificateResult{}, err
		}
		moved[string(relationship)] = refs
	}

	if deleteOld {
		if err := client.DeleteSSLCertificate(ctx, oldID); err != nil {
			return replaceCertificateResult{}, err
		}
	}

	return replaceCertificateResult{
		OldCertificateID:   oldID.String(),
		NewCertificate:     newCert,
		MovedRelationships: moved,
		DeletedOld:         deleteOld,
	}, nil
}

func resourceIdentifiersFromRelationship(rel airlock.Relationship) []airlock.ResourceIdentifier {
	if len(rel.Data) == 0 {
		return nil
	}
	data := rel.Data
	var many []airlock.ResourceIdentifier
	if err := json.Unmarshal(data, &many); err == nil {
		return many
	}
	var one airlock.ResourceIdentifier
	if err := json.Unmarshal(data, &one); err == nil && one.ID != "" && one.Type != "" {
		return []airlock.ResourceIdentifier{one}
	}
	return nil
}

func readSSLCertificateAttributes(path string) (airlock.SSLCertificateAttributes, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return airlock.SSLCertificateAttributes{}, err
	}
	var attrs airlock.SSLCertificateAttributes
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&attrs); err != nil {
		return airlock.SSLCertificateAttributes{}, fmt.Errorf("parse typed SSL certificate attributes: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return airlock.SSLCertificateAttributes{}, errors.New("SSL certificate attributes must contain exactly one JSON object")
	}
	if err := attrs.Validate(); err != nil {
		return airlock.SSLCertificateAttributes{}, err
	}
	return attrs, nil
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printResourceJSON(w io.Writer, v any, showSecrets bool) error {
	if showSecrets {
		return printJSON(w, v)
	}
	return printJSON(w, redactSensitive(v))
}

func redactSensitive(v any) any {
	data, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return v
	}
	redactValue(out)
	return out
}

func redactValue(v any) {
	switch x := v.(type) {
	case map[string]any:
		for key, value := range x {
			if shouldRedactOutputKey(key) {
				x[key] = "<redacted>"
				continue
			}
			redactValue(value)
		}
	case []any:
		for _, value := range x {
			redactValue(value)
		}
	}
}

func shouldRedactOutputKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(key))
	if normalized == "authorization" || normalized == "apikey" {
		return true
	}
	for _, token := range []string{"privatekey", "password", "passphrase", "secret", "token"} {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func changeCertificateRelationship(ctx context.Context, client *airlock.Client, connect bool, certificateID airlock.CertificateID, relationship string, values []string) error {
	switch relationship {
	case "virtual-hosts":
		ids, err := parseVirtualHostIDs(values)
		if err != nil {
			return err
		}
		if connect {
			return client.ConnectSSLCertificateToVirtualHosts(ctx, certificateID, ids...)
		}
		return client.DisconnectSSLCertificateFromVirtualHosts(ctx, certificateID, ids...)
	case "back-end-groups":
		ids := make([]airlock.BackEndGroupID, 0, len(values))
		for _, value := range values {
			id, err := airlock.ParseBackEndGroupID(value)
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		if connect {
			return client.ConnectSSLCertificateToBackEndGroups(ctx, certificateID, ids...)
		}
		return client.DisconnectSSLCertificateFromBackEndGroups(ctx, certificateID, ids...)
	case "remote-jwks":
		ids := make([]airlock.RemoteJWKSID, 0, len(values))
		for _, value := range values {
			id, err := airlock.ParseRemoteJWKSID(value)
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		if connect {
			return client.ConnectSSLCertificateToRemoteJWKS(ctx, certificateID, ids...)
		}
		return client.DisconnectSSLCertificateFromRemoteJWKS(ctx, certificateID, ids...)
	case "nodes":
		ids := make([]airlock.NodeID, 0, len(values))
		for _, value := range values {
			id, err := airlock.ParseNodeID(value)
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		if connect {
			return client.ConnectSSLCertificateToNodes(ctx, certificateID, ids...)
		}
		return client.DisconnectSSLCertificateFromNodes(ctx, certificateID, ids...)
	default:
		return fmt.Errorf("unsupported relationship %q; use virtual-hosts, back-end-groups, remote-jwks, or nodes", relationship)
	}
}

func parseVirtualHostIDs(values []string) ([]airlock.VirtualHostID, error) {
	ids := make([]airlock.VirtualHostID, 0, len(values))
	for _, value := range values {
		id, err := airlock.ParseVirtualHostID(value)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func withPort(rawHost string, port int) string {
	if port == 0 {
		return rawHost
	}
	raw := rawHost
	prefixAdded := false
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
		prefixAdded = true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return rawHost
	}
	host := u.Hostname()
	if host == "" {
		return rawHost
	}
	u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	if prefixAdded {
		return strings.TrimPrefix(u.String(), "https://")
	}
	return u.String()
}

func usage(w io.Writer) {
	fmt.Fprint(w, `airlock-certctl manages Airlock Gateway SSL certificate resources.

Global flags must be placed before the command:
  --host URL-or-host                 Airlock Gateway Configuration Center host or URL
  --api-key KEY                      API key, or AIRLOCK_API_KEY
  --port PORT                        optional management port
  --insecure-skip-verify             disable TLS verification for lab systems
  --show-secrets                     print sensitive values such as privateKey; disabled by default
  --timeout DURATION                 HTTP timeout, default 30s

Commands:
  attrs-from-pem --cert leaf-or-fullchain.pem --key privkey.pem [--chain chain.pem] [--root-ca ca.pem] --out attrs.json
  list [--filter EXPR]
  get --id CERT_ID
  find-domain --domain DOMAIN
  create --attrs attrs.json [--config-id ID] [--save-comment COMMENT] [--activate]
  update --id CERT_ID --attrs attrs.json [--config-id ID] [--save-comment COMMENT] [--activate]
  replace-with-new --old-cert-id CERT_ID --attrs attrs.json [--delete-old=false] [--config-id ID] [--save-comment COMMENT] [--activate]
  delete --id CERT_ID [--config-id ID] [--save-comment COMMENT] [--activate]
  connect-vh --cert-id CERT_ID --virtual-host-ids VH1,VH2 [--config-id ID] [--save-comment COMMENT] [--activate]
  disconnect-vh --cert-id CERT_ID --virtual-host-ids VH1,VH2 [--config-id ID] [--save-comment COMMENT] [--activate]
  connect --cert-id CERT_ID --relationship virtual-hosts --ids ID1,ID2 [--config-id ID] [--save-comment COMMENT] [--activate]
  disconnect --cert-id CERT_ID --relationship virtual-hosts --ids ID1,ID2 [--config-id ID] [--save-comment COMMENT] [--activate]
  validate
  save [--comment COMMENT]
  activate [--comment COMMENT]
  schema [--format json|yaml] [--out file]
  version

Examples:
  export AIRLOCK_HOST=gateway.example.com
  export AIRLOCK_API_KEY=...
  airlock-certctl attrs-from-pem --cert fullchain.pem --key privkey.pem --out cert-attrs.json
  airlock-certctl --insecure-skip-verify list
  airlock-certctl find-domain --domain www.example.com
  airlock-certctl update --id 123 --attrs cert-attrs.json --activate --activate-comment "rotate cert"
  airlock-certctl replace-with-new --old-cert-id 123 --attrs cert-attrs.json --activate --activate-comment "replace cert resource"
  airlock-certctl connect-vh --cert-id 123 --virtual-host-ids 456 --activate --activate-comment "attach cert"

Every command creates an Airlock REST session and loads the currently active configuration before it calls any configuration endpoint.
Mutating commands can then load a specific saved configuration with --config-id.

By default, command output redacts sensitive attributes such as privateKey, passwords, tokens, and secrets.
Use --show-secrets only in a secured shell when you explicitly need the raw values.

The --attrs file is the attributes object for the JSON:API ssl-certificate resource.
Use the schema command against your Gateway to verify the exact attribute names for your version.
`)
}
