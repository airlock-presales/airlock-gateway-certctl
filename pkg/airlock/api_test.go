package airlock_test

import (
	"context"

	"github.com/airlock-presales/airlock-gateway-certctl/pkg/airlock"
)

// releaseCertificateAPI is a compile-time lock on the supported public CRUD
// surface. An accidental return to string IDs or map attributes fails here.
type releaseCertificateAPI interface {
	GatewayVersion(context.Context) (string, error)
	ValidateConfiguration(context.Context) ([]airlock.ValidationMessage, error)
	ListSSLCertificates(context.Context, airlock.ListSSLCertificatesOptions) ([]airlock.SSLCertificateResource, error)
	GetSSLCertificate(context.Context, airlock.CertificateID) (airlock.SSLCertificateResource, error)
	CreateSSLCertificate(context.Context, airlock.SSLCertificateAttributes) (airlock.SSLCertificateResource, error)
	UpdateSSLCertificate(context.Context, airlock.CertificateID, airlock.SSLCertificateAttributes) (airlock.SSLCertificateResource, error)
	DeleteSSLCertificate(context.Context, airlock.CertificateID) error
	ConnectSSLCertificateToVirtualHosts(context.Context, airlock.CertificateID, ...airlock.VirtualHostID) error
	DisconnectSSLCertificateFromVirtualHosts(context.Context, airlock.CertificateID, ...airlock.VirtualHostID) error
	SetVirtualHostCertificate(context.Context, airlock.VirtualHostID, airlock.CertificateID) error
	RemoveVirtualHostCertificate(context.Context, airlock.VirtualHostID, airlock.CertificateID) error
	GetManagedCertificate(context.Context, airlock.CertificateTarget) (airlock.ManagedCertificate, error)
	GetManagedCertificateWithOptions(context.Context, airlock.CertificateTarget, airlock.ReadOptions) (airlock.ManagedCertificate, error)
}

var _ releaseCertificateAPI = (*airlock.Client)(nil)

var (
	_ error = (*airlock.APIError)(nil)
	_ error = (*airlock.VersionSkewError)(nil)
)
