package airlock_test

import (
	"context"

	"github.com/airlock-presales/airlock-gateway-certctl/pkg/airlock"
)

// releaseCertificateAPI is a compile-time lock on the supported public CRUD
// surface. An accidental return to string IDs or map attributes fails here.
type releaseCertificateAPI interface {
	ListSSLCertificates(context.Context, airlock.ListSSLCertificatesOptions) ([]airlock.SSLCertificateResource, error)
	GetSSLCertificate(context.Context, airlock.CertificateID) (airlock.SSLCertificateResource, error)
	CreateSSLCertificate(context.Context, airlock.SSLCertificateAttributes) (airlock.SSLCertificateResource, error)
	UpdateSSLCertificate(context.Context, airlock.CertificateID, airlock.SSLCertificateAttributes) (airlock.SSLCertificateResource, error)
	DeleteSSLCertificate(context.Context, airlock.CertificateID) error
	ConnectSSLCertificateToVirtualHosts(context.Context, airlock.CertificateID, ...airlock.VirtualHostID) error
	DisconnectSSLCertificateFromVirtualHosts(context.Context, airlock.CertificateID, ...airlock.VirtualHostID) error
}

var _ releaseCertificateAPI = (*airlock.Client)(nil)
