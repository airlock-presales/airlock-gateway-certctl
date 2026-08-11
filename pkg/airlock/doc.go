// Package airlock provides a typed Airlock Gateway 8.x certificate lifecycle
// client.
//
// The managed API parses and validates certificate/key bundles locally and
// applies them atomically through an isolated Gateway configuration session:
//
//	bundle, err := airlock.ParseCertificateBundle(input)
//	if err != nil {
//		return err
//	}
//	result, err := client.SyncCertificate(ctx,
//		airlock.ForVirtualHost("www"), bundle,
//		airlock.SyncOptions{ActivationComment: "rotate certificate"})
//
// Typed CRUD methods are available for callers that intentionally manage
// working configurations themselves. Operations outside the supported
// certificate contract must be made through Client.Raw, making the loss of
// compile-time schema guarantees explicit.
//
// ForVirtualHost accepts the stable, operator-defined attributes.name returned
// by /configuration/virtual-hosts and hides numeric resource IDs. CertificateID,
// VirtualHostID, BackEndGroupID, RemoteJWKSID, and NodeID are JSON:API data.id
// values assigned and returned by Airlock Gateway; the library never invents
// them. Parameters and result properties are documented in docs/API.md in the
// module root.
package airlock
