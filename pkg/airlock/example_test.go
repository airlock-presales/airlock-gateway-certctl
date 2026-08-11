package airlock_test

import (
	"context"
	"log"
	"os"

	"github.com/airlock-presales/airlock-gateway-certctl/pkg/airlock"
)

func ExampleClient_SyncCertificate() {
	certificatePEM, err := os.ReadFile("fullchain-leaf.pem")
	if err != nil {
		log.Print(err)
		return
	}
	privateKeyPEM, err := os.ReadFile("private-key.pem")
	if err != nil {
		log.Print(err)
		return
	}
	bundle, err := airlock.ParseCertificateBundle(airlock.CertificateBundleInput{
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  privateKeyPEM,
	})
	if err != nil {
		log.Print(err)
		return
	}
	client, err := airlock.New(airlock.Config{
		Address: "gateway.example.com",
		APIKey:  os.Getenv("AIRLOCK_API_KEY"),
	})
	if err != nil {
		log.Print(err)
		return
	}
	_, err = client.SyncCertificate(
		context.Background(),
		airlock.ForVirtualHost("www"),
		bundle,
		airlock.SyncOptions{ActivationComment: "rotate certificate"},
	)
	if err != nil {
		log.Print(err)
	}
}
