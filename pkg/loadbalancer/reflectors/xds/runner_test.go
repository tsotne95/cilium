// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBuildTransportCredentialsInsecureByDefault(t *testing.T) {
	creds, err := buildTransportCredentials(Config{})
	require.NoError(t, err)
	require.Equal(t, "insecure", creds.Info().SecurityProtocol)
}

func TestBuildTransportCredentialsRequiresCertAndKey(t *testing.T) {
	cfg := Config{ClientCertPath: "client.crt"}
	_, err := buildTransportCredentials(cfg)
	require.Error(t, err)

	cfg = Config{ClientKeyPath: "client.key"}
	_, err = buildTransportCredentials(cfg)
	require.Error(t, err)
}

func TestBuildTransportCredentialsWithTLS(t *testing.T) {
	dir := t.TempDir()
	caPath, certPath, keyPath := writeMTLSFiles(t, dir)

	cfg := Config{
		CACertPath:     caPath,
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
	}

	creds, err := buildTransportCredentials(cfg)
	require.NoError(t, err)
	require.Equal(t, "tls", creds.Info().SecurityProtocol)
}

func writeMTLSFiles(t *testing.T, dir string) (string, string, string) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xds-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "xds-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	certPath := filepath.Join(dir, "client.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))

	keyPath := filepath.Join(dir, "client.key")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return caPath, certPath, keyPath
}
