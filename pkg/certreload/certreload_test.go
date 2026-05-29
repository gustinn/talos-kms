// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package certreload_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gustinn/talos-kms/pkg/certreload"
)

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// genCert writes a fresh self-signed cert/key pair to certPath/keyPath and
// returns the PEM-encoded certificate bytes so tests can assert which cert is
// being served.
func genCert(t *testing.T, certPath, keyPath, cn string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return certPEM
}

func TestReloadOnChange(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	firstPEM := genCert(t, certPath, keyPath, "first")

	r, err := certreload.New(testLogger(), certPath, keyPath)
	require.NoError(t, err)

	got, err := r.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, firstPEM, pemOf(got.Certificate))

	// Rotate the files in place, as cert-manager would.
	secondPEM := genCert(t, certPath, keyPath, "second")

	got, err = r.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, secondPEM, pemOf(got.Certificate))
	require.NotEqual(t, firstPEM, secondPEM)
}

func TestReloadKeepsLastGoodOnBadWrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	firstPEM := genCert(t, certPath, keyPath, "first")

	r, err := certreload.New(testLogger(), certPath, keyPath)
	require.NoError(t, err)

	// Corrupt the cert file; reload should fail internally but keep serving.
	require.NoError(t, os.WriteFile(certPath, []byte("not a cert"), 0o600))

	got, err := r.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, firstPEM, pemOf(got.Certificate))
}

func TestNewFailsOnMissingFiles(t *testing.T) {
	t.Parallel()

	_, err := certreload.New(testLogger(), "/nonexistent/tls.crt", "/nonexistent/tls.key")
	require.Error(t, err)
}

func pemOf(der [][]byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der[0]})
}
