// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package certreload provides a TLS certificate that reloads from disk when the
// underlying files change, so externally-rotated certificates (e.g. renewed by
// cert-manager) are picked up without restarting the process.
package certreload

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// Reloader holds a TLS keypair and reloads it from disk when the cert or key
// file content changes. It is safe for concurrent use.
type Reloader struct {
	logger   *slog.Logger
	certPath string
	keyPath  string

	mu       sync.RWMutex
	cert     *tls.Certificate
	certData []byte
	keyData  []byte
}

// New creates a Reloader and loads the initial keypair, failing if it cannot be
// read or parsed.
func New(logger *slog.Logger, certPath, keyPath string) (*Reloader, error) {
	r := &Reloader{
		logger:   logger,
		certPath: certPath,
		keyPath:  keyPath,
	}

	if _, err := r.reload(); err != nil {
		return nil, err
	}

	return r, nil
}

// GetCertificate is suitable for tls.Config.GetCertificate. It returns the
// cached certificate, reloading first if the files on disk have changed. On a
// reload error it logs and falls back to the last good certificate so a bad
// write can't take the listener down.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	changed, err := r.reload()
	if err != nil {
		r.logger.Error("failed to reload TLS certificate, serving previous one", slog.Any("error", err))
	} else if changed {
		r.logger.Info("reloaded TLS certificate")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.cert == nil {
		return nil, fmt.Errorf("no TLS certificate available")
	}

	return r.cert, nil
}

// reload reads the cert/key files and, if their content differs from what is
// cached, parses and swaps in the new keypair. It reports whether a swap
// happened.
func (r *Reloader) reload() (bool, error) {
	certData, err := os.ReadFile(r.certPath)
	if err != nil {
		return false, fmt.Errorf("failed to read cert: %w", err)
	}

	keyData, err := os.ReadFile(r.keyPath)
	if err != nil {
		return false, fmt.Errorf("failed to read key: %w", err)
	}

	r.mu.RLock()
	unchanged := r.cert != nil && bytesEqual(certData, r.certData) && bytesEqual(keyData, r.keyData)
	r.mu.RUnlock()

	if unchanged {
		return false, nil
	}

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return false, fmt.Errorf("failed to parse keypair: %w", err)
	}

	r.mu.Lock()
	r.cert = &cert
	r.certData = certData
	r.keyData = keyData
	r.mu.Unlock()

	return true, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
