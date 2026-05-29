// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package keyprovider supplies versioned AES key material to the KMS server.
//
// A provider exposes a "current" key used to seal new data and lookup of any
// historical key by id used to unseal existing data. Because the server tags
// every sealed blob with the id of the key that sealed it, old data keeps
// unsealing as long as its key version remains available — rotation never
// requires re-sealing.
package keyprovider

import (
	"context"
	"crypto/aes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxKeyID bounds the key id length so it always fits the single-byte length
// prefix in the sealed blob header.
const maxKeyID = 255

// validateKey rejects keys that are not a valid AES key length, so a bad key is
// caught at startup rather than on a node's first boot.
func validateKey(id string, key []byte) error {
	if id == "" {
		return fmt.Errorf("key id must not be empty")
	}

	if len(id) > maxKeyID {
		return fmt.Errorf("key id %q exceeds %d bytes", id, maxKeyID)
	}

	if _, err := aes.NewCipher(key); err != nil {
		return fmt.Errorf("invalid AES key for id %q (need 16, 24, or 32 bytes): %w", id, err)
	}

	return nil
}

// Static provides a single key under a fixed id. It mirrors the original
// single-key behavior while still tagging blobs with a key id for rotation.
type Static struct {
	id  string
	key []byte
}

// NewStatic creates a Static provider, validating the key.
func NewStatic(id string, key []byte) (*Static, error) {
	if err := validateKey(id, key); err != nil {
		return nil, err
	}

	return &Static{id: id, key: append([]byte(nil), key...)}, nil
}

// Current returns the single key.
func (s *Static) Current(context.Context) (string, []byte, error) {
	return s.id, s.key, nil
}

// Get returns the key if id matches, else an error.
func (s *Static) Get(_ context.Context, id string) ([]byte, error) {
	if id != s.id {
		return nil, fmt.Errorf("unknown key id %q", id)
	}

	return s.key, nil
}

// Dir provides versioned keys loaded from a directory. Each regular file is one
// key version; the file name is the key id and its raw bytes are the key. One
// id is designated current (used to seal). This maps cleanly onto an
// external-secrets Secret mounted as a directory, where each version is a
// separate Secret key.
type Dir struct {
	currentID string
	keys      map[string][]byte
}

// NewDir loads all keys from dir and designates currentID as the sealing key.
// Subdirectories and dotfiles (e.g. the ..data symlink target Kubernetes uses
// for mounted Secrets) are skipped.
func NewDir(dir, currentID string) (*Dir, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read key dir: %w", err)
	}

	keys := make(map[string][]byte)

	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read key %q: %w", e.Name(), err)
		}

		if err := validateKey(e.Name(), data); err != nil {
			return nil, err
		}

		keys[e.Name()] = data
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found in %q", dir)
	}

	if _, ok := keys[currentID]; !ok {
		return nil, fmt.Errorf("current key id %q not found among %v", currentID, sortedIDs(keys))
	}

	return &Dir{currentID: currentID, keys: keys}, nil
}

// Current returns the configured current key.
func (d *Dir) Current(context.Context) (string, []byte, error) {
	return d.currentID, d.keys[d.currentID], nil
}

// Get returns the key for id, or an error if that version is not present.
func (d *Dir) Get(_ context.Context, id string) ([]byte, error) {
	key, ok := d.keys[id]
	if !ok {
		return nil, fmt.Errorf("unknown key id %q", id)
	}

	return key, nil
}

func sortedIDs(keys map[string][]byte) []string {
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	return ids
}
