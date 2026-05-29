// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package keyprovider_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gustinn/talos-kms/pkg/keyprovider"
)

func key32() []byte { return make([]byte, 32) }

func TestStatic(t *testing.T) {
	t.Parallel()

	p, err := keyprovider.NewStatic("v1", key32())
	require.NoError(t, err)

	id, k, err := p.Current(t.Context())
	require.NoError(t, err)
	require.Equal(t, "v1", id)
	require.Len(t, k, 32)

	got, err := p.Get(t.Context(), "v1")
	require.NoError(t, err)
	require.Equal(t, k, got)

	_, err = p.Get(t.Context(), "v2")
	require.Error(t, err)
}

func TestStaticRejectsBadKey(t *testing.T) {
	t.Parallel()

	_, err := keyprovider.NewStatic("v1", make([]byte, 7))
	require.Error(t, err)

	_, err = keyprovider.NewStatic("", key32())
	require.Error(t, err)
}

func TestDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "v1"), key32(), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "v2"), key32(), 0o600))
	// Kubernetes-mounted Secrets contain a ..data symlink and .dotfiles; ensure
	// they are skipped.
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".hidden"), []byte("junk"), 0o600))

	p, err := keyprovider.NewDir(dir, "v2")
	require.NoError(t, err)

	id, _, err := p.Current(t.Context())
	require.NoError(t, err)
	require.Equal(t, "v2", id)

	_, err = p.Get(t.Context(), "v1")
	require.NoError(t, err)

	_, err = p.Get(t.Context(), "v3")
	require.Error(t, err)
}

func TestDirMissingCurrent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "v1"), key32(), 0o600))

	_, err := keyprovider.NewDir(dir, "v2")
	require.ErrorContains(t, err, "not found")
}

func TestDirEmpty(t *testing.T) {
	t.Parallel()

	_, err := keyprovider.NewDir(t.TempDir(), "v1")
	require.ErrorContains(t, err, "no keys")
}

func TestDirRejectsBadKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "v1"), make([]byte, 9), 0o600))

	_, err := keyprovider.NewDir(dir, "v1")
	require.Error(t, err)
}
