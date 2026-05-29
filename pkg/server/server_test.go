// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/gustinn/talos-kms/api/kms"
	"github.com/gustinn/talos-kms/pkg/server"
)

const testNodeUUID = "abcd"

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)

	_, err := io.ReadFull(rand.Reader, b)
	require.NoError(t, err)

	return b
}

// fakeProvider is a test KeyProvider holding versioned keys with a designated
// current id. It supports the same key for every node so per-node isolation is
// exercised through the AEAD binding, not the provider.
type fakeProvider struct {
	err     error
	keys    map[string][]byte
	current string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()

	return &fakeProvider{
		current: "v1",
		keys:    map[string][]byte{"v1": randomBytes(t, 32)},
	}
}

func (f *fakeProvider) Current(context.Context) (string, []byte, error) {
	if f.err != nil {
		return "", nil, f.err
	}

	return f.current, f.keys[f.current], nil
}

func (f *fakeProvider) Get(_ context.Context, id string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}

	k, ok := f.keys[id]
	if !ok {
		return nil, errors.New("unknown key id")
	}

	return k, nil
}

func newServer(t *testing.T, opts ...server.Option) (*server.Server, *fakeProvider) {
	t.Helper()

	p := newFakeProvider(t)

	return server.NewServer(testLogger(), p, opts...), p
}

func ctxWithIP(t *testing.T, ip string) context.Context {
	t.Helper()

	return peer.NewContext(t.Context(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 12345},
	})
}

func TestSealUnseal(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)
	passphrase := randomBytes(t, 32)
	ctx := t.Context()

	encrypted, err := srv.Seal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: passphrase})
	require.NoError(t, err)
	require.NotEmpty(t, encrypted.Data)

	decrypted, err := srv.Unseal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: encrypted.Data})
	require.NoError(t, err)
	require.True(t, bytes.Equal(passphrase, decrypted.Data))
}

// TestNodeUUIDIsolation proves the blob is bound to its node UUID even when the
// provider returns the same key for every node.
func TestNodeUUIDIsolation(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)
	passphrase := randomBytes(t, 32)
	ctx := t.Context()

	encrypted, err := srv.Seal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: passphrase})
	require.NoError(t, err)

	decrypted, err := srv.Unseal(ctx, &kms.Request{NodeUuid: "abce", Data: encrypted.Data})
	require.NoError(t, err) // anti-oracle: returns random data, not an error
	require.False(t, bytes.Equal(passphrase, decrypted.Data))
}

func TestTamperedData(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)
	passphrase := randomBytes(t, 32)
	ctx := t.Context()

	encrypted, err := srv.Seal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: passphrase})
	require.NoError(t, err)

	// Flip a byte in the ciphertext body (past the header).
	encrypted.Data[len(encrypted.Data)-1] ^= 0xFF

	decrypted, err := srv.Unseal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: encrypted.Data})
	require.NoError(t, err)
	require.False(t, bytes.Equal(passphrase, decrypted.Data))
}

// TestKeyRotationNoReseal proves a blob sealed under an old key still unseals
// after the current key is rotated forward, with no re-sealing.
func TestKeyRotationNoReseal(t *testing.T) {
	t.Parallel()

	srv, p := newServer(t)
	passphrase := randomBytes(t, 32)
	ctx := t.Context()

	// Seal under v1.
	encrypted, err := srv.Seal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: passphrase})
	require.NoError(t, err)

	// Rotate: add v2 and make it current.
	p.keys["v2"] = randomBytes(t, 32)
	p.current = "v2"

	// New seals use v2...
	enc2, err := srv.Seal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: passphrase})
	require.NoError(t, err)
	require.NotEqual(t, encrypted.Data[:4], enc2.Data[:4]) // headers differ (v1 vs v2)

	// ...but the old v1 blob still unseals because v1 is still present.
	decrypted, err := srv.Unseal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: encrypted.Data})
	require.NoError(t, err)
	require.True(t, bytes.Equal(passphrase, decrypted.Data))
}

// TestUnknownKeyVersion: a blob referencing a removed key version returns
// random data (anti-oracle) but is classified as a key error for alerting.
func TestUnknownKeyVersion(t *testing.T) {
	t.Parallel()

	srv, p := newServer(t)
	passphrase := randomBytes(t, 32)
	ctx := t.Context()

	encrypted, err := srv.Seal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: passphrase})
	require.NoError(t, err)

	// Remove the key version the blob was sealed under.
	delete(p.keys, "v1")

	decrypted, err := srv.Unseal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: encrypted.Data})
	require.NoError(t, err)
	require.False(t, bytes.Equal(passphrase, decrypted.Data))
}

func TestClientIPBinding(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t, server.WithClientIPBinding())
	passphrase := randomBytes(t, 32)

	encrypted, err := srv.Seal(ctxWithIP(t, "10.0.0.1"), &kms.Request{NodeUuid: testNodeUUID, Data: passphrase})
	require.NoError(t, err)

	decrypted, err := srv.Unseal(ctxWithIP(t, "10.0.0.1"), &kms.Request{NodeUuid: testNodeUUID, Data: encrypted.Data})
	require.NoError(t, err)
	require.True(t, bytes.Equal(passphrase, decrypted.Data))

	decrypted, err = srv.Unseal(ctxWithIP(t, "10.0.0.2"), &kms.Request{NodeUuid: testNodeUUID, Data: encrypted.Data})
	require.NoError(t, err)
	require.False(t, bytes.Equal(passphrase, decrypted.Data))
}

func TestClientIPBindingFailsClosed(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t, server.WithClientIPBinding())

	_, err := srv.Seal(t.Context(), &kms.Request{NodeUuid: testNodeUUID, Data: randomBytes(t, 32)})
	require.Equal(t, codes.Internal, status.Code(err))
}

func TestKeyProviderErrorOnSeal(t *testing.T) {
	t.Parallel()

	srv, p := newServer(t)
	p.err = errors.New("backend down")

	_, err := srv.Seal(t.Context(), &kms.Request{NodeUuid: testNodeUUID, Data: randomBytes(t, 32)})
	require.Equal(t, codes.Internal, status.Code(err))
}

func TestInvalidInputs(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t)
	ctx := t.Context()

	// Wrong passphrase length on Seal.
	_, err := srv.Seal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: randomBytes(t, 64)})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	// Empty data on Unseal (no header).
	_, err = srv.Unseal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: make([]byte, 0)})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	// Valid header but garbage/short body.
	_, err = srv.Unseal(ctx, &kms.Request{NodeUuid: testNodeUUID, Data: append(server.EncodeHeader("v1"), 1, 2, 3)})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
