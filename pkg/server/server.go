// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package server implements a reference server for the KMS.
package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/gustinn/talos-kms/api/kms"
	"github.com/gustinn/talos-kms/pkg/constants"
)

// blobFormatV1 is the first byte of every sealed blob. It lets the format
// evolve (e.g. a new AEAD) without ambiguity, and is authenticated so an
// attacker cannot downgrade it.
const blobFormatV1 byte = 1

// KeyProvider supplies versioned AES key material. Current returns the key used
// to seal new data along with its id; Get returns a historical key by the id
// recorded in a sealed blob. Tagging each blob with its key id is what lets
// rotation happen without re-sealing existing data.
//
// Keys are not per-node: per-node isolation is provided cryptographically by
// binding the node UUID (and optionally source IP) into the AEAD, so the
// provider does not take a node UUID.
type KeyProvider interface {
	Current(ctx context.Context) (id string, key []byte, err error)
	Get(ctx context.Context, id string) (key []byte, err error)
}

// Operation identifies a KMS RPC for metrics and audit.
type Operation string

// KMS operations.
const (
	OpSeal   Operation = "seal"
	OpUnseal Operation = "unseal"
)

// Outcome is the result classification of a request, used as a metric label and
// in the audit log. It is deliberately low-cardinality.
type Outcome string

// Request outcomes.
const (
	// OutcomeSuccess: data was sealed, or unsealed and authenticated.
	OutcomeSuccess Outcome = "success"
	// OutcomeAuthFailure: Unseal could not authenticate the blob (wrong key,
	// tampered data, or mismatched node UUID / source IP). Random data is
	// returned to the caller; this is an expected, not an error, condition.
	OutcomeAuthFailure Outcome = "auth_failure"
	// OutcomeKeyError: the key backend failed to provide a usable key (backend
	// failure, or a blob referencing a key version that is no longer present).
	OutcomeKeyError Outcome = "key_error"
	// OutcomeInvalidArgument: the request was malformed (e.g. wrong data length).
	OutcomeInvalidArgument Outcome = "invalid_argument"
	// OutcomeInternalError: an unexpected internal failure (e.g. RNG failure).
	OutcomeInternalError Outcome = "internal_error"
)

// Observer receives a record for every completed request. Implementations must
// be safe for concurrent use and must not block. The default is a no-op.
//
// node UUID is deliberately not passed here: it is high-cardinality and unfit
// as a metric label. It is recorded in the audit log instead.
type Observer interface {
	RecordRequest(op Operation, outcome Outcome, duration time.Duration)
}

type noopObserver struct{}

func (noopObserver) RecordRequest(Operation, Outcome, time.Duration) {}

// Server implements the gRPC KMS API.
type Server struct {
	kms.UnimplementedKMSServiceServer

	logger       *slog.Logger
	keys         KeyProvider
	observer     Observer
	bindClientIP bool
}

// Option configures a Server.
type Option func(*Server)

// WithClientIPBinding binds the client's source IP into the AEAD additional
// authenticated data. A blob sealed by a node can then only be unsealed from
// the same source IP, in addition to the same node UUID.
//
// Enable this only when nodes have stable addresses: a node that changes IP
// (DHCP lease change, re-IP) will no longer be able to unseal and will fail to
// unlock its disk.
func WithClientIPBinding() Option {
	return func(srv *Server) { srv.bindClientIP = true }
}

// WithObserver installs an Observer that receives a record for every request.
func WithObserver(o Observer) Option {
	return func(srv *Server) { srv.observer = o }
}

// NewServer initializes a new server backed by the given key provider.
func NewServer(logger *slog.Logger, keys KeyProvider, opts ...Option) *Server {
	srv := &Server{
		logger:   logger,
		keys:     keys,
		observer: noopObserver{},
	}

	for _, opt := range opts {
		opt(srv)
	}

	return srv
}

// Seal encrypts the incoming data.
func (srv *Server) Seal(ctx context.Context, req *kms.Request) (*kms.Response, error) {
	start := time.Now()
	resp, outcome, err := srv.seal(ctx, req)
	srv.record(ctx, OpSeal, outcome, time.Since(start), req.NodeUuid)

	return resp, err
}

func (srv *Server) seal(ctx context.Context, req *kms.Request) (*kms.Response, Outcome, error) {
	if len(req.Data) != constants.PassphraseSize {
		return nil, OutcomeInvalidArgument, status.Error(codes.InvalidArgument, "incorrect data length")
	}

	keyID, key, err := srv.keys.Current(ctx)
	if err != nil {
		srv.logger.Error("key provider failed to return current key", slog.Any("error", err))

		return nil, OutcomeKeyError, status.Error(codes.Internal, "failed to seal data")
	}

	aesgcm, err := newAEAD(key)
	if err != nil {
		srv.logger.Error("failed to construct cipher", slog.String("key_id", keyID), slog.Any("error", err))

		return nil, OutcomeKeyError, status.Error(codes.Internal, "failed to seal data")
	}

	// header = format version || keyID; it is prepended to the blob and also
	// authenticated (see additionalData) so it cannot be tampered or downgraded.
	header := encodeHeader(keyID)

	aad, err := srv.additionalData(ctx, req.NodeUuid, header)
	if err != nil {
		return nil, OutcomeInternalError, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, OutcomeInternalError, status.Error(codes.Internal, "failed to generate nonce")
	}

	// Blob layout: header || nonce || ciphertext || tag. Seal appends onto the
	// header+nonce prefix so the whole thing is one contiguous slice.
	prefix := append(header, nonce...) //nolint:gocritic // intentional new slice
	blob := aesgcm.Seal(prefix, nonce, req.Data, aad)

	return &kms.Response{Data: blob}, OutcomeSuccess, nil
}

// Unseal decrypts the incoming data.
func (srv *Server) Unseal(ctx context.Context, req *kms.Request) (*kms.Response, error) {
	start := time.Now()
	resp, outcome, err := srv.unseal(ctx, req)
	srv.record(ctx, OpUnseal, outcome, time.Since(start), req.NodeUuid)

	return resp, err
}

func (srv *Server) unseal(ctx context.Context, req *kms.Request) (*kms.Response, Outcome, error) {
	keyID, header, rest, err := decodeHeader(req.Data)
	if err != nil {
		return nil, OutcomeInvalidArgument, status.Error(codes.InvalidArgument, "incorrect data format")
	}

	key, err := srv.keys.Get(ctx, keyID)
	if err != nil {
		// The blob references a key version we don't have. This is operationally
		// serious (a removed-but-still-used key bricks the node), so log it
		// loudly as a key error. We still return random data rather than an
		// error, to avoid leaking which ids are known.
		srv.logger.Error("blob references unknown key id",
			slog.String("key_id", keyID),
			slog.String("node_uuid", req.NodeUuid),
			slog.Any("error", err),
		)

		return randomResponse(OutcomeKeyError)
	}

	aesgcm, err := newAEAD(key)
	if err != nil {
		srv.logger.Error("failed to construct cipher", slog.String("key_id", keyID), slog.Any("error", err))

		return nil, OutcomeKeyError, status.Error(codes.Internal, "failed to unseal data")
	}

	nonceSize := aesgcm.NonceSize()

	if len(rest) != nonceSize+constants.PassphraseSize+aesgcm.Overhead() {
		return nil, OutcomeInvalidArgument, status.Error(codes.InvalidArgument, "incorrect data length")
	}

	aad, err := srv.additionalData(ctx, req.NodeUuid, header)
	if err != nil {
		return nil, OutcomeInternalError, err
	}

	decrypted, err := aesgcm.Open(nil, rest[:nonceSize], rest[nonceSize:], aad)
	if err != nil {
		// Authentication failed: wrong key, tampered blob, or a mismatched node
		// UUID / source IP (the AEAD additional data). Return random data rather
		// than an error so the caller cannot use this as a decryption oracle.
		return randomResponse(OutcomeAuthFailure)
	}

	return &kms.Response{Data: decrypted}, OutcomeSuccess, nil
}

// randomResponse returns a passphrase-sized buffer of random bytes with the
// given outcome, used for the anti-oracle paths in Unseal.
func randomResponse(outcome Outcome) (*kms.Response, Outcome, error) {
	resp := &kms.Response{Data: make([]byte, constants.PassphraseSize)}

	if _, err := io.ReadFull(rand.Reader, resp.Data); err != nil {
		return nil, OutcomeInternalError, status.Error(codes.Internal, "failed to generate random data")
	}

	return resp, outcome, nil
}

// encodeHeader builds the blob header: format version || len(keyID) || keyID.
// The caller guarantees len(keyID) fits in a byte (validated by the provider).
func encodeHeader(keyID string) []byte {
	header := make([]byte, 0, 2+len(keyID))
	header = append(header, blobFormatV1, byte(len(keyID)))
	header = append(header, keyID...)

	return header
}

// decodeHeader parses the header from a blob and returns the key id, the raw
// header bytes (for AAD), and the remaining ciphertext.
func decodeHeader(blob []byte) (keyID string, header, rest []byte, err error) {
	if len(blob) < 2 || blob[0] != blobFormatV1 {
		return "", nil, nil, status.Error(codes.InvalidArgument, "unknown blob format")
	}

	idLen := int(blob[1])

	end := 2 + idLen
	if idLen == 0 || len(blob) < end {
		return "", nil, nil, status.Error(codes.InvalidArgument, "truncated header")
	}

	return string(blob[2:end]), blob[:end], blob[end:], nil
}

// newAEAD constructs an AES-GCM AEAD from a key.
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// record reports a completed request to the observer (metrics) and writes a
// structured audit log line. This is the single place outcomes are surfaced.
func (srv *Server) record(ctx context.Context, op Operation, outcome Outcome, dur time.Duration, nodeUUID string) {
	srv.observer.RecordRequest(op, outcome, dur)

	attrs := []any{
		slog.String("operation", string(op)),
		slog.String("outcome", string(outcome)),
		slog.String("node_uuid", nodeUUID),
		slog.String("client_ip", clientIPString(ctx)),
		slog.Duration("duration", dur),
	}

	// Key/internal errors are operator-actionable; everything else (including
	// auth failures, which are expected) is an audit-level info record.
	if outcome == OutcomeKeyError || outcome == OutcomeInternalError {
		srv.logger.Error("kms request failed", attrs...)

		return
	}

	srv.logger.Info("kms request", attrs...)
}

// additionalData builds the AEAD additional authenticated data that binds a
// sealed blob to its header and to the node. The blob header (format + key id)
// and node UUID are always included; the client source IP is added when IP
// binding is enabled. The data is not encrypted, but the blob cannot be
// unsealed unless the exact same additional data is presented.
func (srv *Server) additionalData(ctx context.Context, nodeUUID string, header []byte) ([]byte, error) {
	aad := make([]byte, 0, len(header)+1+len(nodeUUID))
	aad = append(aad, header...)
	// NUL separators so the concatenated fields can't collide.
	aad = append(aad, 0)
	aad = append(aad, nodeUUID...)

	if !srv.bindClientIP {
		return aad, nil
	}

	ip, err := clientIP(ctx)
	if err != nil {
		return nil, err
	}

	aad = append(aad, 0)
	aad = append(aad, ip...)

	return aad, nil
}

// clientIP extracts the source IP of the gRPC peer, normalized to 16 bytes.
func clientIP(ctx context.Context) ([]byte, error) {
	host, ok := peerHost(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "no peer address available for IP binding")
	}

	if ip := net.ParseIP(host); ip != nil {
		// Normalize so 127.0.0.1 and ::ffff:127.0.0.1 bind identically.
		return ip.To16(), nil
	}

	return []byte(host), nil
}

// clientIPString returns the peer IP for audit logging, or "unknown".
func clientIPString(ctx context.Context) string {
	if host, ok := peerHost(ctx); ok {
		return host
	}

	return "unknown"
}

func peerHost(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "", false
	}

	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		// Address may not carry a port depending on the transport.
		host = p.Addr.String()
	}

	return host, true
}
