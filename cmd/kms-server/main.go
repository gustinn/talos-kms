// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package main is a simple reference implementation of the KMS server.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/gustinn/talos-kms/api/kms"
	"github.com/gustinn/talos-kms/pkg/certreload"
	"github.com/gustinn/talos-kms/pkg/keyprovider"
	"github.com/gustinn/talos-kms/pkg/metrics"
	"github.com/gustinn/talos-kms/pkg/server"
)

// gracefulShutdownTimeout bounds how long we wait for in-flight Seal/Unseal
// calls to drain before forcing the server to stop.
const gracefulShutdownTimeout = 10 * time.Second

// maxRecvMsgSize caps inbound message size. Requests are a UUID plus a 32-byte
// passphrase, so 64 KiB is generous while keeping the DoS surface small.
const maxRecvMsgSize = 64 * 1024

var kmsFlags struct {
	apiEndpoint     string
	metricsEndpoint string
	keyPath         string
	keyDir          string
	currentKeyID    string
	tlsCertPath     string
	tlsKeyPath      string
	tlsEnable       bool
	bindClientIP    bool
}

func main() {
	flag.StringVar(&kmsFlags.apiEndpoint, "kms-api-endpoint", ":4050", "gRPC API endpoint for the KMS")
	flag.StringVar(&kmsFlags.metricsEndpoint, "metrics-endpoint", ":2122", "HTTP endpoint for Prometheus metrics (empty to disable)")
	flag.StringVar(&kmsFlags.keyPath, "key-path", "", "path to a single encryption key (mutually exclusive with --key-dir)")
	flag.StringVar(&kmsFlags.keyDir, "key-dir", "", "directory of versioned keys, one file per key id (mutually exclusive with --key-path)")
	flag.StringVar(&kmsFlags.currentKeyID, "current-key-id", "v1", "key id used to seal new data; with --key-dir it must name a file in the dir")
	flag.BoolVar(&kmsFlags.tlsEnable, "tls-enable", false, "whether to enable TLS or not")
	flag.StringVar(&kmsFlags.tlsCertPath, "tls-cert-path", "", "TLS server certificate path")
	flag.StringVar(&kmsFlags.tlsKeyPath, "tls-key-path", "", "TLS server key path")
	flag.BoolVar(&kmsFlags.bindClientIP, "bind-client-ip", false,
		"bind the client source IP into the sealed blob (requires stable node addresses)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	logger.Info("starting KMS server",
		slog.String("apiEndpoint", kmsFlags.apiEndpoint),
		slog.String("keyPath", kmsFlags.keyPath),
		slog.String("keyDir", kmsFlags.keyDir),
		slog.String("currentKeyID", kmsFlags.currentKeyID),
		slog.Bool("tlsEnable", kmsFlags.tlsEnable),
		slog.Bool("bindClientIP", kmsFlags.bindClientIP),
	)

	keys, err := keyProvider()
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	recorder := metrics.New(reg)

	opts, err := serverOptions(logger)
	if err != nil {
		return err
	}

	opts = append(opts, grpc.ChainUnaryInterceptor(recoveryInterceptor(logger)))

	srvOpts := []server.Option{server.WithObserver(recorder)}
	if kmsFlags.bindClientIP {
		srvOpts = append(srvOpts, server.WithClientIPBinding())
	}

	srv := server.NewServer(logger, keys, srvOpts...)

	s := grpc.NewServer(opts...)

	kms.RegisterKMSServiceServer(s, srv)

	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(s, healthSrv)
	healthSrv.SetServingStatus(kms.KMSService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", kmsFlags.apiEndpoint)
	if err != nil {
		return fmt.Errorf("error listening for gRPC API: %w", err)
	}

	eg, ctx := errgroup.WithContext(ctx)

	if kmsFlags.metricsEndpoint != "" {
		startMetricsServer(ctx, eg, logger, reg)
	}

	eg.Go(func() error {
		return s.Serve(lis)
	})

	eg.Go(func() error {
		<-ctx.Done()

		logger.Info("shutting down, draining in-flight requests")
		healthSrv.Shutdown()

		// GracefulStop waits for in-flight calls; fall back to a hard Stop if
		// they exceed the timeout so a stuck request can't block shutdown.
		stopped := make(chan struct{})

		go func() {
			s.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
		case <-time.After(gracefulShutdownTimeout):
			logger.Warn("graceful shutdown timed out, forcing stop")
			s.Stop()
		}

		return nil
	})

	if err := eg.Wait(); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}

	return nil
}

// keyProvider builds the key provider from the flags. Exactly one of
// --key-path (single key) or --key-dir (versioned keys) must be set. The key
// material is validated here so a bad config fails at startup, not on a node's
// first boot.
func keyProvider() (server.KeyProvider, error) {
	switch {
	case kmsFlags.keyPath != "" && kmsFlags.keyDir != "":
		return nil, errors.New("--key-path and --key-dir are mutually exclusive")
	case kmsFlags.keyDir != "":
		return keyprovider.NewDir(kmsFlags.keyDir, kmsFlags.currentKeyID)
	case kmsFlags.keyPath != "":
		key, err := os.ReadFile(kmsFlags.keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read key: %w", err)
		}

		return keyprovider.NewStatic(kmsFlags.currentKeyID, key)
	default:
		return nil, errors.New("one of --key-path or --key-dir must be set")
	}
}

// serverOptions builds the gRPC server options: transport credentials plus
// resource limits to bound the DoS surface of a boot-critical service.
func serverOptions(logger *slog.Logger) ([]grpc.ServerOption, error) {
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		grpc.ConnectionTimeout(10 * time.Second),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: 10 * time.Second,
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              2 * time.Hour,
			Timeout:           20 * time.Second,
		}),
	}

	if !kmsFlags.tlsEnable {
		return opts, nil
	}

	if kmsFlags.tlsCertPath == "" || kmsFlags.tlsKeyPath == "" {
		return nil, errors.New("--tls-cert-path and --tls-key-path must be set when --tls-enable is true")
	}

	// Reload the keypair from disk on change so cert-manager renewals are
	// picked up without restarting (a restart could coincide with a node
	// reboot that needs to unseal).
	reloader, err := certreload.New(logger, kmsFlags.tlsCertPath, kmsFlags.tlsKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	creds := credentials.NewTLS(&tls.Config{
		GetCertificate: reloader.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	})

	return append(opts, grpc.Creds(creds)), nil
}

// recoveryInterceptor turns a panic in a handler into a gRPC Internal error so
// a single bad request can't crash a boot-critical service.
func recoveryInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("recovered from panic in handler",
					slog.String("method", info.FullMethod),
					slog.Any("panic", r),
					slog.String("stack", string(debug.Stack())),
				)

				err = status.Error(codes.Internal, "internal error")
			}
		}()

		return handler(ctx, req)
	}
}

// startMetricsServer runs the Prometheus /metrics endpoint in the errgroup and
// shuts it down when the context is cancelled.
func startMetricsServer(ctx context.Context, eg *errgroup.Group, logger *slog.Logger, reg *prometheus.Registry) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	httpSrv := &http.Server{
		Addr:              kmsFlags.metricsEndpoint,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	eg.Go(func() error {
		logger.Info("starting metrics server", slog.String("endpoint", kmsFlags.metricsEndpoint))

		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("metrics server error: %w", err)
		}

		return nil
	})

	eg.Go(func() error {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
		defer cancel()

		return httpSrv.Shutdown(shutdownCtx)
	})
}
