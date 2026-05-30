# Repository Guidelines

## Project Structure & Module Organization

This is a Go module for a Talos network KMS server. The executable entrypoint is
`cmd/kms-server/main.go`. Reusable packages live under `pkg/`: `server` contains
Seal/Unseal logic, `keyprovider` loads versioned AES keys, `metrics` exposes
Prometheus counters, and `certreload` handles TLS certificate reloads.

The gRPC protocol files are in `api/kms/`. Generated Go files are checked in.
The Helm chart lives
in `deploy/helm/talos-kms/`, with defaults in `values.yaml` and Kubernetes
templates in `templates/`.

## Build, Test, and Development Commands

- `go build ./cmd/kms-server` builds the server binary.
- `go test ./...` runs all unit tests.
- `go test -race ./...` runs the test suite with the race detector, matching CI.
- `go vet ./...` runs Go static checks used by CI.
- `golangci-lint run` runs the required Go linter used by CI.
- `gofmt -w cmd pkg` formats edited Go source.
- `docker build -t ghcr.io/gustinn/talos-kms:dev .` builds the scratch-based
  container image.
- `helm template talos-kms deploy/helm/talos-kms` renders the chart when Helm is
  installed.
- `goreleaser release --snapshot --clean --skip=publish` validates release
  archives, the Helm package, and container builds without publishing.

## Coding Style & Naming Conventions

Use standard Go formatting (`gofmt`) and idiomatic package-level names. Keep
errors wrapped with context using `fmt.Errorf("...: %w", err)`. Before opening a
PR, run `go vet ./...`, `go test -race ./...`, and `golangci-lint run`. Tests
should sit next to the package they exercise and use `TestName` functions in
`*_test.go`.

Keep Helm values lower camel case, matching existing keys such as
`bindClientIP`, `currentKeyId`, and `serviceMonitor`. Do not hand-edit generated
protobuf files unless regenerating the full set.

## Testing Guidelines

Add focused unit tests for crypto behavior, key loading, metrics, and reload
logic in the relevant `pkg/*` package. Prefer table-driven tests when checking
validation or multiple edge cases. For chart changes, render with
`helm template` and inspect the affected manifest, especially probes, ports,
volumes, and security settings.

## Commit & Pull Request Guidelines

Recent history uses short imperative subjects, sometimes with a conventional
prefix for CI/chore work, for example `Add plaintext HTTP probe endpoint` or
`ci: adapt renovate config for the fork`. Keep commits focused and avoid mixing
behavior, documentation, and generated output unless they are part of one change.

Pull requests should describe the user-facing behavior, call out configuration
or security implications, and list validation commands run. Link related issues
when available. Include rendered Helm snippets for chart changes when they help
review.

## Security & Configuration Tips

This service is boot-critical. Treat defaults and chart changes carefully.
TLS, key rotation, client IP binding, and probe behavior can affect whether
nodes unlock successfully. Never commit real key material, certificates, or
cluster-specific secrets.
