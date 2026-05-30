# talos-kms

A network **KMS server for [Talos Linux](https://www.talos.dev) disk
encryption**.
Talos nodes can seal their LUKS volume keys against a network KMS and unseal
them on every boot; this is the server side of that protocol.

## Why this exists

I wanted full-disk encryption on Talos nodes that **don't have TPM 2.0**.
Talos can encrypt the `STATE` and `EPHEMERAL` partitions, but its stronger
unlock methods assume a TPM; without one, the practical alternative is the
`kms` key provider, which seals each node's volume key against a network KMS
and asks for it back at boot.
That needs a KMS server to talk to — and the upstream one is an explicitly
minimal reference, not something meant to run as real infrastructure.
This fork is that server, hardened enough to actually depend on for booting a
cluster.

> **Fork notice.**
> This is a fork of
> [`siderolabs/kms-client`](https://github.com/siderolabs/kms-client).
> It keeps the same wire protocol but hardens it for real use: per-node
> cryptographic binding, versioned keys with zero-downtime rotation, TLS with
> hot reload, Prometheus metrics + audit logging, graceful shutdown, and a Helm
> chart.

## How Talos KMS encryption works

When a node uses the `kms` disk-encryption key provider, on first boot it
generates a random volume key, calls **`Seal`** to encrypt it against the KMS,
and stores the returned blob in its disk metadata.
On every subsequent boot it sends that blob back via **`Unseal`** to recover the
volume key and unlock the disk.

```
┌────────────┐   Seal(node_uuid, volumeKey)   ┌─────────────┐
│ Talos node │ ─────────────────────────────> │             │
│  (boot)    │ <───────────────────────────── │  talos-kms  │
│            │        sealed blob             │             │
│            │                                │  AES-256-GCM│
│            │   Unseal(node_uuid, blob)      │  + key store│
│            │ ─────────────────────────────> │             │
│            │ <───────────────────────────── │             │
└────────────┘        volumeKey               └─────────────┘
```

The KMS is therefore **boot-critical**: nodes cannot unlock their disks while it
is unavailable.

### What the Talos client gives you (and doesn't)

The client config is a single endpoint string
(`machine.systemDiskEncryption.<partition>.keys[].kms.endpoint`).
From the Talos source:

- Transport is **one-way TLS** for non-`tcp://` endpoints (the server is
  verified against the **system/public** CA store), or plaintext for `tcp://`.
- There is **no client authentication** — no mTLS, no client certs.
  The only caller-supplied identity is `node_uuid`, an unauthenticated string in
  the request body.

This shapes the security model below.
Since the caller cannot be authenticated, isolation between nodes must come from
the cryptography, not from access control.

## Security model

- **AES-256-GCM** for all sealing, with a random 96-bit nonce per operation.
- **Per-node binding via AEAD additional data.**
  The `node_uuid` (and, optionally, the client source IP) is bound as GCM
  additional authenticated data.
  A blob sealed for one node returns garbage if presented by another — even
  though the server may use one shared key.
  This is what provides per-node isolation in the absence of client auth.
- **Anti-oracle responses.**
  A failed `Unseal` (wrong key, tampered blob, or mismatched UUID/IP) returns
  *random data*, not an error, so the endpoint can't be used as a decryption
  oracle.
- **Self-describing, versioned blob format**, which enables key rotation without
  re-sealing existing data:

  ```
  ┌──────────┬───────────┬─────────┬──────────┬─────────────────┐
  │ format=1 │ len(keyID)│  keyID  │  nonce   │ ciphertext+tag  │
  │  1 byte  │  1 byte   │ N bytes │ 12 bytes │                 │
  └──────────┴───────────┴─────────┴──────────┴─────────────────┘
  AAD = header ‖ node_uuid [‖ 0x00 ‖ client_ip]
  ```

  The header (format + key id) is authenticated in the AAD, so it cannot be
  downgraded or have its key id swapped.

Talos treats the blob as opaque bytes, so the versioned header is transparent to
the node.

## TLS: the STATE-partition constraint

If nodes KMS-encrypt their **`STATE`** partition, the Talos client validates the
KMS server using **only the system/public CA store** — at unlock time the
machine-config trusted CAs live in the not-yet-mounted STATE partition.
In that case the server **must** present a **publicly-trusted (ACME /
Let's Encrypt) certificate**; an internal/self-signed CA will not validate.
If only the `EPHEMERAL` partition is KMS-encrypted, STATE is already mounted and
an internal CA can work.
The Helm chart and its README cover this in detail.

## Configuration

| Flag | Default | Description |
| --- | --- | --- |
| `--kms-api-endpoint` | `:4050` | gRPC API listen address |
| `--metrics-endpoint` | `:2122` | Prometheus `/metrics` listen address (empty to disable) |
| `--key-path` | | Path to a single key file (mutually exclusive with `--key-dir`) |
| `--key-dir` | | Directory of versioned keys, one file per key id |
| `--current-key-id` | `v1` | Key id used to seal new data |
| `--tls-enable` | `false` | Enable TLS |
| `--tls-cert-path` | | Server certificate (PEM); hot-reloaded on change |
| `--tls-key-path` | | Server private key (PEM); hot-reloaded on change |
| `--bind-client-ip` | `true` | Also bind the client source IP into sealed blobs |

Keys must be a valid AES length (16, 24, or 32 bytes); they are validated at
startup so a bad key fails fast instead of on a node's first boot.
`--key-dir` maps cleanly onto a Kubernetes Secret mounted as a directory, where
each key version is a separate Secret entry.

`--bind-client-ip` ties a blob to the node's source IP.
Disable it only when nodes do not have stable addresses — a node that changes
IP (DHCP renewal, re-IP) will no longer be able to unseal while it is enabled.

### Key rotation (no re-seal)

Because every blob records the id of the key that sealed it, rotation never
requires re-sealing:

1. Add a new key version to the key store and roll out — now all replicas can
   *unseal* with it.
2. Set `--current-key-id` to the new version — new data *seals* with it.
3. Keep the old version until no node's stored blob still references it.
   Watch `kms_requests_total{outcome="key_error"}` before pruning.

## Build and run

```sh
# Build
go build ./cmd/kms-server

# Generate a key and run with TLS
head -c 32 /dev/urandom > key
./kms-server \
  --key-path=./key \
  --current-key-id=v1 \
  --tls-enable --tls-cert-path=tls.crt --tls-key-path=tls.key
```

Corresponding Talos machine config:

```yaml
machine:
  systemDiskEncryption:
    state:
      provider: luks2
      keys:
        - slot: 0
          kms:
            endpoint: https://kms.example.com:4050
```

### Container image

```sh
docker build -t ghcr.io/gustinn/talos-kms:dev .
```

The image is built `FROM scratch` (static binary), so it runs comfortably as a
non-root, read-only-rootfs container.

## Kubernetes

A Helm chart lives in [`deploy/helm/talos-kms`](deploy/helm/talos-kms).
It is designed to run the KMS on **control-plane nodes** (unlocked by another
method, so they don't depend on the KMS) while serving worker nodes — avoiding a
cold-start deadlock.
It wires up [external-secrets](https://external-secrets.io) for versioned keys
and [cert-manager](https://cert-manager.io) (ACME) for TLS.
See the chart's [README](deploy/helm/talos-kms/README.md).

## Observability

- **Metrics** on `--metrics-endpoint`:
  - `kms_requests_total{operation,outcome}` — `operation` is `seal`/`unseal`;
    `outcome` is `success`, `auth_failure`, `key_error`, `invalid_argument`, or
    `internal_error`.
  - `kms_request_duration_seconds{operation}` — latency histogram.
- **Audit log**: every request emits a structured JSON line (operation, outcome,
  node UUID, client IP, duration).
  Node UUID is kept out of metric labels (high cardinality) and recorded only in
  the audit log.

## Development

```sh
go test -race ./...   # unit tests
go vet ./...
gofmt -l cmd pkg      # should print nothing
```
