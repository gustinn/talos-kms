# talos-kms Helm chart

Deploys the Talos Linux network KMS server (Seal/Unseal for disk encryption).

## Architecture

This chart is built for the following topology:

- **Control-plane nodes** are unlocked by another method (TPM/static) and do
  **not** depend on the KMS. The KMS pods are pinned here (`nodeSelector` +
  control-plane toleration) so a full cold start cannot deadlock.
- **Worker nodes** KMS-encrypt their `STATE` partition and dial this service on
  boot to unseal.

## The TLS constraint (read this first)

When a worker unlocks its `STATE` partition, that partition is not yet mounted,
so the machine-config trusted CAs are unavailable. The Talos KMS client
validates the server using only the **system/public CA trust store**
(`httpdefaults.RootCAs()`). Consequences:

- The KMS server cert **must** chain to a public root — i.e. an **ACME /
  Let's Encrypt** certificate. A cluster-internal cert-manager CA or a
  self-signed cert will **not** validate.
- The KMS endpoint needs a **publicly resolvable DNS name**. Use a **DNS-01**
  ACME challenge so you don't need to expose the endpoint publicly — the service
  itself can stay firewalled to the worker subnet via `networkPolicy`.

(EPHEMERAL-only KMS encryption relaxes this, since STATE is already mounted at
dial time — but this chart's defaults target the STATE case.)

## Network reachability is the access control

The Talos KMS client sends no client certificates and no tokens (see the repo
README's security model), so the API cannot authenticate callers. Anyone who can
reach port 4050 and knows a node's UUID can have that node's blob unsealed.
Consequences for this chart:

- **The NetworkPolicy CIDR lists are the access control.** Treat them as
  security-critical configuration.
- **Fail-closed by design.** A port whose CIDR list is empty gets no ingress
  rule at all, and a pod with no rules is fully isolated. This is deliberate.
- **Upgrading from a pre-fail-closed chart version:** the old chart rendered
  empty lists as allow-all — the opposite of its comments. After upgrading,
  an empty `ingressCIDRs` means **no node can unseal and the next node reboot
  hangs at unlock**. Set the CIDR lists *before* the upgrade lands.
- **`ipBlock` lists must contain node/host CIDRs.** Cilium-managed pod sources
  are matched by identity, not by IP: pod CIDRs in `ingressCIDRs` do **not**
  authorize pod clients (verified on Cilium 1.19). Talos nodes connect from
  host addresses — list those.

## Prerequisites

- [external-secrets](https://external-secrets.io/) operator + a configured
  `SecretStore`/`ClusterSecretStore` (if `externalSecret.enabled`).
- [cert-manager](https://cert-manager.io/) + an **ACME** `ClusterIssuer` with a
  DNS-01 solver (if `certManager.enabled`).

## Quick start

```yaml
# values-prod.yaml
bindClientIP: true

externalSecret:
  enabled: true
  secretStoreRef:
    name: onepassword
    kind: ClusterSecretStore
  keys:
    - secretKey: v1            # becomes the mounted filename / key id
      remoteRef:
        key: talos-kms         # 1Password item
        property: key-v1       # field holding the base64 key

masterKey:
  currentKeyId: v1

certManager:
  enabled: true
  dnsName: kms.example.com
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer

networkPolicy:
  enabled: true
  ingressCIDRs:
    - 10.0.0.0/16   # worker subnet(s)
```

```sh
helm install talos-kms ./deploy/helm/talos-kms -n kms --create-namespace -f values-prod.yaml
```

## Keys and rotation

The server loads **versioned** AES keys from a mounted directory (`--key-dir`),
one file per key id, and seals with `masterKey.currentKeyId`. The same key is
used for every node; per-node isolation is cryptographic — node UUID (and
optionally source IP) plus the blob header are bound as AEAD additional data.
Every sealed blob is tagged with the id of the key that sealed it, so an old
blob keeps unsealing as long as that version is still present. All replicas must
mount the **same** key set.

With 1Password (via external-secrets), store each version as a field on one item
and list the versions under `externalSecret.keys`; each becomes a file named by
its key id. Generate a key with:

```sh
head -c 32 /dev/urandom | base64   # store as a field, e.g. key-v1
```

### Rotating a key (no re-seal)

1. Add the new version (e.g. `key-v2`) to the 1Password item and to
   `externalSecret.keys`; restart the pods so every replica can **unseal** v2
   (the server loads keys only at startup — [stakater/Reloader](https://github.com/stakater/Reloader)
   can automate the restart when the keys Secret changes).
2. Set `masterKey.currentKeyId: v2` and roll out. New seals use v2.
3. Leave v1 in place until no node's stored blob references it (nodes do not
   re-seal). Removing a still-referenced version makes those nodes fail to
   unlock — watch `kms_requests_total{outcome="key_error"}` before pruning.

## Notable values

| Key | Default | Notes |
| --- | --- | --- |
| `replicaCount` | `2` | HA; all replicas share the same key set |
| `masterKey.currentKeyId` | `v1` | Key id used to seal new data |
| `bindClientIP` | `true` | Keep only if the server sees real node IPs (check the audit log's `client_ip`); a SNATing LB path binds the proxy address — see the root README |
| `probes.enabled` | `true` | Use plaintext HTTP `/livez` and `/readyz` probes |
| `probes.port` | `8080` | Container-only probe port; not exposed by the Service |
| `tls.enabled` | `true` | Disabling is for testing only |
| `certManager.enabled` | `false` | Must use an ACME issuer (see above) |
| `externalSecret.enabled` | `false` | Materializes the keys Secret (1Password) |
| `networkPolicy.ingressCIDRs` | `[]` | Empty = deny all; worker node/host CIDRs (pod CIDRs don't match on Cilium) |
| `networkPolicy.probeCIDRs` | `[]` | Kubelet probe sources (control-plane node IPs); empty keeps the probe port isolated |
| `metrics.enabled` | `true` | Exposes Prometheus `/metrics` on a separate port |
| `metrics.serviceMonitor.enabled` | `false` | Render a Prometheus Operator ServiceMonitor |
| `networkPolicy.metricsCIDRs` | `[]` | Ranges allowed to scrape metrics (plaintext) |
| `priorityClassName` | `""` | Use an existing PriorityClass (e.g. `system-cluster-critical`) |
| `priorityClass.create` | `false` | Render a dedicated PriorityClass instead |

## Scheduling priority

The KMS is boot-critical, so give it a high pod priority — it then wins
scheduling when nodes are full and is evicted last under node pressure.
Either point at an existing class (recommended):

```yaml
priorityClassName: system-cluster-critical
```

or have the chart create a dedicated one:

```yaml
priorityClass:
  create: true
  value: 1000000000   # keep below system-cluster-critical (2000000000)
```

## Metrics and audit

The server exposes Prometheus metrics on `metrics.port` (plaintext HTTP, kept
off the gRPC port — restrict it via `networkPolicy.metricsCIDRs`):

- `kms_requests_total{operation,outcome}` — `operation` is `seal`/`unseal`;
  `outcome` is `success`, `auth_failure`, `key_error`, `invalid_argument`, or
  `internal_error`. Alert on a rising `key_error`/`internal_error` rate (server
  misconfiguration) and on `auth_failure` spikes (tampering, or nodes that
  changed IP under `bindClientIP`).
- `kms_request_duration_seconds{operation}` — request latency histogram.

Every request also emits a structured JSON audit line (operation, outcome,
node UUID, client IP, duration). Node UUID is intentionally kept out of metric
labels (high cardinality) and recorded only in the audit log.

## Probes

The chart uses a dedicated plaintext HTTP probe port instead of Kubernetes'
native gRPC probe against the KMS API port. This matters when `tls.enabled` is
true: kubelet gRPC probes cannot be configured for TLS, while the KMS API
expects TLS on port 4050.

The probe port is not added to the Service. Kubelet probes call the pod IP
directly:

- `/livez` returns success when the process is running.
- `/readyz` returns success when the server's gRPC health service reports
  `SERVING`.
