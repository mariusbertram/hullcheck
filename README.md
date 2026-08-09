# hullcheck

A small WebUI and CVE/SBOM/license scanner built on Anchore's open-source
[syft](https://github.com/anchore/syft) (SBOM) and
[grype](https://github.com/anchore/grype) (vulnerabilities) — linked in as Go
libraries, not spawned as CLIs — see https://oss.anchore.com/docs/projects/.

Paste a reference to a container image or OCI artifact, hit scan, and syft
catalogs it while grype matches the result against its vulnerability
database; a license summary is derived from the same SBOM. Results (SBOM,
vulnerability findings, license report) are shown live, and a past scan can
be reopened by its ID. The UI intentionally exposes nothing else — no
settings screen, no browsable history; registry pull secrets and an
HTTP(S) proxy are configured outside the UI (env vars / mounted Secret / the
`/api/config` API). **The UI has no authentication** and is designed to run
on Kubernetes/OpenShift.

A [Harbor Pluggable Scanner Adapter](https://github.com/goharbor/pluggable-scanner-spec)
(`/api/v1/*`) is built in, so hullcheck can also be registered as a scanner
in Harbor and driven directly from Harbor's own vulnerability scanning and
SBOM generation UI.

## Architecture

```
 browser  ──HTTP──►  Go server (single binary, no CLIs/subprocesses)
                          │        ▲
                          │        └─ Harbor Scanner Adapter API
                          ├─ syft/grype linked in as Go libraries -
                          │  pull the image and match vulnerabilities
                          │  in-process (no PATH lookup, no exec.Command)
                          ├─ job queue (bounded concurrency)
                          ├─ SSE log/status streaming
                          └─ /data (PVC): config.json, grype-db/,
                             scan history + SBOM/vuln/license JSON
```

- `main.go` / `pkg/` — the backend, a single static Go binary (no runtime
  dependencies, no subprocesses). No database; state lives as JSON files
  under `DATA_DIR` (default `/data`), which should be a PVC in Kubernetes.
  - `pkg/server` — HTTP routing, the WebUI JSON API and SSE log streaming.
  - `pkg/jobs` — the scan job queue/history (bounded worker pool).
  - `pkg/scanner` — runs syft (SBOM) and grype (vulnerability matching) via
    their Go libraries (`github.com/anchore/syft`, `github.com/anchore/grype`);
    the license summary is derived directly from syft's SBOM package
    metadata. Nothing here shells out to a CLI or looks one up on `PATH`.
  - `pkg/config` — proxy/TLS/registry-credential configuration, including
    mounted `kubernetes.io/dockerconfigjson` pull secrets; builds the
    in-process registry credentials syft/grype pull images with.
  - `pkg/harbor` — the Harbor Pluggable Scanner Adapter API.
  - `pkg/validate` — image/OCI-artifact reference validation.
- `public/` — a small dependency-free HTML/CSS/JS frontend, embedded into
  the binary at build time (`//go:embed public/*`) and served by the same
  process (single container, single Service).
- Each scan: syft catalogs the image into an SBOM (in-memory + written to
  `sbom.json`); grype matches that SBOM against the vulnerability database
  (no second registry pull); the license summary is read off the same SBOM's
  per-package license metadata. The image is only pulled once, by syft.
- Registry credentials are passed to syft/grype in-process as
  `image.RegistryOptions` — never written to a file or an env var, so
  concurrent scans can't see each other's credentials and there's nothing
  on disk to clean up.
- The vulnerability database is downloaded once at startup into
  `DATA_DIR/grype-db` (persisted across restarts on the PVC) and kept
  in memory; `/readyz` reports not-ready until it's loaded.

## Quick start (local, Docker Compose)

```
docker compose up --build
open http://localhost:8080
```

## CI

All static-analysis/lint checks live in the reusable `.github/workflows/lint.yml`
(three jobs: `golangci-lint`, `dockerfile-lint`, `manifests-lint`) - it's
called from both `ci.yml` and `release.yml` rather than duplicated into each.

`.github/workflows/ci.yml` runs on PRs/pushes to `main` when app/chart/CI files changed:

- **lint** — calls `lint.yml`: `golangci-lint`; hadolint against the
  `Dockerfile`; `helm lint` + `helm template` the chart under a few
  different value combinations (route, ingress, persistence off,
  read-only-root-fs), and `kubectl kustomize deploy/k8s`.
- **test** — `go vet ./...` + `go build ./...` + `go test -race -shuffle=on ./...` against the backend:
  image-reference validation, the grype/syft/grant summary parsers, the
  Harbor scanner adapter (metadata/accept-scan), and the job queue.
- **docker-build-test** — needs `[lint, test]`; builds the real container
  image, starts it, waits for `/readyz` (the vulnerability database
  finishing its download), then drives an actual scan of `alpine:3.20`
  through the HTTP API and asserts all three tool states report `success`
  and produce valid SBOM/vulnerability/license JSON; also runs a
  report-only SBOM + vulnerability scan of that image (Security tab, not
  blocking).

**Release** lives in `.github/workflows/release.yml` and only runs on `v*`
tags: `lint` + `test`, then builds/pushes the real multi-arch image, attests
an SBOM to it and blocks on a Critical vulnerability finding (keyless
cosign), and creates a GitHub Release with a changelog, the image digest,
and standalone `linux/amd64`/`linux/arm64` binaries + checksums.

## Configuration

The UI has no configuration screen — it exposes exactly two actions: start a
scan and look up a previous scan by ID. Registry credentials, proxy and TLS
defaults are configured outside the UI:

1. **Defaults**, seeded at startup from environment variables / a mounted
   Secret (see below) and persisted to `DATA_DIR/config.json` after that.
   They can still be read/updated via the `GET`/`PUT /api/config` API (see
   [API](#api) below) for scripted or admin use.
2. **Per-scan overrides** can still be passed to `POST /api/scans` directly
   (registry host, username/password or token, skip-TLS-verify /
   plain-HTTP) — never persisted — but there is no UI field for them anymore.

| Setting | Env var (seed only) | API field |
|---|---|---|
| HTTP proxy | `HTTP_PROXY` | `httpProxy` |
| HTTPS proxy | `HTTPS_PROXY` | `httpsProxy` |
| No-proxy list | `NO_PROXY` | `noProxy` |
| Registry pull secret(s) | mounted `kubernetes.io/dockerconfigjson` Secret at `PULL_SECRET_PATH` | `registryAuths` (mounted ones are read-only, `source: mounted-secret`) |
| Skip TLS verify / plain HTTP | — | `insecureSkipTlsVerify` / `insecureUseHttp` |

Other env vars: `PORT` (8080), `DATA_DIR` (`/data`), `MAX_CONCURRENCY` (2
parallel scans), `TOOL_TIMEOUT_MS` (900000, applies to each of syft/grype),
`MAX_HISTORY` (200 scans kept), `GRYPE_DB_AUTO_UPDATE` (`true`),
`GOLANG_SEARCH_REMOTE_LICENSES` (`true`), `VEX_LOOKUP_ENABLED` (`true`) — see
[Air-gapped / offline deployment](#air-gapped--offline-deployment) and
[VEX attestations](#vex-attestations) below for what these control and why
they default the way they do.

Credentials are never written to environment variables, files, or disk at
all. Each scan builds its own in-process `image.RegistryOptions` (mounted
secret + UI-configured auths, with an optional per-scan override taking
priority) and passes it directly into the syft/grype library calls for that
scan — concurrent scans never see each other's credentials, and there's no
per-job directory to create or clean up.

## Deploying to Kubernetes / OpenShift

### Build & push the image

```
docker build -t <your-registry>/hullcheck:0.4.0 .
docker push <your-registry>/hullcheck:0.4.0
```

syft/grype are linked into the binary as Go libraries (see `go.mod`), so
their versions are pinned the same way as any other dependency — `go get
github.com/anchore/syft@vX.Y.Z` / `github.com/anchore/grype@vX.Y.Z` then
rebuild — there are no separate `--build-arg`s or CLI installs to manage.

### Helm (recommended)

```
helm install hullcheck charts/hullcheck \
  --set image.repository=<your-registry>/hullcheck \
  --set image.tag=0.4.0 \
  --set route.enabled=true            # OpenShift
  # --set ingress.enabled=true --set ingress.host=hullcheck.example.com   # vanilla k8s
```

Key values (see `charts/hullcheck/values.yaml` for the full list):

- `persistence.*` — PVC for `/data` (scan history + config), or set
  `persistence.enabled=false` for ephemeral/`emptyDir` storage.
- `pullSecret.existingSecret` — name of an existing
  `kubernetes.io/dockerconfigjson` Secret to mount as the default pull
  secret; or `pullSecret.create=true` + `pullSecret.dockerconfigjson` to have
  the chart create one (prefer referencing an existing Secret / secrets
  manager in production).
- `config.httpProxy` / `config.httpsProxy` / `config.noProxy`.
- `route.enabled` (OpenShift `Route`) or `ingress.enabled` (vanilla k8s
  `Ingress`) — both default to off, i.e. cluster-internal only.
- Runs out of the box under OpenShift's `restricted` SCC: the image is
  built group(0)-writable so an arbitrary assigned UID still works.

### Scaling

The chart (and `deploy/k8s/`) ship an autoscaling `Deployment` by default:
`HorizontalPodAutoscaler` (CPU-based, `autoscaling.*`), a
`PodDisruptionBudget` (`podDisruptionBudget.*`), a rolling-update strategy
that never drops below the current replica count, and a
`terminationGracePeriodSeconds` generous enough for a scan (up to ~2x
`TOOL_TIMEOUT_MS`) plus its SSE stream to finish before a pod is force-killed.

Two things this needs to actually work:

- **A cluster metrics pipeline** (e.g. `metrics-server`) — the HPA reads
  `cpu`/`requests.cpu` utilization; without it, `kubectl get hpa` shows
  `<unknown>` and it never scales.
- **An RWX-capable `StorageClass`** for `persistence.accessMode` (NFS,
  Longhorn, EFS, Azure Files, CephFS, ...) — every replica mounts the same
  `/data` volume, since scan history/artifacts are only written to disk, not
  shared through any other backend. If only `ReadWriteOnce` storage is
  available, set `autoscaling.enabled=false` and `replicaCount=1` (or drop
  `hpa.yaml` from `deploy/k8s/kustomization.yaml` and pin `replicas: 1`).

Job state, the live SSE stream, and the per-job worker queue live in each
pod's memory - there's no Redis/DB behind this. A request can land on a pod
that didn't create the job (any `GET`/list call, or the initial connection of
an SSE stream); that pod falls back to reading the job straight off the
shared volume, polling it once a second, so the UI keeps working regardless
of which replica handles a given request. `EventSource` reconnects on its
own if a stream's pod is replaced mid-scan (rolling update, scale-down,
node drain), and the process only exits after any scan it's still running
locally has finished (bounded by `terminationGracePeriodSeconds`), so
scaling events don't orphan a job mid-run.

This doesn't (yet) extend to `config.Manager` (the Settings page - proxy,
registry credentials, etc.): it also caches in memory per pod, but unlike
jobs, a config change made through one pod isn't picked up by others until
they restart. With multiple replicas, change settings sparingly and expect
a brief window of inconsistent behavior across pods after doing so.

### Plain manifests (no Helm)

Equivalent static manifests are under `deploy/k8s/` (usable directly or via
`kubectl apply -k deploy/k8s`). Edit the image reference in
`deploy/k8s/deployment.yaml`, then uncomment `route.yaml` (OpenShift) or
`ingress.yaml` (vanilla k8s) in `deploy/k8s/kustomization.yaml`. Create a
real pull secret from `deploy/k8s/pull-secret-example.yaml` if you need one
(it's optional — the Deployment mounts it with `optional: true`).

## Air-gapped / offline deployment

Building the image itself needs network access too - `go mod download` (see
`Dockerfile`) fetches every Go module from `proxy.golang.org` by default. If
your build environment's egress is restricted, or another team runs an
internal Go-proxy repository (e.g. Nexus) you're expected to build through,
point the build at it instead:

```
docker build --build-arg GOPROXY=https://nexus.internal/repository/go-proxy .
```

Falls back to `,direct` (a plain VCS fetch) for anything that mirror
doesn't have, so it doesn't need to carry every possible dependency. If that
Nexus repository doesn't also proxy `sum.golang.org`, module checksum
verification against it will fail - either have the team that runs it add
that (safer), or add `--build-arg GOPROXY=...` together with
`--build-arg GOSUMDB=off` (also wired into the Dockerfile as a build arg)
at your own risk.

Two more features need network egress beyond the registry being scanned at
*runtime*; both are safe to leave off (the defaults) in a cluster with no
outbound access:

- **grype vulnerability database** (required for CVE matching): downloaded
  once at startup into `DATA_DIR/grype-db` and reused across restarts. For
  air-gapped clusters, pre-seed that directory before first start — the
  simplest way is running this same binary once somewhere with network
  access, pointed at the same `DATA_DIR` (or an empty one you then copy into
  the PVC/image) — then set `GRYPE_DB_AUTO_UPDATE=false` so startup never
  attempts to reach the network at all. Leaving `GRYPE_DB_AUTO_UPDATE` at its
  default (`true`) is still air-gap-*safe* even without pre-seeding
  failure-wise: grype's own update check fails soft (logs a warning, falls
  back to whatever's already on disk) rather than blocking startup — but
  with nothing pre-seeded there's simply no DB to fall back to, so scans
  will report the vulnerability database as failed to load. Turning off
  auto-update just skips the (bounded, ~30s) network check outright once
  you've pre-seeded the DB.
- **Go module license lookup** (`GOLANG_SEARCH_REMOTE_LICENSES`, default
  `true`): compiled Go binaries embed almost no license metadata on their
  own (just module name+version via `debug/buildinfo`), so syft's own
  license catalogers find close to nothing for Go-heavy images unless this
  fetches each module's license from a Go proxy (respects
  `GOPROXY`/`GONOPROXY`/`GOPRIVATE` from the environment same as the `go`
  CLI). It's on by default so Go-heavy images get real license data out of
  the box; **air-gapped or network-restricted clusters must either point
  `GOPROXY` at a reachable proxy (see below) or set
  `GOLANG_SEARCH_REMOTE_LICENSES=false` to disable it outright.** This
  matters more than a typical opt-in flag: syft's remote-license fetch (as
  of syft v1.50.0) uses a bare `http.Get` with no request timeout and
  doesn't honor cancellation from the scan's own `TOOL_TIMEOUT_MS` context —
  on a network that silently drops packets instead of actively refusing
  them (common with restrictive `NetworkPolicy`/firewall setups, not just
  fully air-gapped ones), a scan of a Go-heavy image can hang far longer
  than the configured tool timeout. If you haven't confirmed egress to a Go
  proxy works, disable it. It also adds real time even when it works (tens
  of seconds for a few hundred unique modules, since each is a separate
  proxy round-trip).

  This is a separate `GOPROXY` from the build-time one above - that one only
  controls fetching *this repo's own* dependencies while compiling the
  `hullcheck` binary (`docker build --build-arg GOPROXY=...`). This one is
  read by syft *inside the running container* at scan time, straight from
  its process environment, to fetch license metadata for modules found
  *in the images being scanned*. If your cluster's egress only allows an
  internal Nexus Go-proxy, point `GOPROXY` at it as a plain container env
  var (leave `GOLANG_SEARCH_REMOTE_LICENSES` at its default `true`):
  - Helm: `values.yaml`'s `extraEnv` -
    ```yaml
    extraEnv:
      - name: GOPROXY
        value: https://nexus.internal/repository/go-proxy
    ```
  - Plain manifests: add the key directly to `deploy/k8s/configmap.yaml`'s
    `data:` map.
  - Fully air-gapped, no Go proxy reachable at all:
    ```yaml
    extraEnv:
      - name: GOLANG_SEARCH_REMOTE_LICENSES
        value: "false"
    ```

  Same checksum caveat as the build-time proxy: if that Nexus repository
  doesn't also mirror `sum.golang.org`, also set `GOSUMDB=off` (same
  `extraEnv`/ConfigMap mechanism as above), or (safer) have the team running
  it add that mirror.

## Security notes

- **No authentication.** This is intentional per the requirements, so treat
  network exposure as the only access control: keep `route.enabled` /
  `ingress.enabled` off (cluster-internal only) unless you put it behind
  something that authenticates, and consider a `NetworkPolicy` restricting
  which pods/namespaces can reach it.
- Scanning is inherently an SSRF-shaped feature (it fetches attacker-chosen
  registry URLs) — this is why the UI has no auth in front of it but should
  never be reachable from an untrusted network.
- The scan image reference is validated against a conservative regex
  (`pkg/validate`) before it ever reaches syft/grype. Since those run
  in-process as libraries — not as a spawned CLI — there's no argv/shell
  boundary to inject through in the first place.
- Raw scan output (SBOM/vulnerability/license JSON) is served back as
  `Content-Type: application/json`/downloadable files, and the frontend
  escapes all scanned data before inserting it into the DOM, so a malicious
  package/license name embedded in a scanned image can't run script in the
  UI.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/config` | current default config (secrets masked) |
| `PUT` | `/api/config` | update default config |
| `GET` | `/api/scans` | scan history (summaries) |
| `POST` | `/api/scans` | start a scan: `{ image, registryAuth?, insecureSkipTlsVerify?, insecureUseHttp? }` |
| `GET` | `/api/scans/:id` | full job (status, tool states, summary, logs) |
| `GET` | `/api/scans/:id/stream` | Server-Sent Events: `status`, `log`, `done` |
| `GET` | `/api/scans/:id/artifacts/{sbom,sbom-spdx,grype,grant}.json` | raw tool output (`sbom.json` is syft's native format, `sbom-spdx.json` an SPDX JSON encoding of the same SBOM) |
| `GET` | `/healthz`, `/readyz` | liveness/readiness |

### Harbor Pluggable Scanner Adapter

Implements the [Harbor scanner adapter API](https://github.com/goharbor/pluggable-scanner-spec)
so hullcheck can be registered under Harbor → Administration → Interrogation
Services → Scanners (endpoint URL: `http://<service>:8080`).

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/metadata` | scanner capabilities: `vulnerability` and `sbom` |
| `POST` | `/api/v1/scan` | Harbor submits an artifact to scan; returns a scan request `id` |
| `GET` | `/api/v1/scan/{id}/report` | report content-negotiated via `Accept`: the `grype` vulnerability report, or (`Accept: application/vnd.security.sbom.report+json`) the SPDX SBOM, both from the same scan |

## VEX attestations

Every scan checks the registry for an [OpenVEX](https://openvex.dev/)
attestation attached to the scanned image and, if one is found, feeds it into
grype's matching (`grype.VulnerabilityMatcher.VexProcessor`) so
vendor-declared `not_affected`/`fixed` statuses suppress the corresponding
findings — the same effect `grype --vex <file>` has on the CLI, just
discovered automatically instead of requiring the file locally.

Discovery follows the convention [cosign](https://github.com/sigstore/cosign)
uses for attestations (SBOM/provenance/VEX alike): a tag named
`sha256-<image-digest>.att` in the same repository, holding an OCI manifest
whose layers are DSSE-enveloped [in-toto](https://in-toto.io/) statements.
Each layer's statement is decoded and kept only if its `predicateType` is
`https://openvex.dev/ns` (other predicates on the same tag, e.g. an SBOM
attestation, are skipped) **and** its `subject` digest matches the digest of
the image actually being scanned. The extracted OpenVEX document is written
to a temp file for grype's `vex.Processor` and removed once the scan
finishes. None of this touches a second registry beyond the one already
configured for the scan (same credentials, same `insecureUseHttp`/TLS
settings) — see `pkg/scanner/vex.go`.

**No signature verification is performed.** The DSSE envelope carries a
cosign signature and a Rekor transparency-log bundle, but this code doesn't
check either — only that the attestation's declared subject digest matches
the image, not who produced it. In practice this means **anyone able to push
tags to the scanned repository can suppress vulnerability findings** by
pushing their own `.att` tag with fabricated `not_affected` statements.
Verifying the signature would need a trust policy (which signer
identities/OIDC issuers are acceptable) that isn't configured anywhere in
hullcheck today; treat this the way you'd treat any other unauthenticated
input to the scan (see [Security notes](#security-notes)) and don't rely on
it in a threat model where the registry itself isn't trusted.

Controlled by `VEX_LOOKUP_ENABLED` (default `true`); set it to `false` to
disable VEX discovery entirely (e.g. if unsigned VEX attestations
influencing scan results is unacceptable for your environment, or the
registry doesn't support attestations and you'd rather skip the extra
manifest lookup). CSAF-format VEX documents aren't recognized yet — only
OpenVEX's `predicateType` convention is matched.

This also changes what the [Harbor Pluggable Scanner Adapter](#harbor-pluggable-scanner-adapter)
reports: `GetReport`'s vulnerability report is built from the same
VEX-filtered `grype.json`, so an artifact Harbor previously failed on a
Critical/High severity gate can start passing once its image carries a VEX
attestation marking those findings `not_affected` — with the same
no-signature-verification caveat above.

## Known limitations

- License data ("grant" in the UI/API) is derived directly from syft's SBOM
  package metadata rather than by running Anchore's `grant` tool as a
  library — that was tried, but `grant`'s package blank-imports
  `modernc.org/sqlite` (for RPM DB compatibility), which registers a
  database/sql driver under the same name (`"sqlite"`) that grype's own DB
  storage (`glebarez/go-sqlite`) already registers, so linking both into one
  binary panics at startup (`sql: Register called twice for driver
  sqlite`). The one piece of `grant`'s logic worth keeping — splitting
  compound SPDX expressions ("MIT AND BSD-2-Clause") into individual
  licenses and dropping the `sha256:...` content-hash pseudo-licenses syft
  emits when it can't identify one — is reimplemented directly in
  `extractLicenseNames` using the same underlying
  `github.com/github/go-spdx/v2/spdxexp` parser `grant` itself uses, which
  has no such conflict. This is license *discovery* only; there's no
  `grant`-style license *policy* enforcement (pass/fail gating against an
  allow/deny list) - add that in `pkg/scanner/scanner.go:runLicenseSummary`
  if you need it. For Go binaries specifically, see
  `GOLANG_SEARCH_REMOTE_LICENSES` under
  [Air-gapped / offline deployment](#air-gapped--offline-deployment) — without
  it, compiled Go binaries show almost no license data at all, since syft
  can't read a LICENSE file that was never embedded in the binary.
- If syft fails to build an SBOM (bad image reference, unreachable/private
  registry without valid credentials), the whole scan fails — there's no
  separate "pull the image again directly for grype" fallback, since grype
  matches against the SBOM syft already built rather than pulling the image
  itself.
- VEX attestation discovery (see [VEX attestations](#vex-attestations))
  applies unsigned OpenVEX documents to matching results without verifying
  who published them - any principal with push access to the scanned
  repository can suppress findings this way.
- The vulnerability database downloads on first startup (cached under
  `DATA_DIR/grype-db` after that) — scans submitted before `/readyz` reports
  ready will wait for it, up to `TOOL_TIMEOUT_MS`.
- The Harbor adapter's SBOM report is an SPDX JSON encoding of syft's SBOM
  (`spdxjson`, generated alongside the native one on every scan). License
  results aren't exposed to Harbor at all - Harbor's Pluggable Scanner Spec
  has no report type for them - but remain available through the WebUI API
  above.
