# anchor-webui

A small WebUI and CVE/SBOM/license scanner built on Anchore's open-source
[syft](https://github.com/anchore/syft) (SBOM) and
[grype](https://github.com/anchore/grype) (vulnerabilities) — linked in as Go
libraries, not spawned as CLIs — see https://oss.anchore.com/docs/projects/.

Paste a reference to a container image or OCI artifact, hit scan, and syft
catalogs it while grype matches the result against its vulnerability
database; a license summary is derived from the same SBOM. Results (SBOM,
vulnerability findings, license report) are shown live and kept in a
searchable history. Registry pull secrets and an HTTP(S) proxy can be
configured centrally. **The UI has no authentication** and is designed to
run on Kubernetes/OpenShift.

A [Harbor Pluggable Scanner Adapter](https://github.com/goharbor/pluggable-scanner-spec)
(`/api/v1/*`) is built in, so anchor-webui can also be registered as a scanner
in Harbor and driven directly from Harbor's own vulnerability scanning UI.

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

`.github/workflows/ci.yml` runs on PRs/pushes to `main` when app/chart/CI files changed:

- **lint** — `golangci-lint` (via reusable `.github/workflows/lint.yml`).
- **test** — `go vet ./...` + `go build ./...` + `go test -race -shuffle=on ./...` against the backend:
  image-reference validation, the grype/syft/grant summary parsers, the
  Harbor scanner adapter (metadata/accept-scan), and the job queue.
- **dockerfile-lint** — hadolint against the `Dockerfile`.
- **manifests-lint** — `helm lint` + `helm template` the chart under a few
  different value combinations (route, ingress, persistence off,
  read-only-root-fs), and `kubectl kustomize deploy/k8s`.
- **docker-build-test** — builds the real container image, starts it, waits
  for `/readyz` (the vulnerability database finishing its download), then
  drives an actual scan of `alpine:3.20` through the HTTP API and asserts
  all three tool states report `success` and produce valid
  SBOM/vulnerability/license JSON.
- **release/publish** lives in `.github/workflows/release.yml` and only runs
  on `v*` tags (build/push/sign/attest + GitHub release binaries).

## Configuration

Two layers, both editable from the **Settings** page in the UI:

1. **Defaults**, seeded at startup from environment variables / a mounted
   Secret (see below) and persisted to `DATA_DIR/config.json` after that.
2. **Per-scan overrides**, entered under "Advanced" on the Scan page for a
   one-off private image (registry host, username/password or token,
   skip-TLS-verify / plain-HTTP) — never persisted.

| Setting | Env var (seed only) | UI field |
|---|---|---|
| HTTP proxy | `HTTP_PROXY` | Settings → HTTP proxy |
| HTTPS proxy | `HTTPS_PROXY` | Settings → HTTP proxy |
| No-proxy list | `NO_PROXY` | Settings → HTTP proxy |
| Registry pull secret(s) | mounted `kubernetes.io/dockerconfigjson` Secret at `PULL_SECRET_PATH` | Settings → Registry credentials |
| Skip TLS verify / plain HTTP | — | Settings → TLS |

Registry credentials from a mounted Secret show up read-only in the UI
(`source: mounted-secret`) and can't be edited or deleted there — add/edit
your own on top from the UI, or update the Secret and roll the Deployment.

Other env vars: `PORT` (8080), `DATA_DIR` (`/data`), `MAX_CONCURRENCY` (2
parallel scans), `TOOL_TIMEOUT_MS` (900000, applies to each of syft/grype),
`MAX_HISTORY` (200 scans kept), `GRYPE_DB_AUTO_UPDATE` (`true`),
`GOLANG_SEARCH_REMOTE_LICENSES` (`false`) — see
[Air-gapped / offline deployment](#air-gapped--offline-deployment) below for
what the last two control and why they default the way they do.

Credentials are never written to environment variables, files, or disk at
all. Each scan builds its own in-process `image.RegistryOptions` (mounted
secret + UI-configured auths, with an optional per-scan override taking
priority) and passes it directly into the syft/grype library calls for that
scan — concurrent scans never see each other's credentials, and there's no
per-job directory to create or clean up.

## Deploying to Kubernetes / OpenShift

### Build & push the image

```
docker build -t <your-registry>/anchor-webui:1.0.0 .
docker push <your-registry>/anchor-webui:1.0.0
```

syft/grype are linked into the binary as Go libraries (see `go.mod`), so
their versions are pinned the same way as any other dependency — `go get
github.com/anchore/syft@vX.Y.Z` / `github.com/anchore/grype@vX.Y.Z` then
rebuild — there are no separate `--build-arg`s or CLI installs to manage.

### Helm (recommended)

```
helm install anchor-webui charts/anchor-webui \
  --set image.repository=<your-registry>/anchor-webui \
  --set image.tag=1.0.0 \
  --set route.enabled=true            # OpenShift
  # --set ingress.enabled=true --set ingress.host=anchor-webui.example.com   # vanilla k8s
```

Key values (see `charts/anchor-webui/values.yaml` for the full list):

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

### Plain manifests (no Helm)

Equivalent static manifests are under `deploy/k8s/` (usable directly or via
`kubectl apply -k deploy/k8s`). Edit the image reference in
`deploy/k8s/deployment.yaml`, then uncomment `route.yaml` (OpenShift) or
`ingress.yaml` (vanilla k8s) in `deploy/k8s/kustomization.yaml`. Create a
real pull secret from `deploy/k8s/pull-secret-example.yaml` if you need one
(it's optional — the Deployment mounts it with `optional: true`).

## Air-gapped / offline deployment

Two features need network egress beyond the registry being scanned; both are
safe to leave off (the defaults) in a cluster with no outbound access:

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
  `false`): compiled Go binaries embed almost no license metadata on their
  own (just module name+version via `debug/buildinfo`), so syft's own
  license catalogers find close to nothing for Go-heavy images unless this
  is turned on, which makes it fetch each module's license from a Go proxy
  (respects `GOPROXY`/`GONOPROXY`/`GOPRIVATE` from the environment same as
  the `go` CLI). This is opt-in rather than defaulted on because syft's
  remote-license fetch (as of syft v1.50.0) uses a bare `http.Get` with no
  request timeout and doesn't honor cancellation from the scan's own
  `TOOL_TIMEOUT_MS` context — on a network that silently drops packets
  instead of actively refusing them (common with restrictive
  `NetworkPolicy`/firewall setups, not just fully air-gapped ones), a scan
  of a Go-heavy image could hang far longer than the configured tool
  timeout. Only enable it once you've confirmed egress to the proxy actually
  works; it adds real time either way (tens of seconds for a few hundred
  unique modules, since each is a separate proxy round-trip).

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
| `GET` | `/api/scans/:id/artifacts/{sbom,grype,grant}.json` | raw tool output |
| `GET` | `/healthz`, `/readyz` | liveness/readiness |

### Harbor Pluggable Scanner Adapter

Implements the [Harbor scanner adapter API](https://github.com/goharbor/pluggable-scanner-spec)
so anchor-webui can be registered under Harbor → Administration → Interrogation
Services → Scanners (endpoint URL: `http://<service>:8080`).

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/metadata` | scanner capabilities |
| `POST` | `/api/v1/scan` | Harbor submits an artifact to scan; returns a scan request `id` |
| `GET` | `/api/v1/scan/{id}/report` | vulnerability report in Harbor's expected format, sourced from `grype` |

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
- The vulnerability database downloads on first startup (cached under
  `DATA_DIR/grype-db` after that) — scans submitted before `/readyz` reports
  ready will wait for it, up to `TOOL_TIMEOUT_MS`.
- The Harbor adapter's `GET /api/v1/scan/{id}/report` only returns the
  `grype` vulnerability report shape; SBOM/license results from the same
  scan are still available through the WebUI API above.
