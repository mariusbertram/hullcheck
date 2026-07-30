# anchor-webui

A small WebUI around Anchore's open-source scanning tools —
[syft](https://github.com/anchore/syft) (SBOM), [grype](https://github.com/anchore/grype)
(vulnerabilities) and [grant](https://github.com/anchore/grant) (license
policy) — see https://oss.anchore.com/docs/projects/.

Paste a reference to a container image or OCI artifact, hit scan, and all
three tools run against it. Results (SBOM, vulnerability findings, license
report) are shown live and kept in a searchable history. Registry pull
secrets and an HTTP(S) proxy can be configured centrally and are used by all
three tools. **The UI has no authentication** and is designed to run on
Kubernetes/OpenShift.

## Architecture

```
 browser  ──HTTP──►  Node/Express server  ──spawns──►  syft / grype / grant CLIs
                          │                                   │
                          ├─ job queue (bounded concurrency)  └─ pull images directly
                          ├─ SSE log/status streaming             from the registry
                          └─ /data (PVC): config.json, scan
                             history + SBOM/vuln/license JSON
```

- `server/` — the backend (Express). No database; state lives as JSON files
  under `DATA_DIR` (default `/data`), which should be a PVC in Kubernetes.
- `public/` — a small dependency-free HTML/CSS/JS frontend served by the
  same process (single container, single Service).
- Each scan: `syft` generates an SBOM from the image, which `grype` and
  `grant` then reuse (`sbom:<path>`) so the registry is only pulled once. If
  `syft` fails, `grype`/`grant` fall back to scanning the image reference
  directly.
- syft/grype/grant are invoked with `spawn(cmd, [args...])` (no shell), so
  the image reference can never be used for shell/command injection.

## Quick start (local, Docker Compose)

```
docker compose up --build
open http://localhost:8080
```

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
parallel scans), `TOOL_TIMEOUT_MS` (900000), `MAX_HISTORY` (200 scans kept).

Credentials are never written to environment variables of the long-lived
server process. For each scan, a throwaway per-job directory is created with
its own `~/.docker/config.json` and a syft/grype `registry.yaml`
(`-c` flag), pointed to via `DOCKER_CONFIG`/`HOME` for that child process
only, and deleted once the scan finishes — concurrent scans never see each
other's credentials.

## Deploying to Kubernetes / OpenShift

### Build & push the image

```
docker build -t <your-registry>/anchor-webui:1.0.0 .
docker push <your-registry>/anchor-webui:1.0.0
```

Pin exact tool versions for reproducible builds with
`--build-arg SYFT_VERSION=vX.Y.Z --build-arg GRYPE_VERSION=vX.Y.Z --build-arg GRANT_VERSION=vX.Y.Z`
(defaults to latest release at build time).

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

## Security notes

- **No authentication.** This is intentional per the requirements, so treat
  network exposure as the only access control: keep `route.enabled` /
  `ingress.enabled` off (cluster-internal only) unless you put it behind
  something that authenticates, and consider a `NetworkPolicy` restricting
  which pods/namespaces can reach it.
- Scanning is inherently an SSRF-shaped feature (it fetches attacker-chosen
  registry URLs) — this is why the UI has no auth in front of it but should
  never be reachable from an untrusted network.
- The scan image reference is validated against a conservative regex and
  always passed as an argv element (never through a shell), so it cannot be
  used for command injection.
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

## Known limitations

- `grant list -o json`'s exact JSON shape isn't guaranteed to be stable
  across versions; the license summary parser is defensive and falls back
  to showing the raw JSON if it can't recognize the shape.
- `grant` doesn't accept the same `-c <registry.yaml>` config as syft/grype
  in this integration; when scanning an image directly (i.e. `syft` failed
  first) it can still authenticate via the generated `DOCKER_CONFIG`, but
  per-scan skip-TLS-verify/plain-HTTP overrides don't apply to it.
- No built-in license *policy* enforcement (`grant check` + a policy file);
  only `grant list` (license discovery) is wired up. Mount a policy file and
  extend `server/src/scanner.js` if you need pass/fail gating.
