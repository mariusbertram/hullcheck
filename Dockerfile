# syntax=docker/dockerfile:1

# ---- Stage 1: Build Go Backend ---------------------------------------------
# Project Hummingbird "go" builder image: minimal, hardened, includes the
# full Go toolchain plus a shell for RUN steps (https://hummingbird-project.io).
# The distroless runtime image in stage 2 has neither, so all filesystem prep
# (mkdir, chmod) that the runtime needs must happen here and be COPYed over.
#
# --platform=$BUILDPLATFORM pins this stage to the build host's own
# architecture (e.g. amd64 GitHub runner) regardless of which platform is
# being targeted below - Go's own cross-compiler (GOOS/GOARCH) then produces
# the target binary natively, with zero emulation. Without this, buildx runs
# the *entire* stage - go mod download plus compiling the whole syft/grype
# dependency tree - under QEMU for the non-native target, which is 10-50x+
# slower for CPU-bound work like this: a linux/arm64 release build measured
# this way ran past a 1-hour job timeout and got killed before finishing.
FROM --platform=$BUILDPLATFORM quay.io/hummingbird/go:1.26-builder AS builder
USER 1001
WORKDIR /build

# UID 1001 has no $HOME in the builder image, so Go falls back to /.cache and
# fails with permission denied; point HOME/GOCACHE at a writable directory.
ENV HOME=/build GOCACHE=/build/.cache/go-build

COPY --chown=1001:0 go.mod go.sum ./
RUN go mod download
COPY --chown=1001:0 . .

# TARGETOS/TARGETARCH are set automatically by buildx to the platform being
# built (e.g. linux/arm64), independent of this stage's own native platform.
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-w -s" -o hullcheck main.go

# Prepare the writable data directory with OpenShift-style arbitrary-UID
# permissions (GID 0, group=owner); the distroless runtime has no shell to
# do this itself, so it's staged here (under /build, writable by UID 1001)
# and copied into the final image's /data.
RUN mkdir -p /build/data \
  && chgrp -R 0 /build/data \
  && chmod -R g=u /build/data

# ---- Stage 2: Final minimal image -------------------------------------------
# Project Hummingbird "static" image: purpose-built runtime for statically
# compiled binaries (Go/Rust/C). Contains only CA certificates, tzdata, and
# a non-root user - no shell, package manager, or libc. syft/grype/grant run
# in-process via their Go libraries (see pkg/scanner), so nothing besides
# the static binary and the CA bundle is required.
# The `static` image only ships a rolling `:latest` tag (no semver), so it's
# pinned by digest for reproducible builds. This MUST be the multi-arch
# manifest LIST digest, not a single-platform image digest - `docker
# pull`/`podman pull` + `inspect` on a local machine resolves to *that
# machine's* platform-specific manifest, which breaks multi-platform buildx
# builds (InvalidBaseImagePlatform: pulled with platform "arm64", expected
# "amd64" - exactly what pinning the arm64 digest here caused). Get the
# correct digest with:
#   docker buildx imagetools inspect quay.io/hummingbird/static:latest
# (its top-level "Digest:" line - the "Manifests:" sub-entries below it are
# the per-platform ones to avoid), or without Docker:
#   skopeo inspect --raw docker://quay.io/hummingbird/static:latest \
#     | sha256sum # must match the registry's Docker-Content-Digest header
FROM quay.io/hummingbird/static:latest@sha256:e6e00bcc3803b2faf7de0b08af2e1b21b155da6c891e153caafd99999c083ee1
WORKDIR /app

COPY --from=builder --chown=1001:0 /build/hullcheck ./hullcheck
COPY --from=builder --chown=1001:0 /build/data /data

ENV PORT=8080 \
    DATA_DIR=/data \
    HOME=/data

EXPOSE 8080
USER 1001:0

# No container-level HEALTHCHECK: the distroless runtime ships no shell or
# wget to run one. Kubernetes liveness/readiness probes hit /healthz and
# /readyz directly over HTTP instead (see charts/hullcheck, deploy/k8s).
CMD ["/app/hullcheck"]
