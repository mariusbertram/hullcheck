# syntax=docker/dockerfile:1

# ---- install node dependencies -------------------------------------------
FROM node:20-alpine AS deps
WORKDIR /app
COPY server/package.json ./
RUN npm install --omit=dev

# ---- final image: node runtime + syft/grype/grant CLIs -------------------
FROM node:20-alpine

# Pin specific tool versions for reproducible builds, e.g.
#   docker build --build-arg SYFT_VERSION=v1.18.1 ...
# Leave empty to install the latest release at build time.
ARG SYFT_VERSION=""
ARG GRYPE_VERSION=""
ARG GRANT_VERSION=""

RUN apk add --no-cache ca-certificates tzdata curl \
  && curl -sSfL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin ${SYFT_VERSION:+-v $SYFT_VERSION} \
  && curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin ${GRYPE_VERSION:+-v $GRYPE_VERSION} \
  && curl -sSfL https://get.anchore.io/grant | sh -s -- -b /usr/local/bin ${GRANT_VERSION:+-v $GRANT_VERSION} \
  && apk del curl \
  && syft version && grype version && grant version

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY server/package.json ./
COPY server/src ./src
COPY public ./public

ENV NODE_ENV=production \
    PORT=8080 \
    DATA_DIR=/data \
    HOME=/data

# Support running as an arbitrary, non-root UID (OpenShift restricted SCC):
# everything the app needs to write to is group-owned by root (gid 0) and
# group-writable, regardless of which UID the platform assigns at runtime.
RUN mkdir -p /data \
  && chgrp -R 0 /app /data \
  && chmod -R g=u /app /data

EXPOSE 8080
USER 1001:0

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz', r => process.exit(r.statusCode===200?0:1)).on('error', () => process.exit(1))"

CMD ["node", "src/index.js"]
