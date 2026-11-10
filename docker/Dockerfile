# syntax=docker/dockerfile:1
#
# Targets:
#   tools   - recon binaries only (subfinder, dnsx, httpx, naabu, nmap). The harness
#             running on the host calls these via `docker run --rm surface-tools <tool>`.
#   harness - tools + the Python harness. Everything runs inside the container.
#
# Build:  make images   (or: docker build -f docker/Dockerfile --target harness -t surface-harness .)

ARG GO_VERSION=1.26
ARG DEBIAN_RELEASE=bookworm

# ---------------------------------------------------------------------------
FROM golang:${GO_VERSION}-${DEBIAN_RELEASE} AS gobuild
ENV GOTOOLCHAIN=auto CGO_ENABLED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

ARG SUBFINDER_VERSION=v2.17.0
ARG DNSX_VERSION=v1.3.1
ARG HTTPX_VERSION=v1.12.0
ARG NAABU_VERSION=v2.7.0

# Upstream releases can lag behind fixes in their Go dependencies: build-pd.sh builds each tool from
# its release tag with these modules raised to their latest releases. Drop a module once upstream
# ships the fix.
ARG PATCH_MODULES="golang.org/x/net golang.org/x/crypto github.com/klauspost/compress github.com/andybalholm/brotli github.com/yuin/goldmark"
ENV PATCH_MODULES=${PATCH_MODULES}
COPY docker/build-pd.sh /usr/local/bin/build-pd.sh

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    build-pd.sh subfinder "${SUBFINDER_VERSION}" ./cmd/subfinder subfinder \
 && build-pd.sh dnsx      "${DNSX_VERSION}"      ./cmd/dnsx      dnsx \
 && build-pd.sh httpx     "${HTTPX_VERSION}"     ./cmd/httpx     httpx \
 && build-pd.sh naabu     "${NAABU_VERSION}"     ./cmd/naabu     naabu

# ---------------------------------------------------------------------------
FROM debian:${DEBIAN_RELEASE}-slim AS tools
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libpcap0.8 nmap \
 && rm -rf /var/lib/apt/lists/*
COPY --from=gobuild /go/bin/subfinder /go/bin/dnsx /go/bin/httpx /go/bin/naabu /usr/local/bin/
# Generate default configs at build time so first runs are quiet.
RUN subfinder -version >/dev/null 2>&1 || true
WORKDIR /work
# No ENTRYPOINT: callers run `docker run --rm surface-tools <tool> [args]`.
CMD ["sh", "-c", "for t in subfinder dnsx httpx naabu; do $t -version 2>&1 | tail -1; done; nmap --version | head -1"]

# ---------------------------------------------------------------------------
FROM tools AS harness
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1
COPY pyproject.toml /src/
COPY surface_harness /src/surface_harness
# DL3013: pip/setuptools are deliberately unpinned so every rebuild picks up their security fixes.
# hadolint ignore=DL3013
RUN pip install --no-cache-dir --upgrade pip setuptools \
 && pip install --no-cache-dir "/src[graphql]" && rm -rf /src
ENV SURFACE_TOOLS=local SURFACE_OUT=/data/runs
WORKDIR /data
# docker run surface-harness acme.com | ... engagement engagements/x | ... merge ... | ... serve ...
ENTRYPOINT ["surface-harness"]
