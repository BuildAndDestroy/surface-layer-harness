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

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
 && go install -ldflags="-s -w" github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION} \
 && go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
 && go install -ldflags="-s -w" github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}

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
RUN pip install --no-cache-dir "/src[graphql]" && rm -rf /src
ENV SURFACE_TOOLS=local SURFACE_OUT=/data/runs
WORKDIR /data
# docker run surface-harness acme.com | ... engagement engagements/x | ... merge ... | ... serve ...
ENTRYPOINT ["surface-harness"]
