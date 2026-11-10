TOOLS_IMAGE   ?= surface-tools:latest
HARNESS_IMAGE ?= surface-harness:latest
DOCKERFILE    := docker/Dockerfile

.PHONY: help venv lint audit check test images tools-image harness-image scan scan-docker engagement-docker merge serve clean

DOCKER_ENV = -e SECURITYTRAILS_API_KEY -e VIRUSTOTAL_API_KEY -e WHOISXML_API_KEY -e OTX_API_KEY \
	-e CERTSPOTTER_API_KEY -e OPENCORPORATES_API_TOKEN -e SURFACE_CONTACT -e SEC_USER_AGENT

help:
	@echo "make venv            - local Python venv (.venv) with the harness installed"
	@echo "make test            - run unit tests"
	@echo "make lint            - ruff (style + bandit SAST rules) and hadolint"
	@echo "make audit           - pip-audit the venv for known-vulnerable dependencies"
	@echo "make check           - lint + audit + test (what CI runs)"
	@echo "make tools-image     - build recon tools image ($(TOOLS_IMAGE))"
	@echo "make harness-image   - build all-in-one harness image ($(HARNESS_IMAGE))"
	@echo "make scan D='acme.com' ARGS='--org \"Acme Inc\"'          - run locally (tools via docker)"
	@echo "make scan-docker D='acme.com' ARGS='-m passive'           - run fully inside docker"
	@echo "make engagement-docker E=acme ARGS='--parallel 3'         - run engagements/acme inside docker"
	@echo "make merge E=engagements/acme                             - rebuild report.md / engagement.json / graph"
	@echo "make serve E=engagements/acme                             - GraphQL on http://127.0.0.1:8787/graphql"

PYTHON ?= $(shell for p in python3.13 python3.12 python3.11 python3 $$HOME/.pyenv/versions/3.1[1-9]*/bin/python3; do $$p -c 'import sys; assert sys.version_info >= (3, 11)' >/dev/null 2>&1 && { echo $$p; break; }; done)

venv:
	@test -n "$(PYTHON)" || { echo 'Python >= 3.11 required (set PYTHON=/path/to/python3.11+)'; exit 1; }
	$(PYTHON) -m venv .venv
	.venv/bin/pip install -q -e '.[dev]'

test:
	.venv/bin/python -m pytest -q tests

lint:
	.venv/bin/ruff check surface_harness tests
	docker run --rm -i -v "$(CURDIR)/.hadolint.yaml:/.config/hadolint.yaml:ro" hadolint/hadolint:v2.12.0 < $(DOCKERFILE)

audit:
	.venv/bin/pip-audit --skip-editable --progress-spinner off

check: lint audit test

images: tools-image harness-image

tools-image:
	docker build -f $(DOCKERFILE) --target tools -t $(TOOLS_IMAGE) .

harness-image:
	docker build -f $(DOCKERFILE) --target harness -t $(HARNESS_IMAGE) .

scan:
	.venv/bin/surface-harness --tools auto --docker-image $(TOOLS_IMAGE) $(ARGS) $(D)

# --network host so DNS/port scanning behaves like a host run; results land in ./runs
scan-docker:
	mkdir -p runs
	docker run --rm -it --network host -v "$(CURDIR)/runs:/data/runs" \
		--user "$$(id -u):$$(id -g)" -e HOME=/tmp \
		$(DOCKER_ENV) $(HARNESS_IMAGE) $(ARGS) $(D)

# E is the engagement id (directory name under ./engagements)
engagement-docker:
	docker run --rm -it --network host -v "$(CURDIR)/engagements:/data/engagements" \
		--user "$$(id -u):$$(id -g)" -e HOME=/tmp \
		$(DOCKER_ENV) $(HARNESS_IMAGE) engagement engagements/$(notdir $(E)) $(ARGS)

merge:
	.venv/bin/surface-harness merge $(E)

serve:
	.venv/bin/surface-harness serve $(E)

clean:
	rm -rf .venv *.egg-info .pytest_cache
