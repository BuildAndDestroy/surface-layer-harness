TOOLS_IMAGE   ?= surface-tools:latest
HARNESS_IMAGE ?= surface-harness:latest
DOCKERFILE    := docker/Dockerfile

.PHONY: help venv test images tools-image harness-image scan scan-docker engagement-docker merge serve clean

DOCKER_ENV = -e SECURITYTRAILS_API_KEY -e VIRUSTOTAL_API_KEY -e WHOISXML_API_KEY -e OTX_API_KEY \
	-e CERTSPOTTER_API_KEY -e OPENCORPORATES_API_TOKEN -e SURFACE_CONTACT -e SEC_USER_AGENT

help:
	@echo "make venv            - local Python venv (.venv) with the harness installed"
	@echo "make test            - run unit tests"
	@echo "make tools-image     - build recon tools image ($(TOOLS_IMAGE))"
	@echo "make harness-image   - build all-in-one harness image ($(HARNESS_IMAGE))"
	@echo "make scan D='acme.com' ARGS='--org \"Acme Inc\"'          - run locally (tools via docker)"
	@echo "make scan-docker D='acme.com' ARGS='-m passive'           - run fully inside docker"
	@echo "make engagement-docker E=acme ARGS='--parallel 3'         - run engagements/acme inside docker"
	@echo "make merge E=engagements/acme                             - rebuild report.md / engagement.json / graph"
	@echo "make serve E=engagements/acme                             - GraphQL on http://127.0.0.1:8787/graphql"

venv:
	python3 -m venv .venv
	.venv/bin/pip install -q -e '.[dev]'

test:
	.venv/bin/python -m pytest -q tests

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
