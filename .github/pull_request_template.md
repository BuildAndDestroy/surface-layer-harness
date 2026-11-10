## What and why

<!-- What does this change, and why? Link issues. -->

## How it was tested

- [ ] `make lint test` passes locally
- [ ] Ran against an authorised target (say which mode) or only unit tests
- [ ] `make images` (if `docker/`, dependencies or tooling changed)

## Safety checklist

- [ ] No client data, scan output, `engagements/` or `runs/` content committed
- [ ] No API keys, tokens or personal contact details in code, tests or fixtures
- [ ] New network activity respects the mode gates (passive / standard / active + authorization)
- [ ] New sources never pivot on registered agents or WHOIS privacy proxies
- [ ] Output schema changes bump `schema_version` and are noted in the README
