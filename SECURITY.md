# Security Policy

## Supported Versions

Security support applies to the current `main` branch and to release candidate
branches the maintainers announce. Releases v0.5.0 to v0.13.0 were published from
[gateway-fm/open-privacy-suite](https://github.com/gateway-fm/open-privacy-suite),
the archived repository the project was developed in before it moved here; fixes
for them are made on `main`.

## Reporting a Vulnerability

Please do not open public issues for suspected vulnerabilities.

Report security issues privately to:

- security@gateway.fm

Include:

- Affected component or endpoint.
- Reproduction steps or proof of concept.
- Impact and affected deployment assumptions.
- Suggested mitigation, if known.

Maintainers acknowledge and triage reports on a best-effort basis and will
respond as quickly as they can.

## Public Disclosure

Security issues should remain private until a fix or mitigation is available,
unless maintainers and the reporter agree on a different disclosure timeline.

## Scope

In scope:

- Open Privacy Suite backend, frontend, MCP tooling, and deployment manifests in
  this repository.
- Source-only release materials such as scripts, docs, examples, and generated
  code.

Out of scope:

- Third-party services operated outside this repository.
- Public test networks and local-only demo environments, except where they
  expose a vulnerability in production guidance or code.
