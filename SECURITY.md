# Security Policy

## Supported versions

Security fixes are provided for the latest release on the `main` branch. The
current supported release line is `0.1.x`.

## Reporting a vulnerability

Please do not disclose a suspected vulnerability in a public issue, discussion,
pull request, dataset, or screenshot. Use GitHub's private vulnerability
reporting flow instead:

<https://github.com/Lpk124/CyberRisk-Intel/security/advisories/new>

Include the affected version or commit, reproduction steps, expected impact,
and any suggested mitigation. Do not include real credentials, personal data,
private incident records, or third-party confidential material. Reports are
handled on a best-effort basis, with an acknowledgment target of seven days.

## Security scope

In scope:

- ingestion adapters and untrusted source parsing;
- JSON and local-file import validation;
- SQLite/FTS queries and generated reports;
- optional LLM and embedding integrations;
- accidental disclosure of secrets or private data;
- dependency and GitHub Actions supply-chain risks.

Out of scope:

- availability or correctness of third-party public data sources;
- vulnerabilities in upstream services that are not caused by this project;
- unsupported public deployment configurations;
- reports based only on missing rate limits or denial-of-service against a
  local single-user instance.

## Deployment boundary

CyberRisk Intel is a local-first, single-user research application. It does not
currently provide authentication, tenant isolation, or a production permission
model. Publishing the source code does not mean the Streamlit application is
safe to expose directly to the internet. A public deployment requires an
authentication boundary, TLS termination, outbound-request controls, rate
limits, least-privilege database access, logging controls, and tested backups.

Secrets must be supplied through environment variables or an ignored local
Streamlit secrets file. Never commit API keys, local databases, raw snapshots,
or private research material.
