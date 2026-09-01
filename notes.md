# Implementation Notes

## Repository Findings
- The repository started with only `.git` and no commits, code, data, or documentation.
- A bundled Python 3.12.13 runtime is available to create and test a project environment.
- Docker and uv are not globally installed; Docker is intentionally outside V1.

## Product Guardrails
- Policy is one intelligence source, not the product root.
- Business scenarios are demonstrations, not enterprise compliance assessments.
- Published facts and relationships require provenance and review state.
- Public-event counts are samples of collected disclosures, not incident prevalence.
- AI output is always a candidate or cited research aid.

## Reference Boundaries
- OpenCTI, CISO Assistant, and MISP contribute conceptual patterns only.
- MITRE ATT&CK, CISA KEV, CVE, and NIST content keep source and license attribution.
- Legal RAG contributes design ideas only because its repository does not state a standard open-source license.

## Verified Implementation Snapshot

- Demo dataset: 10 policies, 12 security events, 4 vulnerabilities (3 KEV), 7 ATT&CK
  techniques, 15 baseline controls, and 3 validation scenarios.
- Published relationship edges: 213; unified search chunks: 58.
- Checks: build pass, Ruff pass, Mypy pass, 13 tests pass, 69% coverage, dependency audit clean.
- Browser smoke test passed on six representative Streamlit pages using local Edge.
- JSON policy/event imports are idempotent and audited; the initial Alembic migration was
  validated against an empty SQLite database.
- Official sync snapshot: 1,687 KEV entries, 858 ATT&CK techniques, 1,688 vulnerabilities,
  and 2,593 indexed chunks. The synchronized SQLite database remains local and is not committed.
- Two official download snapshots are stored under ignored `data/raw` paths and registered by hash.
