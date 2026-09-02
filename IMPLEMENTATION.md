# Cyber Governance & Risk Intelligence Implementation

This document tracks the implemented V1 surface. It is updated with verified commands and results as the build progresses.

## Intended Complete Flow

Source or import file → immutable provenance → normalized entity → review → published index → cross-entity search/analysis → cited report.

## Verification Status

Verified on Windows with Python 3.12.13 on 2026-09-01 through 2026-09-02:

- package build: pass (sdist and wheel)
- Ruff: pass
- Mypy: pass across 40 source files
- Pytest: 25/25 pass, 74% total coverage
- pip-audit: no known vulnerabilities in resolved third-party packages
- repeated demo seeding: stable at 30 policies, 12 events, 4 vulnerabilities, 298 relations,
  and 78 indexed chunks
- real browser smoke test: pass across overview, search, events, relationships, RAG, and reports
- JSON policy/event import: pass with idempotent updates and ingestion-run audit records
- Alembic initial migration: upgraded an empty SQLite database to head, including FTS5
- official synchronization: 1,687 KEV entries and 873 ATT&CK tactic/technique objects discovered,
  with zero ingestion failures; the local index now contains 2,613 chunks
- immutable provenance: content-addressed raw snapshots and deduplicated raw-document records
- event adapters: HHS OCR, California DOJ, Massachusetts OCABR PDF, and Washington AGO joined open-data feeds; local corpus is 103 records (12 published, 91 pending review)
- fresh migration chain: pass through `b31e6f24a908`, including nullable incident dates and incident end dates

The 30-policy target and 100-record source-backed event corpus have been exceeded locally. Of the 103
event records, 12 are published demo records and 91 are regulator-imported candidates awaiting review and
cross-source entity resolution. The 50-question RAG benchmark remains an explicit research goal and
is not claimed as completed.
