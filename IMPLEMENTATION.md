# Cyber Governance & Risk Intelligence Implementation

This document tracks the implemented V1 surface. It is updated with verified commands and results as the build progresses.

## Intended Complete Flow

Source or import file → immutable provenance → normalized entity → review → published index → cross-entity search/analysis → cited report.

## Verification Status

Verified on Windows with Python 3.12.13 on 2026-09-01:

- package build: pass (sdist and wheel)
- Ruff: pass
- Mypy: pass across 35 source files
- Pytest: 13/13 pass, 69% total coverage
- pip-audit: no known vulnerabilities in resolved third-party packages
- repeated demo seeding: stable at 10 policies, 12 events, 4 vulnerabilities, 213 relations,
  and 58 indexed chunks
- real browser smoke test: pass across overview, search, events, relationships, RAG, and reports
- JSON policy/event import: pass with idempotent updates and ingestion-run audit records
- Alembic initial migration: upgraded an empty SQLite database to head, including FTS5
- official synchronization: 1,687 KEV entries and 873 ATT&CK tactic/technique objects discovered,
  with zero ingestion failures; the local index now contains 2,593 chunks
- immutable provenance: two content-addressed raw snapshots and deduplicated raw-document records

The 30-policy/100-event research corpus and 50-question RAG benchmark remain explicit data-
building goals, not claimed implementation results.
