# Task Plan: Cyber Governance & Risk Intelligence V1

## Goal
Build a real, locally runnable, tested Streamlit system that unifies policies, security events, vulnerabilities, ATT&CK techniques, risks, industries, and controls with provenance, review, search, analytics, reports, and optional AI assistance.

## Phases
- [x] Phase 1: Confirm repository state and implementation scope
- [x] Phase 2: Bootstrap project, domain model, database, and seed data
- [x] Phase 3: Implement ingestion, unified retrieval, relations, and analytics
- [x] Phase 4: Implement Streamlit UI, reports, review, and scenario demos
- [x] Phase 5: Run tests, quality checks, startup checks, and update documentation

## Key Questions
1. Can the application run without any LLM or embedding credentials? Yes; lexical retrieval and deterministic reports are mandatory fallbacks.
2. How is evidence preserved? Every published entity and relationship carries source/provenance and review state.
3. How is V1 kept lightweight? SQLite, modular Python services, local NetworkX/Plotly rendering, and no graph database or web API.

## Decisions Made
- Python 3.12, Streamlit, SQLAlchemy, SQLite, Pandas, Plotly, Pydantic.
- Current repository is empty; there is no legacy code or data to migrate.
- Policy seed data contains 30 source-verified policy/governance records; event seed data remains explicitly labeled demo data and is not presented as the final 100-event research corpus.
- KEV, ATT&CK, and CVE connectors are implemented as explicit commands; online synchronization is not required for offline tests.
- AI and embeddings use an optional OpenAI-compatible interface and never gate core functionality.

## Errors Encountered
- System `python` and `uv` are not on PATH; a bundled Python 3.12 runtime is available.
- Bundled Git lacks `git-remote-https`; local Git works but remote synchronization requires a repaired/system Git installation.
- Default Windows uv/pip-audit cache locations collided with inaccessible filesystem entries;
  verification used task-specific cache directories.
- The installed `npx` launcher is broken because `npx-cli.js` is missing; UI verification used
  native Python Playwright with the locally installed Edge browser.
- Production `autoflush=False` exposed pending-relation duplicate handling; the seed service now
  checks persisted and pending relations, and the integration fixture matches production.

## Status
**In progress** - the runnable V1, reproducible environment, tests, security checks, browser smoke
test, and initial documentation are finished. The 30-record policy target is complete. Event corpus
expansion and the 50-question RAG benchmark remain data/research milestones and are not represented
as completed results.
