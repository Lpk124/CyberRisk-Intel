from __future__ import annotations

import argparse
import json
from pathlib import Path

from cyberrisk_intel.analytics.landscape import overview_metrics
from cyberrisk_intel.db.session import get_session, init_database
from cyberrisk_intel.ingestion.attack.mitre import sync_attack
from cyberrisk_intel.ingestion.importers import import_events, import_policies
from cyberrisk_intel.ingestion.vulnerability.cve import fetch_cve
from cyberrisk_intel.ingestion.vulnerability.kev import sync_kev
from cyberrisk_intel.retrieval.index import rebuild_index
from cyberrisk_intel.services.report import REPORT_TITLES, generate_report
from cyberrisk_intel.services.seed import seed_demo


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="cyberrisk-intel")
    commands = root.add_subparsers(dest="command", required=True)
    for command in ("init-db", "seed-demo", "reindex", "sync-kev", "sync-attack", "status"):
        commands.add_parser(command)
    fetch = commands.add_parser("fetch-cve")
    fetch.add_argument("cve_id")
    ingest = commands.add_parser("ingest")
    ingest_commands = ingest.add_subparsers(dest="ingest_type", required=True)
    for entity_type in ("policies", "events"):
        import_parser = ingest_commands.add_parser(entity_type)
        import_parser.add_argument("path", type=Path)
    report = commands.add_parser("generate-report")
    report.add_argument("report", choices=REPORT_TITLES)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    init_database()
    if args.command == "init-db":
        print("Database initialized.")
        return 0
    with get_session() as session:
        if args.command == "seed-demo":
            seed_demo(session)
            count = rebuild_index(session)
            print(f"Demo data seeded; {count} chunks indexed.")
        elif args.command == "reindex":
            print(f"Indexed {rebuild_index(session)} chunks.")
        elif args.command == "sync-kev":
            print(sync_kev(session))
        elif args.command == "sync-attack":
            print(sync_attack(session))
        elif args.command == "fetch-cve":
            print(fetch_cve(session, args.cve_id).cve_id)
        elif args.command == "ingest":
            stats = (
                import_policies(session, args.path)
                if args.ingest_type == "policies"
                else import_events(session, args.path)
            )
            print(stats)
        elif args.command == "generate-report":
            print("\n".join(str(path) for path in generate_report(session, args.report)))
        elif args.command == "status":
            print(json.dumps(overview_metrics(session), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
