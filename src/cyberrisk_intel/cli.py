from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path

from cyberrisk_intel.analytics.landscape import overview_metrics
from cyberrisk_intel.db.session import get_session, init_database
from cyberrisk_intel.ingestion.attack.mitre import sync_attack
from cyberrisk_intel.ingestion.event.california import sync_california_breaches
from cyberrisk_intel.ingestion.event.hhs import sync_hhs_breaches
from cyberrisk_intel.ingestion.event.massachusetts import sync_massachusetts_breaches
from cyberrisk_intel.ingestion.event.washington import sync_washington_breaches
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
    hhs = commands.add_parser("sync-hhs-breaches")
    hhs.add_argument("--limit", type=int, default=25)
    california = commands.add_parser("sync-california-breaches")
    california.add_argument("--limit", type=int, default=25)
    massachusetts = commands.add_parser("sync-massachusetts-breaches")
    massachusetts.add_argument("--limit", type=int, default=25)
    massachusetts.add_argument("--year", type=int, default=date.today().year)
    massachusetts.add_argument("--file", type=Path)
    washington = commands.add_parser("sync-washington-breaches")
    washington.add_argument("--limit", type=int, default=25)
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
        elif args.command == "sync-hhs-breaches":
            print(sync_hhs_breaches(session, limit=args.limit))
        elif args.command == "sync-california-breaches":
            print(sync_california_breaches(session, limit=args.limit))
        elif args.command == "sync-massachusetts-breaches":
            payload = args.file.read_bytes() if args.file else None
            print(
                sync_massachusetts_breaches(
                    session, payload, limit=args.limit, year=args.year
                )
            )
        elif args.command == "sync-washington-breaches":
            print(sync_washington_breaches(session, limit=args.limit))
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
