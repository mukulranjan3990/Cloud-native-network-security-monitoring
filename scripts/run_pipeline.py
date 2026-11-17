"""Run the cloud-native network-security monitoring pipeline.

Run from the repository root:
    python scripts/run_pipeline.py
    python scripts/run_pipeline.py --source sample --dry-run
    python scripts/run_pipeline.py --source cloudwatch --hours 1

The default source is local sample-data/*.log. Live AWS collection is opt-in.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

LOG = logging.getLogger("security_pipeline")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse network logs, detect suspicious patterns, score findings, and optionally save to SQLite."
    )
    parser.add_argument("--source", choices=("sample", "cloudwatch"), default="sample")
    parser.add_argument("--sample-dir", type=Path, default=PROJECT_ROOT / "sample-data")
    parser.add_argument("--files", nargs="+", type=Path, help="Specific sample log files.")
    parser.add_argument("--db-path", type=Path, default=PROJECT_ROOT / "data" / "security_monitor.db")
    parser.add_argument("--region", default=None, help="AWS region; defaults to AWS_REGION.")
    parser.add_argument("--log-group", default=None, help="CloudWatch log group; defaults to AWS_FLOW_LOG_GROUP.")
    parser.add_argument("--hours", type=float, default=1.0, help="CloudWatch look-back window in hours.")
    parser.add_argument("--limit", type=int, default=None, help="Optional maximum CloudWatch events.")
    parser.add_argument("--port-scan-min-ports", type=int, default=10)
    parser.add_argument("--repeated-min-count", type=int, default=20)
    parser.add_argument("--rejected-min-count", type=int, default=100)
    parser.add_argument("--dry-run", action="store_true", help="Analyze without writing to SQLite.")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def load_sample_messages(sample_dir: Path, selected_files: Sequence[Path] | None = None) -> List[str]:
    """Load non-empty, non-comment records from sample log files."""
    paths = ([p if p.is_absolute() else Path.cwd() / p for p in selected_files]
             if selected_files else sorted(sample_dir.glob("*.log")))
    if not paths:
        raise FileNotFoundError(f"No .log files found in {sample_dir}; add sample-data/*.log or use --files.")
    messages: List[str] = []
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"Sample log file not found: {path}")
        count = 0
        with path.open("r", encoding="utf-8") as stream:
            for line in stream:
                value = line.strip()
                if value and not value.startswith("#"):
                    messages.append(value)
                    count += 1
        LOG.info("Loaded %d records from %s", count, path)
    return messages


def collect_cloudwatch_events(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Fetch VPC Flow Log records from the configured CloudWatch Logs group."""
    from src.collector import CloudWatchLogCollector
    if args.hours <= 0:
        raise ValueError("--hours must be greater than zero.")
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=args.hours)
    collector = CloudWatchLogCollector(log_group_name=args.log_group, region_name=args.region)
    records = collector.fetch_events(
        start_time_ms=int(start.timestamp() * 1000),
        end_time_ms=int(end.timestamp() * 1000),
        limit=args.limit,
    )
    LOG.info("Collected %d CloudWatch records", len(records))
    return records


def run_pipeline(args: argparse.Namespace) -> Dict[str, Any]:
    """Execute input -> parse -> detect -> score -> persist."""
    from src.database import SecurityDatabase
    from src.detector import ThreatDetector
    from src.parser import EventParser
    from src.risk_scorer import RiskScorer

    raw_records = (load_sample_messages(args.sample_dir, args.files)
                   if args.source == "sample" else collect_cloudwatch_events(args))
    parser = EventParser()
    events: List[Dict[str, Any]] = []
    parse_errors: List[str] = []
    for index, raw in enumerate(raw_records, start=1):
        try:
            events.append(parser.parse(raw))
        except (TypeError, ValueError) as exc:
            message = f"record {index}: {exc}"
            parse_errors.append(message)
            LOG.warning("Skipping malformed %s", message)

    detector = ThreatDetector(
        port_scan_min_ports=args.port_scan_min_ports,
        repeated_attempt_min_count=args.repeated_min_count,
        rejected_min_count=args.rejected_min_count,
    )
    findings = RiskScorer().score_findings(detector.detect(events))
    inserted_events = inserted_findings = 0
    if not args.dry_run:
        database = SecurityDatabase(str(args.db_path))
        inserted_events = database.insert_events(events)
        inserted_findings = database.insert_findings(findings)

    return {
        "source": args.source,
        "records_received": len(raw_records),
        "events_parsed": len(events),
        "parse_errors": parse_errors,
        "findings_detected": len(findings),
        "findings": findings,
        "database_path": None if args.dry_run else str(args.db_path),
        "events_persisted": inserted_events,
        "new_findings_persisted": inserted_findings,
        "dry_run": args.dry_run,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s: %(message)s")
    try:
        result = run_pipeline(args)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        LOG.error("%s", exc)
        return 1
    except Exception:
        LOG.exception("Pipeline execution failed")
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
