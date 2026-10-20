"""Command-line entry point for CI: scan a path, migrate, verify, write the report.

    python -m cryptolens.ci path/to/repo [--no-migrate] [--out reports]

Exit code 0 = gate passed, 1 = risky cryptography remains. Use it as a pipeline step.
"""
import argparse
import json
import sys
from pathlib import Path

from .config import REPORT_DIR
from .pipeline import Pipeline, load_model
from .stage6_report import to_markdown


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("path")
    ap.add_argument("--no-migrate", action="store_true", help="classify only")
    ap.add_argument("--backend", default="template", choices=["template", "anthropic"])
    ap.add_argument("--out", default=str(REPORT_DIR))
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):      # Windows consoles default to a narrow encoding
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    result = Pipeline(load_model(), args.backend).analyze_path(args.path, not args.no_migrate)
    if result is None:
        print("no Python files found")
        return 0
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cbom.json").write_text(json.dumps(result["cbom"], indent=2), encoding="utf-8")
    (out / "report.md").write_text(to_markdown(result["cbom"]), encoding="utf-8")
    print(to_markdown(result["cbom"]))
    return 0 if result["gate"]["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())