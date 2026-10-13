"""aicl command line: argparse tree dispatching to the cmd_* function of the owning module."""
from __future__ import annotations

import argparse
import importlib
import os
import sys
from pathlib import Path
from typing import Sequence

from aicl import __version__, decisionlog, hook

__all__ = ["build_parser", "main", "color_enabled"]

FAIL_ON = ("none", "new-major", "major", "critical")
SEMANTIC_FAIL_ON = ("none", "limited", "high_risk", "prohibited")


def color_enabled(no_color: bool = False) -> bool:
    """Colour only when not disabled by --no-color, NO_COLOR, or a non-tty stdout."""
    return not no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()


def _no_color(p: argparse.ArgumentParser) -> None:
    # SUPPRESS keeps a subcommand from resetting the global `aicl --no-color` back to False.
    p.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="disable colour")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aicl", description="AI Compliance Layer: runtime guardrail hook and agentic "
                                "CI wrapper around the Opencomplai CLI (reached only via subprocess).")
    p.add_argument("--version", action="version", version=f"aicl {__version__}")
    p.add_argument("--no-color", action="store_true", help="disable colour (also NO_COLOR or a non-tty stdout)")
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    i = sub.add_parser("init", help="install the hooks, write the oversight doc, merge the manifest, run agents check")
    i.add_argument("--repo", type=Path, default=Path("."))
    i.add_argument("--manifest", type=Path, help="default: <repo>/system-manifest.json")
    i.add_argument("--force", action="store_true", help="regenerate the oversight doc")
    i.add_argument("--opencomplai", help="path to the opencomplai executable")
    i.set_defaults(func="aicl.init_cmd:cmd_init")

    hook.add_parser(sub).set_defaults(func="aicl.hook:cmd_hook")
    decisionlog.add_parser(sub).set_defaults(func="aicl.decisionlog:cmd_log")

    c = sub.add_parser("ci", help="opencomplai check + verify-log, semantic classification, report, remediation")
    c.add_argument("--repo", type=Path, default=Path("."))
    c.add_argument("--manifest", type=Path, help="default: <repo>/system-manifest.json")
    c.add_argument("--fail-on", choices=FAIL_ON, default="major")
    c.add_argument("--semantic-fail-on", choices=SEMANTIC_FAIL_ON, default="high_risk")
    c.add_argument("--judge", choices=("auto", "off", "llm"), default="auto")
    c.add_argument("--out-dir", type=Path, help="default: <repo>")
    c.add_argument("--opencomplai", help="path to the opencomplai executable")
    c.add_argument("--quiet", action="store_true", help="print only the verdict line")
    _no_color(c)
    c.set_defaults(func="aicl.ci:cmd_ci")

    d = sub.add_parser("demo", help="run the seven-step acceptance narrative offline on a fixture copy")
    d.add_argument("--workdir", type=Path, help="keep everything here (default: a temp dir, deleted afterwards)")
    d.add_argument("--keep", action="store_true", help="keep the temp workdir")
    d.add_argument("--judge", choices=("off", "auto"), default="off")
    d.add_argument("--opencomplai", help="path to the opencomplai executable")
    _no_color(d)
    d.set_defaults(func="aicl.demo:cmd_demo")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.no_color = not color_enabled(bool(getattr(args, "no_color", False)))
    mod, fn = args.func.split(":")
    return int(getattr(importlib.import_module(mod), fn)(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
