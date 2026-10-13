#!/usr/bin/env python3
"""Fake `opencomplai` for aicl ci tests: prints the captured tests/data samples, exit code chosen by argv.

FAKE_OC_EXIT=<n> forces exit n (2 = validation_fail: no JSON, message on stderr). FAKE_OC_GAPS=after picks the
post-init gaps sample. Never imports opencomplai; standard library only.
"""
import json
import os
import sys
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"


def sample(name: str) -> dict:
    return json.loads((DATA / f"{name}.sample.json").read_text("utf-8"))


def flag(argv: list[str], name: str) -> str | None:
    return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else None


def main(argv: list[str]) -> int:
    if argv[:1] == ["--version"]:
        print("opencomplai 0.12.0")
        return 0
    forced = os.environ.get("FAKE_OC_EXIT")
    if forced == "2":
        print("Error: manifest failed validation (fake opencomplai)", file=sys.stderr)
        return 2
    if argv[:1] == ["check"]:
        manifest = flag(argv, "-m") or ""
        obj, code = sample("check_patched" if manifest.endswith(".proposed.json") else "check"), 1
    elif argv[:2] == ["agents", "verify-log"]:
        obj = sample("verify_log")
        want = flag(argv, "--expected-count")
        if want is not None and int(want) != obj["chain"]["count"]:
            obj["chain"].update(ok=False, error="count")
        code = 0 if obj["chain"]["ok"] and not obj["out_of_mandate"] else 1
        obj["status"] = "ok" if code == 0 else "invalid"
    elif argv[:2] == ["agents", "check"]:
        obj, code = sample("agents_check"), 0
    elif argv[:1] == ["gaps"]:
        obj, code = sample("gaps_after" if os.environ.get("FAKE_OC_GAPS") == "after" else "gaps_before"), 0
    else:
        print(f"fake opencomplai: unsupported argv {argv}", file=sys.stderr)
        return 2
    print(json.dumps(obj, indent=2))
    return int(forced) if forced else code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
