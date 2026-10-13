"""Licence boundary: aicl never imports Opencomplai; it is reached only through its CLI."""
import ast
import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = "opencomplai"


def _py_files():
    for base in (ROOT / "src" / "aicl", ROOT / "tests", ROOT / "scripts"):
        yield from (p for p in (base.rglob("*.py") if base.is_dir() else ()) if "__pycache__" not in p.parts)


def test_no_opencomplai_imports_in_source():
    bad = []
    for p in _py_files():
        for node in ast.walk(ast.parse(p.read_text("utf-8"), filename=str(p))):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0 else []
            bad += [f"{p.relative_to(ROOT)}:{node.lineno} {n}" for n in names if n.split(".")[0].startswith(FORBIDDEN)]
            if isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", "")) in (
                    "import_module", "__import__") and node.args and isinstance(node.args[0], ast.Constant) \
                    and str(node.args[0].value).startswith(FORBIDDEN):
                bad.append(f"{p.relative_to(ROOT)}:{node.lineno} dynamic import")
    assert not bad, bad


def test_importing_every_aicl_module_loads_no_opencomplai():
    # Fresh interpreter: pytest plugins must not pollute sys.modules.
    code = (
        "import importlib, json, pkgutil, sys, aicl\n"
        "mods = [m.name for m in pkgutil.walk_packages(aicl.__path__, 'aicl.') if m.name != 'aicl.__main__']\n"
        "for m in mods: importlib.import_module(m)\n"
        f"print(json.dumps({{'mods': mods, 'bad': sorted(k for k in sys.modules if k.startswith({FORBIDDEN!r}))}}))\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert {"aicl.core", "aicl.manifest"} <= set(out["mods"])
    assert out["bad"] == []


def test_pyproject_runtime_dependencies_exclude_opencomplai():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]
    assert project["dependencies"] == []
    assert not any(FORBIDDEN in d for d in project["dependencies"])
    assert any(d.startswith("opencomplai==") for d in project["optional-dependencies"]["dev"])
    assert "license" not in project and project["requires-python"] == ">=3.11"
    assert project["scripts"]["aicl"] == "aicl.cli:main"
