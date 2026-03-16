#!/usr/bin/env python
"""
run_tests.py — agentauth Test Runner
=====================================
Place this file at the root of your AGENTAUTH project (it's already there).

Your project layout:
    AGENTAUTH/
    ├── agentauth/        <- library source
    ├── tests/            <- test files
    ├── pyproject.toml
    ├── run_tests.py      <- YOU ARE HERE
    └── run_tests.sh

Usage:
    python run_tests.py                   # run all tests
    python run_tests.py --group tokens    # one group
    python run_tests.py --group agents
    python run_tests.py --group scopes
    python run_tests.py --group audit
    python run_tests.py --group guard
    python run_tests.py --coverage        # HTML + XML coverage in ./reports/
    python run_tests.py --fast            # skip slow tests (expiry waits)
    python run_tests.py --verbose         # full tracebacks
    python run_tests.py --failfast        # stop on first failure
    python run_tests.py --install         # run pip install -e . first, then tests
    python run_tests.py --install --group tokens --coverage
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

# ── Project root = directory this script lives in ─────────────────────────────
ROOT       = Path(__file__).parent.resolve()
TESTS_DIR  = ROOT / "tests"
REPORTS_DIR = ROOT / "reports"
PKG_DIR    = ROOT / "agentauth"


# ── Colour helpers ─────────────────────────────────────────────────────────────
class C:
    RED    = "\033[0;31m"
    GREEN  = "\033[0;32m"
    YELLOW = "\033[1;33m"
    CYAN   = "\033[0;36m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    NC     = "\033[0m"

    @staticmethod
    def disable():
        for a in ("RED","GREEN","YELLOW","CYAN","BOLD","DIM","NC"):
            setattr(C, a, "")

# Plain Windows cmd.exe doesn't support ANSI — disable colours
if sys.platform == "win32" and "ANSICON" not in os.environ and "WT_SESSION" not in os.environ:
    C.disable()


# ── Test groups ────────────────────────────────────────────────────────────────
GROUPS = {
    "tokens": "test_tokens.py",
    "agents": "test_agents.py",
    "scopes": "test_scopes.py",
    "audit":  "test_audit.py",
    "guard":  "test_guard.py",
}

DESCRIPTIONS = {
    "tokens": "EphemeralTokenVault — issue, verify, expiry, one-time-use, bound_to",
    "agents": "AgentIdentity + AgentRegistry — register, trust, revoke, keypairs",
    "scopes": "ScopeManager + @require_scope — grant, validate, async support",
    "audit":  "AuditLogger — hash chain, tamper detection, filtering",
    "guard":  "PromptInjectionGuard — 5 rules, strict/non-strict, audit integration",
}


# ── Print helpers ──────────────────────────────────────────────────────────────
def banner():
    w = 58
    print(f"\n{C.BOLD}{C.CYAN}{'=' * w}{C.NC}")
    print(f"{C.BOLD}{C.CYAN}  agentauth Test Runner{C.NC}")
    print(f"{C.BOLD}{C.CYAN}  Root: {C.DIM}{ROOT}{C.CYAN}{C.NC}")
    print(f"{C.BOLD}{C.CYAN}{'=' * w}{C.NC}")

def section(title):
    print(f"\n{C.BOLD}-- {title} {'-' * max(0, 50 - len(title))}{C.NC}")

def ok(msg):   print(f"  {C.GREEN}[OK]{C.NC} {msg}")
def warn(msg): print(f"  {C.YELLOW}[!!]{C.NC} {msg}")
def err(msg):  print(f"  {C.RED}[XX]{C.NC} {msg}")


# ── Editable install ───────────────────────────────────────────────────────────
def install_editable() -> bool:
    """
    Run: pip install -e .
    This installs agentauth from the current project root in editable mode.
    After this, `import agentauth` will pick up your local source files.
    """
    pyproject = ROOT / "pyproject.toml"
    setup_py  = ROOT / "setup.py"

    if not pyproject.exists() and not setup_py.exists():
        err(f"No pyproject.toml or setup.py found in {ROOT}")
        err( "  Cannot install — is this the right project root?")
        return False

    print(f"\n  {C.CYAN}Installing agentauth in editable mode...{C.NC}")
    print(f"  {C.DIM}$ pip install -e {ROOT}{C.NC}\n")

    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", str(ROOT)]
    )

    if result.returncode != 0:
        err("pip install -e . failed.")
        err("  Try running manually:")
        err(f"    pip install -e {ROOT}")
        return False

    # Flush any stale cached imports
    for mod in [k for k in sys.modules if k.startswith("agentauth")]:
        del sys.modules[mod]

    print()
    ok(f"Installed from {ROOT}")
    return True


# ── Preflight ──────────────────────────────────────────────────────────────────
def preflight(args) -> bool:
    section("Preflight checks")
    passed = True

    # Python version
    pv = sys.version_info
    if pv < (3, 11):
        warn(f"Python {pv.major}.{pv.minor} — 3.11+ recommended")
    else:
        ok(f"Python {pv.major}.{pv.minor}.{pv.micro}")

    # pytest
    try:
        import pytest
        ok(f"pytest {pytest.__version__}")
    except ImportError:
        err("pytest not found  ->  pip install pytest")
        passed = False

    # pytest-asyncio
    try:
        import pytest_asyncio
        ok(f"pytest-asyncio {pytest_asyncio.__version__}")
    except ImportError:
        warn("pytest-asyncio not found — async tests skipped  ->  pip install pytest-asyncio")

    # pytest-cov (only needed for --coverage)
    if args.coverage:
        try:
            import pytest_cov
            ok(f"pytest-cov {pytest_cov.__version__}")
        except ImportError:
            err("pytest-cov not found  ->  pip install pytest-cov")
            passed = False

    # --install flag: run pip install -e . before importing
    if args.install:
        if not install_editable():
            passed = False

    # agentauth importable?
    try:
        import agentauth
        ver = getattr(agentauth, "__version__", "unknown")
        src = getattr(agentauth, "__file__", "?")
        ok(f"agentauth {ver}")
        print(f"       {C.DIM}source: {src}{C.NC}")
    except ImportError:
        err("agentauth is not importable yet.")
        print(f"""
  {C.YELLOW}Your agentauth/ folder is at:{C.NC}
    {C.BOLD}{PKG_DIR}{C.NC}

  {C.YELLOW}Fix — choose one:{C.NC}

  {C.BOLD}Option A{C.NC} — use --install flag (easiest):
    {C.BOLD}python run_tests.py --install{C.NC}

  {C.BOLD}Option B{C.NC} — install once manually, then run normally:
    {C.BOLD}pip install -e .{C.NC}          <- run this in {ROOT}
    {C.BOLD}python run_tests.py{C.NC}
""")
        passed = False

    # sqlalchemy
    try:
        import sqlalchemy
        ok(f"sqlalchemy {sqlalchemy.__version__}")
    except ImportError:
        err("sqlalchemy not found  ->  pip install sqlalchemy")
        passed = False

    # tests/ directory
    if not TESTS_DIR.exists():
        err(f"tests/ directory not found: {TESTS_DIR}")
        passed = False
    else:
        files = sorted(TESTS_DIR.glob("test_*.py"))
        ok(f"tests/ — {len(files)} files: {', '.join(f.stem for f in files)}")

    # agentauth/ package directory
    if not PKG_DIR.exists():
        warn(f"agentauth/ package not found at {PKG_DIR}")
    else:
        ok(f"agentauth/ package directory exists")

    return passed


# ── Build pytest command ───────────────────────────────────────────────────────
def build_pytest_args(args) -> list:
    cmd = [sys.executable, "-m", "pytest"]

    # Verbosity
    cmd += ["-vv", "--tb=long"] if args.verbose else ["-v", "--tb=short"]

    # Fail fast
    if args.failfast:
        cmd += ["-x"]

    # Fast mode — skip @pytest.mark.slow tests (expiry waits)
    if args.fast:
        cmd += ["-m", "not slow"]

    # asyncio mode
    try:
        import pytest_asyncio
        cmd += ["--asyncio-mode=auto"]
    except ImportError:
        pass

    # Show the 10 slowest tests
    cmd += ["--durations=10"]

    # Colour output
    cmd += ["--color=yes"]

    # Coverage
    if args.coverage:
        REPORTS_DIR.mkdir(exist_ok=True)
        cmd += [
            "--cov=agentauth",
            "--cov-report=term-missing",
            f"--cov-report=html:{REPORTS_DIR / 'htmlcov'}",
            f"--cov-report=xml:{REPORTS_DIR / 'coverage.xml'}",
            "--cov-fail-under=70",
        ]

    # Test target
    if args.group == "all":
        cmd += [str(TESTS_DIR)]
    else:
        target = TESTS_DIR / GROUPS[args.group]
        if not target.exists():
            err(f"Test file not found: {target}")
            sys.exit(1)
        cmd += [str(target)]

    return cmd


# ── Test plan display ──────────────────────────────────────────────────────────
def print_test_plan(args):
    section("Test plan")
    if args.group == "all":
        print(f"  Running {C.BOLD}all {len(GROUPS)} groups{C.NC}:\n")
        for name, desc in DESCRIPTIONS.items():
            print(f"  {C.CYAN}>{C.NC} {C.BOLD}{name:8}{C.NC}  {C.DIM}{desc}{C.NC}")
    else:
        print(f"  {C.BOLD}Group  :{C.NC} {args.group}")
        print(f"  {C.BOLD}File   :{C.NC} {GROUPS[args.group]}")
        print(f"  {C.BOLD}Covers :{C.NC} {DESCRIPTIONS[args.group]}")

    flags = []
    if args.install:  flags.append(f"{C.CYAN}install{C.NC}")
    if args.fast:     flags.append(f"{C.YELLOW}fast{C.NC}")
    if args.coverage: flags.append(f"{C.GREEN}coverage{C.NC}")
    if args.verbose:  flags.append("verbose")
    if args.failfast: flags.append(f"{C.RED}failfast{C.NC}")
    if flags:
        print(f"\n  Flags  : {', '.join(flags)}")


# ── Final summary ──────────────────────────────────────────────────────────────
def print_summary(exit_code: int, elapsed: float, args):
    w = 58
    print(f"\n{C.BOLD}{C.CYAN}{'=' * w}{C.NC}")
    if exit_code == 0:
        print(f"{C.BOLD}{C.GREEN}  ALL TESTS PASSED  :){C.NC}")
    else:
        print(f"{C.BOLD}{C.RED}  SOME TESTS FAILED  (exit {exit_code}){C.NC}")
        print(f"\n  Tip: {C.BOLD}--verbose{C.NC}  to see full tracebacks")
        print(f"  Tip: {C.BOLD}--failfast{C.NC} to stop on first failure")

    print(f"\n  Time : {elapsed:.1f}s")

    if args.coverage:
        html = REPORTS_DIR / "htmlcov" / "index.html"
        if html.exists():
            print(f"  HTML coverage: {C.GREEN}{html}{C.NC}")

    print(f"{C.BOLD}{C.CYAN}{'=' * w}{C.NC}\n")


# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="agentauth Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--install", "-i",
        action="store_true",
        help="Run 'pip install -e .' first, then run tests. "
             "Use this the first time or after changing pyproject.toml.",
    )
    parser.add_argument(
        "--group", "-g",
        default="all",
        choices=["all"] + list(GROUPS.keys()),
        help="Which test group to run (default: all)",
    )
    parser.add_argument(
        "--coverage", "-c",
        action="store_true",
        help="Generate coverage report in ./reports/htmlcov/",
    )
    parser.add_argument(
        "--fast", "-f",
        action="store_true",
        help="Skip @pytest.mark.slow tests (token expiry waits)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Full tracebacks and extra detail",
    )
    parser.add_argument(
        "--failfast", "-x",
        action="store_true",
        help="Stop immediately on first failure",
    )
    args = parser.parse_args()

    banner()

    if not preflight(args):
        print(f"\n{C.RED}{C.BOLD}  Preflight failed. Fix the errors above and re-run.{C.NC}\n")
        sys.exit(1)

    print_test_plan(args)

    cmd = build_pytest_args(args)

    section("Running tests")
    print(f"  {C.DIM}$ {' '.join(str(c) for c in cmd)}{C.NC}\n")

    start  = time.time()
    result = subprocess.run(cmd)
    elapsed = time.time() - start

    print_summary(result.returncode, elapsed, args)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
