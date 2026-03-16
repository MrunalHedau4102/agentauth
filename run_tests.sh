#!/usr/bin/env bash
# =============================================================================
# run_tests.sh — agentauth Test Runner (bash version for macOS / Linux / WSL)
#
# Place this at the root of your AGENTAUTH project (it's already there).
#
# Usage:
#   ./run_tests.sh                   # run all tests
#   ./run_tests.sh --group tokens    # one group
#   ./run_tests.sh --group agents
#   ./run_tests.sh --group scopes
#   ./run_tests.sh --group audit
#   ./run_tests.sh --group guard
#   ./run_tests.sh --install         # pip install -e . first, then tests
#   ./run_tests.sh --coverage        # HTML + XML coverage report
#   ./run_tests.sh --fast            # skip slow tests (expiry waits)
#   ./run_tests.sh --verbose         # full tracebacks
#   ./run_tests.sh --failfast        # stop on first failure
#   ./run_tests.sh --install --group tokens --coverage
#
# On Windows use:  python run_tests.py  (same flags)
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── Defaults ──────────────────────────────────────────────────────────────────
GROUP="all"
INSTALL=false
COVERAGE=false
FAST=false
VERBOSE=false
FAILFAST=false

# ── Project root = directory this script lives in ─────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$SCRIPT_DIR/tests"
REPORTS_DIR="$SCRIPT_DIR/reports"
PKG_DIR="$SCRIPT_DIR/agentauth"

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --group|-g)    GROUP="$2"; shift 2 ;;
    --install|-i)  INSTALL=true;  shift ;;
    --coverage|-c) COVERAGE=true; shift ;;
    --fast|-f)     FAST=true;     shift ;;
    --verbose|-v)  VERBOSE=true;  shift ;;
    --failfast|-x) FAILFAST=true; shift ;;
    --help|-h)
      sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      echo "Run ./run_tests.sh --help for usage."
      exit 1
      ;;
  esac
done

# ── Banner ────────────────────────────────────────────────────────────────────
W=58
echo ""
printf "${BOLD}${CYAN}%${W}s${NC}\n" | tr ' ' '='
echo -e "${BOLD}${CYAN}  agentauth Test Runner${NC}"
echo -e "${BOLD}${CYAN}  Root: ${DIM}$SCRIPT_DIR${NC}"
printf "${BOLD}${CYAN}%${W}s${NC}\n" | tr ' ' '='

# ── Helpers ───────────────────────────────────────────────────────────────────
ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!!]${NC} $1"; }
err()  { echo -e "  ${RED}[XX]${NC} $1"; }
section() { echo -e "\n${BOLD}-- $1 $(printf '%0.s-' $(seq 1 $((50 - ${#1}))))${NC}"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
section "Preflight checks"
PASSED=true

# Python
if command -v python3 &>/dev/null; then
  PYTHON=python3
elif command -v python &>/dev/null; then
  PYTHON=python
else
  err "Python not found. Install Python 3.11+."
  exit 1
fi
PY_VER=$($PYTHON --version 2>&1)
ok "$PY_VER"

# pytest
if ! $PYTHON -m pytest --version &>/dev/null 2>&1; then
  err "pytest not found  ->  pip install pytest"
  PASSED=false
else
  PYTEST_VER=$($PYTHON -m pytest --version 2>&1 | head -1)
  ok "$PYTEST_VER"
fi

# pytest-asyncio
if ! $PYTHON -c "import pytest_asyncio" &>/dev/null 2>&1; then
  warn "pytest-asyncio not found — async tests skipped  ->  pip install pytest-asyncio"
else
  AA_VER=$($PYTHON -c "import pytest_asyncio; print(pytest_asyncio.__version__)" 2>/dev/null)
  ok "pytest-asyncio $AA_VER"
fi

# pytest-cov (only for --coverage)
if $COVERAGE; then
  if ! $PYTHON -c "import pytest_cov" &>/dev/null 2>&1; then
    err "pytest-cov not found  ->  pip install pytest-cov"
    PASSED=false
  else
    COV_VER=$($PYTHON -c "import pytest_cov; print(pytest_cov.__version__)" 2>/dev/null)
    ok "pytest-cov $COV_VER"
  fi
fi

# --install: run pip install -e . first
if $INSTALL; then
  if [[ ! -f "$SCRIPT_DIR/pyproject.toml" && ! -f "$SCRIPT_DIR/setup.py" ]]; then
    err "No pyproject.toml or setup.py found in $SCRIPT_DIR"
    PASSED=false
  else
    echo ""
    echo -e "  ${CYAN}Installing agentauth in editable mode...${NC}"
    echo -e "  ${DIM}$ pip install -e $SCRIPT_DIR${NC}"
    echo ""
    if ! $PYTHON -m pip install -e "$SCRIPT_DIR"; then
      err "pip install -e . failed."
      err "  Try:  pip install setuptools wheel"
      err "  Then: pip install -e ."
      PASSED=false
    else
      echo ""
      ok "Installed from $SCRIPT_DIR"
    fi
  fi
fi

# agentauth importable
if ! $PYTHON -c "import agentauth" &>/dev/null 2>&1; then
  err "agentauth is not importable."
  echo ""
  echo -e "  ${YELLOW}Your agentauth/ is at: ${BOLD}$PKG_DIR${NC}"
  echo ""
  echo -e "  ${YELLOW}Fix — choose one:${NC}"
  echo -e "  ${BOLD}Option A${NC} — use --install flag:"
  echo -e "    ${BOLD}./run_tests.sh --install${NC}"
  echo ""
  echo -e "  ${BOLD}Option B${NC} — install manually:"
  echo -e "    ${BOLD}pip install -e $SCRIPT_DIR${NC}"
  echo -e "    ${BOLD}./run_tests.sh${NC}"
  echo ""
  PASSED=false
else
  AA_VER=$($PYTHON -c "import agentauth; print(getattr(agentauth,'__version__','unknown'))" 2>/dev/null)
  AA_SRC=$($PYTHON -c "import agentauth; print(agentauth.__file__)" 2>/dev/null)
  ok "agentauth $AA_VER"
  echo -e "       ${DIM}source: $AA_SRC${NC}"
fi

# sqlalchemy
if ! $PYTHON -c "import sqlalchemy" &>/dev/null 2>&1; then
  err "sqlalchemy not found  ->  pip install sqlalchemy"
  PASSED=false
else
  SA_VER=$($PYTHON -c "import sqlalchemy; print(sqlalchemy.__version__)" 2>/dev/null)
  ok "sqlalchemy $SA_VER"
fi

# tests/ directory
if [[ ! -d "$TESTS_DIR" ]]; then
  err "tests/ directory not found: $TESTS_DIR"
  PASSED=false
else
  TEST_COUNT=$(ls "$TESTS_DIR"/test_*.py 2>/dev/null | wc -l | tr -d ' ')
  ok "tests/ — $TEST_COUNT test files found"
fi

# agentauth/ package directory
if [[ ! -d "$PKG_DIR" ]]; then
  warn "agentauth/ package not found at $PKG_DIR"
else
  ok "agentauth/ package directory exists"
fi

if [[ "$PASSED" == "false" ]]; then
  echo ""
  echo -e "${RED}${BOLD}  Preflight failed. Fix the errors above and re-run.${NC}"
  echo ""
  exit 1
fi

# ── Test plan ─────────────────────────────────────────────────────────────────
section "Test plan"

declare -A DESCRIPTIONS=(
  ["tokens"]="EphemeralTokenVault — issue, verify, expiry, one-time-use, bound_to"
  ["agents"]="AgentIdentity + AgentRegistry — register, trust, revoke, keypairs"
  ["scopes"]="ScopeManager + @require_scope — grant, validate, async support"
  ["audit"]="AuditLogger — hash chain, tamper detection, filtering"
  ["guard"]="PromptInjectionGuard — 5 rules, strict/non-strict, audit integration"
)

if [[ "$GROUP" == "all" ]]; then
  echo -e "  Running ${BOLD}all 5 groups${NC}:"
  echo ""
  for name in tokens agents scopes audit guard; do
    echo -e "  ${CYAN}>${NC} ${BOLD}${name}${NC}  ${DIM}${DESCRIPTIONS[$name]}${NC}"
  done
else
  echo -e "  ${BOLD}Group  :${NC} $GROUP"
fi

FLAGS=""
$INSTALL  && FLAGS="$FLAGS install"
$FAST     && FLAGS="$FLAGS fast"
$COVERAGE && FLAGS="$FLAGS coverage"
$VERBOSE  && FLAGS="$FLAGS verbose"
$FAILFAST && FLAGS="$FLAGS failfast"
[[ -n "$FLAGS" ]] && echo -e "\n  Flags  :$FLAGS"

# ── Build pytest command ──────────────────────────────────────────────────────
CMD=("$PYTHON" "-m" "pytest")

$VERBOSE  && CMD+=("-vv" "--tb=long")  || CMD+=("-v" "--tb=short")
$FAILFAST && CMD+=("-x")
$FAST     && CMD+=("-m" "not slow")

# asyncio mode if available
$PYTHON -c "import pytest_asyncio" &>/dev/null 2>&1 && CMD+=("--asyncio-mode=auto")

CMD+=("--durations=10" "--color=yes")

if $COVERAGE; then
  mkdir -p "$REPORTS_DIR"
  CMD+=(
    "--cov=agentauth"
    "--cov-report=term-missing"
    "--cov-report=html:$REPORTS_DIR/htmlcov"
    "--cov-report=xml:$REPORTS_DIR/coverage.xml"
    "--cov-fail-under=70"
  )
fi

declare -A GROUP_FILES=(
  ["tokens"]="test_tokens.py"
  ["agents"]="test_agents.py"
  ["scopes"]="test_scopes.py"
  ["audit"]="test_audit.py"
  ["guard"]="test_guard.py"
)

if [[ "$GROUP" == "all" ]]; then
  CMD+=("$TESTS_DIR")
else
  TARGET="$TESTS_DIR/${GROUP_FILES[$GROUP]}"
  if [[ ! -f "$TARGET" ]]; then
    err "Test file not found: $TARGET"
    exit 1
  fi
  CMD+=("$TARGET")
fi

# ── Run ───────────────────────────────────────────────────────────────────────
section "Running tests"
echo -e "  ${DIM}$ ${CMD[*]}${NC}"
echo ""

START=$(date +%s)
set +e
"${CMD[@]}"
EXIT_CODE=$?
set -e
END=$(date +%s)
ELAPSED=$((END - START))

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
printf "${BOLD}${CYAN}%${W}s${NC}\n" | tr ' ' '='

if [[ $EXIT_CODE -eq 0 ]]; then
  echo -e "${BOLD}${GREEN}  ALL TESTS PASSED  :)${NC}"
else
  echo -e "${BOLD}${RED}  SOME TESTS FAILED  (exit $EXIT_CODE)${NC}"
  echo -e "\n  Tip: ${BOLD}--verbose${NC}  for full tracebacks"
  echo -e "  Tip: ${BOLD}--failfast${NC} to stop on first failure"
fi

echo -e "\n  Time : ${ELAPSED}s"

if $COVERAGE; then
  HTML="$REPORTS_DIR/htmlcov/index.html"
  [[ -f "$HTML" ]] && echo -e "  HTML : ${GREEN}$HTML${NC}"
fi

printf "${BOLD}${CYAN}%${W}s${NC}\n\n" | tr ' ' '='

exit $EXIT_CODE
