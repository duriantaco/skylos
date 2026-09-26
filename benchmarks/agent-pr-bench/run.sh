#!/usr/bin/env bash
# One-command reproduction of agent-pr-bench.
#
#   benchmarks/agent-pr-bench/run.sh
#
# Environment:
#   AGENT_PR_BENCH_WORK  scratch dir for clones/raw outputs (default: $TMPDIR/agent-pr-bench)
#   TOOLS_PYTHON         interpreter for the Semgrep/Bandit venv (default: python3.14, else python3)
#   SKYLOS_PYTHON        interpreter with Skylos' dependencies (default: python3; `pip install -e .` first)
#   SONAR_HOST_URL, SONAR_TOKEN, SONAR_SCANNER   optional: enables the SonarQube runner
#
# Network: clones pinned GitHub commits, downloads the Semgrep registry packs
# once per work dir, and Skylos' dependency-hallucination rule (SKY-D222)
# queries PyPI/npm. No results are uploaded anywhere.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${AGENT_PR_BENCH_WORK:-${TMPDIR:-/tmp}/agent-pr-bench}"
TOOLS_PYTHON="${TOOLS_PYTHON:-$(command -v python3.14 || command -v python3)}"
SKYLOS_PYTHON="${SKYLOS_PYTHON:-python3}"

mkdir -p "$WORK"
if [ ! -x "$WORK/venv/bin/semgrep" ] || [ ! -x "$WORK/venv/bin/bandit" ]; then
  "$TOOLS_PYTHON" -m venv "$WORK/venv"
  "$WORK/venv/bin/pip" install --quiet --upgrade pip
  "$WORK/venv/bin/pip" install --quiet -r "$HERE/requirements-tools.txt"
fi

exec "$SKYLOS_PYTHON" "$HERE/bench.py" all \
  --work "$WORK" \
  --semgrep "$WORK/venv/bin/semgrep" \
  --bandit "$WORK/venv/bin/bandit" \
  --skylos-python "$SKYLOS_PYTHON" "$@"
