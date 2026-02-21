#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Run all LLM security demos in sequence (educational mode).
# Usage: ./demos/run_all_demos.sh
#        or inside the attacker container:
#        docker exec -it attacker bash /workspace/demos/run_all_demos.sh
# ─────────────────────────────────────────────────────────────────

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TARGET_URL="${TARGET_URL:-http://localhost:8000}"
export PYTHONPATH="$SCRIPT_DIR"

echo ""
echo "================================================================"
echo "  LLM Security Demo Suite — Cybersecurity Class"
echo "  Target: $TARGET_URL"
echo "================================================================"
echo ""

# Wait for server
until curl -sf "$TARGET_URL/health" > /dev/null; do
  echo "Waiting for llm-server..."
  sleep 2
done

echo "[OK] Server is up."
echo ""

for demo in \
    01_prompt_injection \
    02_jailbreaking \
    03_prompt_leaking \
    04_filter_bypass; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Running: $demo"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    python "$SCRIPT_DIR/${demo}.py"
    echo ""
    echo "Press ENTER to continue to next demo..."
    read -r
done

echo "All demos complete. See the Jupyter notebook for the hardened version."
