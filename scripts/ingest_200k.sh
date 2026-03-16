#!/usr/bin/env bash
# =============================================================================
#  HashGuard — 200K Dataset Ingest Campaign
#  Starts continuous ingestion via the API targeting 200,000 samples.
#  Run this on the VPS after the stack is up.
# =============================================================================
set -euo pipefail

API_URL="${HASHGUARD_API_URL:-http://localhost:8000}"
API_KEY="${HASHGUARD_API_KEY:-}"
TARGET="${1:-200000}"
DELAY="${2:-0.5}"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  HashGuard — 200K Dataset Ingest Campaign        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Target:  ${GREEN}${TARGET}${NC} samples"
echo -e "  Delay:   ${DELAY}s between samples"
echo -e "  API:     ${API_URL}"
echo ""

# ── Check API health ────────────────────────────────────────────────────────
echo -n "Checking API health... "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${API_URL}/api/health" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" != "200" ]; then
    echo -e "${RED}FAIL${NC} (HTTP ${HTTP_CODE})"
    echo "Make sure the HashGuard API is running: docker compose -f docker-compose.production.yml up -d"
    exit 1
fi
echo -e "${GREEN}OK${NC}"

# ── Build auth header ───────────────────────────────────────────────────────
AUTH_HEADER=""
if [ -n "$API_KEY" ]; then
    AUTH_HEADER="-H \"X-API-Key: ${API_KEY}\""
fi

# ── Start continuous ingest ─────────────────────────────────────────────────
echo ""
echo -e "${CYAN}Starting continuous ingest...${NC}"
echo "  This will cycle through MalwareBazaar, URLhaus, MalShare, Hybrid Analysis,"
echo "  Triage, 50 popular tags, and 20 file types until ${TARGET} samples are analysed."
echo ""

RESPONSE=$(curl -s -X POST \
    "${API_URL}/api/ingest/start" \
    -H "Content-Type: application/json" \
    ${AUTH_HEADER} \
    -d "{\"source\": \"continuous\", \"limit\": ${TARGET}, \"delay\": ${DELAY}, \"use_vt\": false}")

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

# ── Monitor progress ────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}Monitoring progress (Ctrl+C to stop monitoring, ingest continues in background)...${NC}"
echo ""

while true; do
    sleep 30
    STATUS=$(curl -s "${API_URL}/api/ingest/status" ${AUTH_HEADER} 2>/dev/null)

    ANALYSED=$(echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('analysed',0))" 2>/dev/null || echo "?")
    ERRORS=$(echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('errors',0))" 2>/dev/null || echo "?")
    STATE=$(echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "?")
    CURRENT=$(echo "$STATUS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('current_sha256','')[:50])" 2>/dev/null || echo "")

    TIMESTAMP=$(date '+%H:%M:%S')
    echo -e "[${TIMESTAMP}] ${STATE} — ${GREEN}${ANALYSED}${NC}/${TARGET} analysed, ${RED}${ERRORS}${NC} errors | ${CURRENT}"

    if [ "$STATE" = "done" ] || [ "$STATE" = "stopped" ] || [ "$STATE" = "error" ]; then
        echo ""
        echo -e "${GREEN}Ingest finished: ${STATE}${NC}"
        echo "$STATUS" | python3 -m json.tool 2>/dev/null || echo "$STATUS"
        break
    fi
done
