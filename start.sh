#!/usr/bin/env bash
# ============================================================
# Pentra AI — Unified Start / Management Script
#
# Usage:
#   ./start.sh [command] [options]
#
# Commands:
#   (kosong)           Start semua services
#   api                Start API server saja
#   worker             Start Celery worker + beat saja
#   web                Start frontend dev server saja
#   infra              Start Docker infra (PostgreSQL, Redis, Qdrant)
#
#   scan [domain]      Jalankan live scan
#   scan:burp [domain] Live scan dengan Burp forced-enable
#
#   burp:check         Cek koneksi Burp MCP + Proxy
#   burp:setup         Panduan interaktif setup Burp Suite
#   burp:test [url]    Kirim request uji melalui Burp Proxy
#
#   logs               Tail semua log (api + worker + beat)
#   logs [filter]      Tail dengan grep filter
#   logs:api           Tail log API saja
#   logs:worker        Tail log Worker saja
#   logs:scan          Tail log scan terakhir
#   logs:rotate        Rotate semua log (gzip + new empty)
#   logs:clear         Hapus semua log file
#
#   status             Tampilkan status lengkap semua service
#   stop               Stop semua service Pentra
#   restart [svc]      Restart service tertentu (api|worker|web|all)
#
#   kb:stats           Tampilkan Knowledge Base statistics
#   kb:reembed         Trigger re-embed semua KB records dengan bge-m3
#
# Env overrides:
#   API_PORT=8001      Port API server (default 8001)
#   BURP_MCP_URL       Burp MCP URL (default http://localhost:9877)
#   BURP_PROXY_URL     Burp HTTP Proxy (default http://localhost:8082)
# ============================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$REPO_ROOT/.logs"
mkdir -p "$LOG_DIR"

# ── Configuration ─────────────────────────────────────────────────────────────
API_PORT="${API_PORT:-8001}"
BURP_MCP_URL="${BURP_MCP_URL:-http://localhost:9877}"
BURP_PROXY_URL="${BURP_PROXY_URL:-http://localhost:8082}"
BURP_PROXY_PORT="${BURP_PROXY_URL##*:}"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
MAG='\033[0;35m'
CYN='\033[0;36m'
WHT='\033[1;37m'
DIM='\033[2m'
RST='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${BLU}[INFO]${RST}  $*"; }
ok()      { echo -e "${GRN}[ OK ]${RST}  $*"; }
warn()    { echo -e "${YLW}[WARN]${RST}  $*"; }
err()     { echo -e "${RED}[ERR ]${RST}  $*"; }
section() {
    echo -e ""
    echo -e "${CYN}╔══════════════════════════════════════════════════╗${RST}"
    printf  "${CYN}║${RST}  %-48s${CYN}║${RST}\n" "$*"
    echo -e "${CYN}╚══════════════════════════════════════════════════╝${RST}"
}

_get_token() {
    curl -s "http://localhost:${API_PORT}/api/v1/auth/login" \
        -X POST -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"Pentra@2026!"}' \
        2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null
}

_port_up() { ss -tlnp 2>/dev/null | grep -q ":${1} "; }

_http_up() {
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "$1" 2>/dev/null)
    [[ "$code" =~ ^[2345] ]]
}

# ═══════════════════════════════════════════════════════════
# INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════

start_infra() {
    section "Starting Docker infrastructure"
    if ! command -v docker &>/dev/null; then
        warn "docker not found — assuming infra already running externally"
        return
    fi
    cd "$REPO_ROOT/infra"
    info "docker compose up -d  (db redis qdrant)"
    docker compose up -d db redis qdrant 2>&1 | grep -v "^$"
    info "Waiting for services to be ready..."
    local tries=0
    until _port_up 5432 && _port_up 6379 && _port_up 6333; do
        sleep 1; tries=$((tries+1))
        [[ $tries -ge 45 ]] && { err "Infra failed to start in 45s"; docker compose logs --tail 20 2>/dev/null; exit 1; }
        [[ $((tries % 5)) -eq 0 ]] && info "  Still waiting... (${tries}s)"
    done
    ok "PostgreSQL :5432  Redis :6379  Qdrant :6333  ✓"
    cd "$REPO_ROOT"
}

check_infra() {
    section "Infrastructure Check"
    local all_ok=true

    if _port_up 5432; then ok "PostgreSQL   :5432"
    else
        warn "PostgreSQL   :5432  (tidak running — mencoba auto-start...)"
        if command -v docker &>/dev/null; then
            cd "$REPO_ROOT/infra" && docker compose up -d db 2>&1 | tail -3
            cd "$REPO_ROOT"
            sleep 3
            _port_up 5432 && ok "PostgreSQL   :5432  ✓ (started)" || { err "PostgreSQL gagal start"; all_ok=false; }
        else
            all_ok=false
        fi
    fi

    if _port_up 6379; then ok "Redis        :6379"
    else
        warn "Redis        :6379  (tidak running — mencoba auto-start...)"
        if command -v docker &>/dev/null; then
            cd "$REPO_ROOT/infra" && docker compose up -d redis 2>&1 | tail -3
            cd "$REPO_ROOT"
            sleep 3
            _port_up 6379 && ok "Redis        :6379  ✓ (started)" || { err "Redis gagal start"; all_ok=false; }
        else
            all_ok=false
        fi
    fi

    if _port_up 6333; then ok "Qdrant       :6333"
    else
        warn "Qdrant       :6333  (tidak running — mencoba auto-start...)"
        if command -v docker &>/dev/null; then
            cd "$REPO_ROOT/infra" && docker compose up -d qdrant 2>&1 | tail -3
            cd "$REPO_ROOT"
            sleep 5
            _port_up 6333 && ok "Qdrant       :6333  ✓ (started)" || { err "Qdrant gagal start"; all_ok=false; }
        else
            all_ok=false
        fi
    fi

    if _http_up "http://localhost:11434/api/tags"; then
        local models
        models=$(curl -sf "http://localhost:11434/api/tags" 2>/dev/null | \
            python3 -c "import sys,json; print(', '.join(m['name'] for m in json.load(sys.stdin).get('models',[])))" 2>/dev/null || echo "?")
        ok "Ollama       :11434  [${models}]"
    else
        warn "Ollama       :11434  (tidak reachable — LLM & embedding disabled)"
        echo -e "       ${DIM}Jalankan Ollama: ollama serve${RST}"
    fi

    if curl -sf "http://localhost:11434/api/tags" 2>/dev/null | grep -q "bge-m3"; then
        ok "bge-m3       embedding model installed"
    else
        warn "bge-m3       tidak terinstall"
        echo -e "       ${DIM}Fix: ollama pull bge-m3${RST}"
    fi

    _check_burp_silent || true

    if [[ "$all_ok" == "false" ]]; then
        echo ""
        err "Infra kritis gagal start. Coba manual: cd infra && docker compose up -d"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════
# BURP SUITE
# ═══════════════════════════════════════════════════════════

_check_burp_silent() {
    local mcp_ok=false proxy_ok=false

    if [[ -n "$(curl -s --max-time 2 "${BURP_MCP_URL}/" 2>/dev/null)" ]]; then
        mcp_ok=true
    fi

    if curl -s --proxy "${BURP_PROXY_URL}" --max-time 3 \
        -o /dev/null -w "%{http_code}" "http://testaspnet.vulnweb.com/" 2>/dev/null | grep -qE "^[123456]"; then
        proxy_ok=true
    fi

    if $mcp_ok && $proxy_ok; then
        ok "Burp Suite   MCP ${BURP_MCP_URL}  Proxy ${BURP_PROXY_URL}  ✓"
        return 0
    elif $mcp_ok; then
        warn "Burp Suite   MCP ✓  Proxy ${BURP_PROXY_URL} ✗ (check Proxy listener)"
        return 1
    else
        warn "Burp Suite   not connected (optional — passive mode active)"
        echo -e "       ${DIM}Run: ./start.sh burp:setup${RST}"
        return 1
    fi
}

check_burp() {
    section "Burp Suite Connection Check"

    echo ""
    echo -e "  ${WHT}MCP Server${RST}  ${DIM}(${BURP_MCP_URL})${RST}"
    local mcp_resp
    mcp_resp=$(curl -s --max-time 5 "${BURP_MCP_URL}/" 2>/dev/null || echo "")

    if [[ -n "$mcp_resp" ]]; then
        ok "  MCP reachable"
        local tool_count
        tool_count=$(echo "$mcp_resp" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    tools = d.get('tools', d.get('result', {}).get('tools', []))
    print(len(tools))
except:
    print('?')
" 2>/dev/null || echo "?")
        echo -e "     Tools available: ${CYN}${tool_count}${RST}"
    else
        err "  MCP not reachable at ${BURP_MCP_URL}"
        echo ""
        echo -e "     ${YLW}Troubleshooting:${RST}"
        echo -e "     1. Pastikan Burp Suite sedang berjalan"
        echo -e "     2. Install extension: ${CYN}Burp MCP Server${RST}"
        echo -e "        (Extensions → BApp Store → cari 'MCP')"
        echo -e "     3. Di extension settings: klik 'Start Server' → port 9877"
        echo -e "     4. Atau jalankan: ${CYN}./start.sh burp:setup${RST} untuk panduan lengkap"
    fi

    echo ""
    echo -e "  ${WHT}HTTP Proxy${RST}  ${DIM}(${BURP_PROXY_URL})${RST}"
    local proxy_code
    proxy_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --proxy "${BURP_PROXY_URL}" --max-time 5 \
        "http://testaspnet.vulnweb.com/" 2>/dev/null || echo "000")

    if [[ "$proxy_code" =~ ^[123456] ]] && [[ "$proxy_code" != "000" ]]; then
        ok "  Proxy reachable (test request → HTTP ${proxy_code})"
        echo -e "     ${DIM}Cek Burp → Proxy → HTTP History${RST}"
    else
        err "  Proxy not reachable at ${BURP_PROXY_URL}"
        echo ""
        echo -e "     ${YLW}Troubleshooting:${RST}"
        echo -e "     1. Burp → Proxy → Options → Proxy Listeners"
        echo -e "     2. Add listener: port ${BURP_PROXY_PORT}, All interfaces"
        echo -e "     3. Atau ubah BURP_PROXY_URL di ${REPO_ROOT}/apps/api/.env"
    fi

    if grep -qi "microsoft\|wsl" /proc/version 2>/dev/null; then
        local gw
        gw=$(ip route show default 2>/dev/null | awk '/default/{print $3}' | head -1 || echo "N/A")
        echo ""
        echo -e "  ${YLW}WSL2 Tips${RST}"
        echo -e "  • Windows gateway IP: ${CYN}${gw}${RST}"
        echo -e "  • Jika Burp di Windows: BURP_MCP_URL=http://${gw}:9877"
        echo -e "  • Atau gunakan mirrored networking (wsl2 networkingMode=mirrored)"
    fi
    echo ""
}

setup_burp() {
    section "Burp Suite Setup Guide"
    cat << 'GUIDE'

  Pentra AI menggunakan dua koneksi ke Burp Suite:
  ┌─────────────────────────────────────────────────────────┐
  │  1. Burp MCP Server  (port 9877) — tool automation      │
  │  2. Burp HTTP Proxy  (port 8082) — traffic capture      │
  └─────────────────────────────────────────────────────────┘

  ── LANGKAH 1: Install Burp MCP Extension ─────────────────

  a. Buka Burp Suite Pro
  b. Tab "Extensions" → "BApp Store"
  c. Cari "MCP" → Install "Burp MCP Server"
     (atau manual: Extensions → Add → pilih .jar)
  d. Tab "Extensions" → klik extension "Burp MCP Server"
  e. Klik "Start Server" → port 9877
     Output: "MCP server started on 0.0.0.0:9877"

  ── LANGKAH 2: Konfigurasi HTTP Proxy Listener ────────────

  a. Burp → Proxy → Options → Proxy Listeners
  b. Klik "Add"
  c. Binding tab:
       Bind to port:      8082
       Bind to address:   All interfaces  (0.0.0.0)
  d. Klik OK → pastikan listener aktif (checkbox hijau ✓)

  ── LANGKAH 3: Update .env ────────────────────────────────

  File: apps/api/.env
    BURP_MCP_URL=http://localhost:9877
    BURP_MCP_ENABLED=true
    BURP_PROXY_URL=http://localhost:8082

  ── LANGKAH 4 (WSL2): Jika Burp di Windows ───────────────

  Opsi A — WSL2 Mirrored Networking (direkomendasikan):
    File: %USERPROFILE%\.wslconfig  (di Windows)
    ─────────────────────────────────
    [wsl2]
    networkingMode=mirrored
    ─────────────────────────────────
    Restart: wsl --shutdown
    → Setelah ini, localhost di WSL = localhost di Windows

  Opsi B — Portproxy manual (PowerShell sebagai Admin):
    $wslIp = (wsl -- hostname -I).Trim().Split()[0]
    netsh interface portproxy add v4tov4 ^
      listenport=9877 listenaddress=0.0.0.0 ^
      connectport=9877 connectaddress=$wslIp
    netsh interface portproxy add v4tov4 ^
      listenport=8082 listenaddress=0.0.0.0 ^
      connectport=8082 connectaddress=$wslIp

  Opsi C — .env pakai Windows IP:
    Cari Windows gateway dari WSL: ip route show default | awk '/default/{print $3}'
    BURP_MCP_URL=http://<windows-ip>:9877
    BURP_PROXY_URL=http://<windows-ip>:8082

  ── LANGKAH 5: Verifikasi ─────────────────────────────────

GUIDE

    echo -n "  Cek koneksi sekarang? [Y/n]: "
    read -r answer
    [[ "${answer,,}" != "n" ]] && check_burp
}

test_burp_proxy() {
    local target="${1:-http://testaspnet.vulnweb.com/}"
    section "Burp Proxy Test → ${target}"
    echo ""
    info "Sending via ${BURP_PROXY_URL} → ${target}"
    echo ""
    curl -v \
        --proxy "${BURP_PROXY_URL}" \
        --max-time 10 \
        -H "X-Pentra-Test: burp-proxy-check" \
        "${target}" 2>&1 | head -50
    echo ""
    echo -e "  ${DIM}Cek Burp → Proxy → HTTP History untuk request di atas${RST}"
    echo ""
}

# ═══════════════════════════════════════════════════════════
# SERVICES
# ═══════════════════════════════════════════════════════════

run_migrations() {
    info "Running DB migrations..."
    cd "$REPO_ROOT/apps/api"
    uv run alembic upgrade head 2>&1 | grep -E "Running|up to date|done|ERROR" | tail -5
    ok "DB migrations current"
}

start_api() {
    fuser -k "${API_PORT}/tcp" 2>/dev/null || true
    sleep 0.5
    info "Starting API server → :${API_PORT}"
    cd "$REPO_ROOT/apps/api"
    echo "═══ API started $(date '+%Y-%m-%d %H:%M:%S') ═══" >> "$LOG_DIR/api.log"
    nohup uv run uvicorn app.main:app \
        --host 0.0.0.0 --port "$API_PORT" --log-level info \
        >>"$LOG_DIR/api.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$LOG_DIR/api.pid"
    local i=0
    while true; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            "http://localhost:${API_PORT}/api/v1/auth/me" 2>/dev/null)
        [[ "$code" =~ ^[234] ]] && break
        sleep 1; i=$((i+1))
        if [[ $i -ge 20 ]]; then
            err "API tidak start dalam 20s — lihat: ./start.sh logs:api"
            tail -20 "$LOG_DIR/api.log"; return 1
        fi
    done
    ok "API server  http://localhost:${API_PORT}  (PID $pid)"
}

start_worker() {
    pkill -f "celery.*app\.worker" 2>/dev/null || true
    sleep 0.5
    info "Starting Celery worker..."
    cd "$REPO_ROOT/apps/worker"
    echo "═══ Worker started $(date '+%Y-%m-%d %H:%M:%S') ═══" >> "$LOG_DIR/worker.log"
    nohup uv run celery -A app.worker.celery_app worker \
        --loglevel=info -Q default,knowledge --concurrency=2 \
        >>"$LOG_DIR/worker.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$LOG_DIR/worker.pid"
    sleep 2
    if ps -p "$pid" >/dev/null 2>&1; then
        ok "Celery worker  PID $pid"
    else
        err "Worker gagal start — lihat: ./start.sh logs:worker"
        tail -20 "$LOG_DIR/worker.log"; return 1
    fi
}

start_beat() {
    pkill -f "celery.*beat.*app\.worker" 2>/dev/null || true
    pkill -f "celery.*app\.worker.*beat" 2>/dev/null || true
    sleep 0.3
    info "Starting Celery beat..."
    cd "$REPO_ROOT/apps/worker"
    echo "═══ Beat started $(date '+%Y-%m-%d %H:%M:%S') ═══" >> "$LOG_DIR/beat.log"
    nohup uv run celery -A app.worker.celery_app beat \
        --loglevel=info >>"$LOG_DIR/beat.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$LOG_DIR/beat.pid"
    sleep 1
    if ps -p "$pid" >/dev/null 2>&1; then
        ok "Celery beat    PID $pid"
    else
        warn "Beat gagal start (non-critical) — lihat: ./start.sh logs:worker"
    fi
}

start_web() {
    fuser -k 5173/tcp 2>/dev/null || true
    sleep 0.3
    info "Starting frontend → :5173"
    cd "$REPO_ROOT/apps/web"
    [[ -d node_modules ]] || pnpm install --frozen-lockfile
    echo "═══ Web started $(date '+%Y-%m-%d %H:%M:%S') ═══" >> "$LOG_DIR/web.log"
    nohup pnpm dev >>"$LOG_DIR/web.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$LOG_DIR/web.pid"
    sleep 3
    if ps -p "$pid" >/dev/null 2>&1; then
        ok "Frontend    http://localhost:5173  (PID $pid)"
    else
        err "Frontend gagal start — lihat: ./start.sh logs"
        tail -20 "$LOG_DIR/web.log"; return 1
    fi
}

# ═══════════════════════════════════════════════════════════
# STOP / RESTART
# ═══════════════════════════════════════════════════════════

stop_all() {
    section "Stopping Pentra AI"
    for svc in api worker beat web; do
        local pid_file="$LOG_DIR/${svc}.pid"
        if [[ -f "$pid_file" ]]; then
            local pid; pid=$(cat "$pid_file")
            kill "$pid" 2>/dev/null && ok "Stopped $svc (PID $pid)" || true
            rm -f "$pid_file"
        fi
    done
    pkill -f "uvicorn app.main:app"  2>/dev/null || true
    pkill -f "celery.*app\.worker"   2>/dev/null || true
    fuser -k 5173/tcp                2>/dev/null || true
    ok "All services stopped"
}

restart_svc() {
    local svc="${1:-all}"
    case "$svc" in
        api)    fuser -k "${API_PORT}/tcp" 2>/dev/null || true; sleep 1; start_api ;;
        worker) pkill -f "celery.*app\.worker" 2>/dev/null || true
                sleep 1; start_worker; start_beat ;;
        web)    fuser -k 5173/tcp 2>/dev/null || true; sleep 1; start_web ;;
        all)    stop_all; sleep 1; run_migrations; start_api; start_worker; start_beat; start_web ;;
        *)      err "Unknown service: $svc (api|worker|web|all)"; return 1 ;;
    esac
}

# ═══════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════

tail_logs() {
    local filter="${1:-}"
    local files=()
    for svc in api worker beat; do
        [[ -f "$LOG_DIR/${svc}.log" ]] && files+=("$LOG_DIR/${svc}.log")
    done
    if [[ ${#files[@]} -eq 0 ]]; then
        warn "Tidak ada log file di $LOG_DIR — jalankan services dulu"
        return
    fi
    section "Tailing logs  (Ctrl+C to stop)"
    echo -e "  ${DIM}${files[*]}${RST}"; echo ""
    if [[ -n "$filter" ]]; then
        info "Filter: $filter"
        tail -F "${files[@]}" | grep --line-buffered -i "$filter"
    else
        tail -F "${files[@]}"
    fi
}

_tail_one() {
    local svc="$1"
    local f="$LOG_DIR/${svc}.log"
    if [[ ! -f "$f" ]]; then
        warn "Log $f tidak ada — $svc belum pernah distart"
        return
    fi
    section "Log: $svc  (Ctrl+C to stop)"
    echo -e "  ${DIM}$f${RST}"; echo ""
    tail -F "$f"
}

tail_scan_log() {
    local latest
    latest=$(ls -t /tmp/pentra_scan_*.log 2>/dev/null | head -1 || echo "")
    if [[ -z "$latest" ]]; then
        warn "Tidak ada scan log di /tmp"
        return
    fi
    section "Scan Log: $(basename "$latest")  (Ctrl+C to stop)"
    echo -e "  ${DIM}$latest${RST}"; echo ""
    tail -F "$latest"
}

rotate_logs() {
    section "Rotating logs"
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    for svc in api worker beat web; do
        local f="$LOG_DIR/${svc}.log"
        if [[ -f "$f" && -s "$f" ]]; then
            gzip -c "$f" > "$LOG_DIR/${svc}.${ts}.log.gz"
            : > "$f"
            ok "Rotated $svc.log → ${svc}.${ts}.log.gz  ($(du -sh "$LOG_DIR/${svc}.${ts}.log.gz" | cut -f1))"
        fi
    done
    echo ""
    echo -e "  ${DIM}Archived: $LOG_DIR/${RST}"
    ls -lh "$LOG_DIR"/*.gz 2>/dev/null | awk '{print "  " $NF " (" $5 ")"}'
    echo ""
}

clear_logs() {
    section "Clearing logs"
    echo -n "  Hapus semua log di $LOG_DIR? [y/N]: "
    read -r answer
    [[ "${answer,,}" != "y" ]] && { info "Dibatalkan"; return; }
    rm -f "$LOG_DIR"/*.log "$LOG_DIR"/*.log.gz "$LOG_DIR"/*.pid
    ok "Log files cleared"
}

# ═══════════════════════════════════════════════════════════
# KNOWLEDGE BASE
# ═══════════════════════════════════════════════════════════

kb_stats() {
    section "Knowledge Base Stats"
    local token; token=$(_get_token)
    if [[ -z "$token" ]]; then
        err "Gagal auth — API running? Creds: admin / Pentra@2026!"; return 1
    fi
    local data
    data=$(curl -s "http://localhost:${API_PORT}/api/v1/admin/stats" \
        -H "Authorization: Bearer $token" 2>/dev/null)
    echo "$data" | python3 -c "
import sys, json
d = json.load(sys.stdin)
total   = d.get('total_knowledge_records', 0)
embed   = d.get('embedded_records', 0)
pending = total - embed
pct     = (embed/total*100) if total else 0
print(f'  Total records   : {total:,}')
print(f'  Embedded        : {embed:,}  ({pct:.1f}%)')
print(f'  Pending embed   : {pending:,}')
print(f'  Total users     : {d.get(\"total_users\", 0)}')
print(f'  Total findings  : {d.get(\"total_findings\", 0)}')
print(f'  Engagements     : {d.get(\"total_engagements\", 0)}')
print()
print('  By source:')
for src, cnt in sorted(d.get('records_by_source', {}).items(), key=lambda x: -x[1]):
    print(f'    {src:<30} {cnt:>5,}')
" 2>/dev/null || echo "$data"
    echo ""
}

kb_reembed() {
    section "KB Re-embed with bge-m3"
    local token; token=$(_get_token)
    if [[ -z "$token" ]]; then err "Gagal auth — API running?"; return 1; fi
    info "Reset is_embedded=False untuk semua records..."
    local result
    result=$(curl -sX POST "http://localhost:${API_PORT}/api/v1/admin/knowledge/reembed" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d '{"model":"bge-m3","batch_size":50}' 2>/dev/null)
    echo "$result" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  Reset : {d.get(\"reset_count\", 0):,} records')
print(f'  Model : {d.get(\"model\", \"?\")}')
print(f'  Status: {d.get(\"message\", str(d))}')
" 2>/dev/null || echo "$result"
    echo ""
    ok "Worker akan re-embed pada siklus berikutnya"
    echo -e "  ${DIM}Monitor: ./start.sh logs:worker${RST}"
    echo ""
}

kb_search() {
    local query="${1:-}"
    local filter_vuln="${2:-}"
    local filter_sev="${3:-}"
    if [[ -z "$query" ]]; then
        echo -n "  Search query: "; read -r query
    fi
    [[ -z "$query" ]] && { err "Query diperlukan"; return 1; }

    local token; token=$(_get_token)
    [[ -z "$token" ]] && { err "Gagal auth"; return 1; }

    section "KB Search: \"${query}\""

    local url="http://localhost:${API_PORT}/knowledge/search?q=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$query")&top_k=10"
    [[ -n "$filter_vuln" ]] && url+="&vuln_class=${filter_vuln}"
    [[ -n "$filter_sev" ]]  && url+="&severity=${filter_sev}"

    curl -s "$url" -H "Authorization: Bearer $token" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
results = d.get('results', [])
print(f'  Found: {d.get(\"total\", len(results))} results\n')
for i, r in enumerate(results, 1):
    sev  = r.get('severity','?').upper()
    vc   = r.get('vuln_class','?')
    src  = r.get('source','?')
    prog = r.get('program') or ''
    insight = (r.get('key_insight') or '')[:80].replace('\\n',' ')
    print(f'  [{i:02d}] {r[\"id\"]}')
    print(f'       Title    : {r[\"title\"][:70]}')
    print(f'       Vuln     : {vc:<25} Severity: {sev}')
    print(f'       Source   : {src}  {prog}')
    if insight and insight != '---':
        print(f'       Insight  : {insight}')
    url_val = r.get('source_url') or ''
    if url_val:
        print(f'       URL      : {url_val[:80]}')
    print()
" 2>/dev/null || { err "Parse error"; curl -s "$url" -H "Authorization: Bearer $token"; }
    echo -e "  ${DIM}Filter: ./start.sh kb:search \"query\" [vuln_class] [severity]${RST}"
    echo -e "  ${DIM}Detail: ./start.sh kb:view <record-id>${RST}"
    echo ""
}

kb_view() {
    local id="${1:-}"
    if [[ -z "$id" ]]; then
        echo -n "  Record ID (UUID): "; read -r id
    fi
    [[ -z "$id" ]] && { err "ID diperlukan"; return 1; }

    local token; token=$(_get_token)
    [[ -z "$token" ]] && { err "Gagal auth"; return 1; }

    section "KB Record: ${id}"
    curl -s "http://localhost:${API_PORT}/knowledge/${id}" \
        -H "Authorization: Bearer $token" 2>/dev/null | python3 -c "
import sys, json
r = json.load(sys.stdin)
if 'detail' in r:
    print(f'  Error: {r[\"detail\"]}')
    sys.exit(1)
print(f'  ID          : {r[\"id\"]}')
print(f'  Title       : {r[\"title\"]}')
print(f'  Vuln Class  : {r[\"vuln_class\"]}')
print(f'  Severity    : {r.get(\"severity\",\"?\").upper()}')
print(f'  Source      : {r.get(\"source\",\"?\")}  {r.get(\"program\") or \"\"}')
print(f'  Embedded    : {r.get(\"is_embedded\", False)}')
if r.get('source_url'):
    print(f'  URL         : {r[\"source_url\"]}')
if r.get('tech_stack'):
    print(f'  Tech Stack  : {\" | \".join(r[\"tech_stack\"])}')
print()
if r.get('key_insight') and r['key_insight'] != '---':
    print('  Key Insight :')
    for line in r['key_insight'].splitlines():
        print(f'    {line}')
    print()
if r.get('technique') and r['technique'] != '---':
    print('  Technique   :')
    for line in r['technique'].splitlines():
        print(f'    {line}')
    print()
if r.get('raw_text'):
    snippet = r['raw_text'][:500].replace('\\n', '\\n  ')
    print(f'  Raw Text (preview):')
    print(f'  {snippet}')
    if len(r['raw_text']) > 500:
        print(f'  ... ({len(r[\"raw_text\"]):,} chars total)')
    print()
" 2>/dev/null || echo "Parse error"
}

kb_list() {
    local filter_vuln="${1:-}"
    local filter_sev="${2:-}"

    local token; token=$(_get_token)
    [[ -z "$token" ]] && { err "Gagal auth"; return 1; }

    section "KB Records Overview"

    # Use search with broad query to get recent records
    local q="vulnerability technique"
    local q_enc; q_enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "vulnerability technique")
    local url="http://localhost:${API_PORT}/knowledge/search?q=${q_enc}&top_k=20"
    [[ -n "$filter_vuln" ]] && url+="&vuln_class=${filter_vuln}"
    [[ -n "$filter_sev" ]]  && url+="&severity=${filter_sev}"

    # Show stats first
    local stats
    stats=$(curl -s "http://localhost:${API_PORT}/api/v1/admin/stats" \
        -H "Authorization: Bearer $token" 2>/dev/null)
    echo "$stats" | python3 -c "
import sys, json
d = json.load(sys.stdin)
total = d.get('total_knowledge_records', 0)
embed = d.get('embedded_records', 0)
print(f'  Total: {total:,} records  |  Embedded: {embed:,}  ({embed/total*100:.0f}%)' if total else '  No records')
print()
print('  Vuln Class Distribution:')
for vc, cnt in sorted(d.get('records_by_vuln_class', {}).items(), key=lambda x: -x[1])[:15]:
    bar = '█' * min(int(cnt/10), 30)
    print(f'    {vc:<35} {cnt:>5,}  {bar}')
" 2>/dev/null

    echo ""
    if [[ -n "$filter_vuln" || -n "$filter_sev" ]]; then
        info "Sample records (vuln=${filter_vuln:-any}, sev=${filter_sev:-any}):"
        curl -s "$url" -H "Authorization: Bearer $token" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
for r in d.get('results', [])[:10]:
    sev = r.get('severity','?').upper()
    print(f'  {r[\"id\"]}  [{sev:<8}] [{r.get(\"vuln_class\",\"?\")}]  {r[\"title\"][:60]}')
" 2>/dev/null
        echo ""
        echo -e "  ${DIM}Detail: ./start.sh kb:view <id>${RST}"
    fi
    echo -e "  ${DIM}Search: ./start.sh kb:search \"query\" [vuln_class] [severity]${RST}"
    echo ""
}

kb_add() {
    section "KB Add — Manual Inject"
    local token; token=$(_get_token)
    [[ -z "$token" ]] && { err "Gagal auth"; return 1; }

    echo -e "  ${DIM}Isi detail knowledge record baru:${RST}"
    echo ""
    echo -n "  Title (required): "; read -r kb_title
    [[ -z "$kb_title" ]] && { err "Title diperlukan"; return 1; }

    echo -n "  Vuln class (e.g. xss_reflected, idor, rce, sqli, lfi): "; read -r kb_vuln
    [[ -z "$kb_vuln" ]] && kb_vuln="info"

    echo -n "  Severity [critical/high/medium/low/info] (default: medium): "; read -r kb_sev
    [[ -z "$kb_sev" ]] && kb_sev="medium"

    echo -n "  Source label (default: manual): "; read -r kb_source
    [[ -z "$kb_source" ]] && kb_source="manual"

    echo -n "  Tech stack (space-separated, e.g. 'php laravel mysql', optional): "; read -r kb_tech_raw
    local kb_tech="[]"
    if [[ -n "$kb_tech_raw" ]]; then
        kb_tech=$(python3 -c "import json,sys; print(json.dumps(sys.argv[1].split()))" "$kb_tech_raw")
    fi

    echo -n "  Key insight (1 line summary, optional): "; read -r kb_insight
    echo -n "  Technique (attack steps, optional): "; read -r kb_technique
    echo ""
    echo -e "  ${YLW}Raw text / full write-up (paste, then enter a single '.' on a new line to finish):${RST}"
    local kb_raw_lines=() line
    while IFS= read -r line; do
        [[ "$line" == "." ]] && break
        kb_raw_lines+=("$line")
    done
    local kb_raw
    kb_raw=$(printf '%s\n' "${kb_raw_lines[@]}")
    [[ -z "$kb_raw" ]] && kb_raw="$kb_title"

    echo ""
    info "Injecting..."
    local payload
    payload=$(python3 -c "
import json, sys
print(json.dumps({
    'title': sys.argv[1],
    'vuln_class': sys.argv[2],
    'severity': sys.argv[3],
    'source': sys.argv[4],
    'raw_text': sys.argv[5],
    'key_insight': sys.argv[6],
    'technique': sys.argv[7],
    'tech_stack': json.loads(sys.argv[8]),
    'tags': ['manual_inject'],
}))" "$kb_title" "$kb_vuln" "$kb_sev" "$kb_source" "$kb_raw" "${kb_insight:-}" "${kb_technique:-}" "$kb_tech")

    local result
    result=$(curl -s -X POST "http://localhost:${API_PORT}/knowledge/inject" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null)

    echo "$result" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'detail' in d:
    print(f'  Error: {d[\"detail\"]}')
    sys.exit(1)
print(f'  ID     : {d.get(\"record_id\", d.get(\"id\", \"?\"))}')
print(f'  Status : {d.get(\"status\", \"?\")}')
print(f'  Message: {d.get(\"message\", str(d))}')
" 2>/dev/null || echo "$result"
    echo ""
    ok "Record injected — worker akan embed pada siklus berikutnya"
    echo -e "  ${DIM}Monitor: ./start.sh logs:worker${RST}"
    echo ""
}

kb_add_url() {
    local url_arg="${1:-}"
    section "KB Add from URL"
    local token; token=$(_get_token)
    [[ -z "$token" ]] && { err "Gagal auth"; return 1; }

    local target_url="$url_arg"
    if [[ -z "$target_url" ]]; then
        echo -n "  URL (blog post / write-up / CVE advisory): "; read -r target_url
    fi
    [[ -z "$target_url" ]] && { err "URL diperlukan"; return 1; }

    echo -n "  Vuln class (optional, e.g. xss_reflected, idor): "; read -r kb_vuln
    echo -n "  Tags (space-separated, optional): "; read -r kb_tags_raw
    local kb_tags="[]"
    if [[ -n "$kb_tags_raw" ]]; then
        kb_tags=$(python3 -c "import json,sys; print(json.dumps(sys.argv[1].split()))" "$kb_tags_raw")
    fi

    echo ""
    info "Fetching & injecting: $target_url"

    local payload
    payload=$(python3 -c "
import json, sys
d = {'url': sys.argv[1], 'tags': json.loads(sys.argv[3])}
if sys.argv[2]: d['vuln_class'] = sys.argv[2]
print(json.dumps(d))" "$target_url" "${kb_vuln:-}" "$kb_tags")

    local result
    result=$(curl -s -X POST "http://localhost:${API_PORT}/knowledge/inject/url" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null)

    echo "$result" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'detail' in d:
    print(f'  Error: {d[\"detail\"]}')
    sys.exit(1)
print(f'  ID     : {d.get(\"record_id\", d.get(\"id\", \"?\"))}')
print(f'  Status : {d.get(\"status\", \"?\")}')
print(f'  Message: {d.get(\"message\", str(d))}')
" 2>/dev/null || echo "$result"
    echo ""
    ok "URL diproses — worker akan embed pada siklus berikutnya"
    echo -e "  ${DIM}Monitor: ./start.sh logs:worker${RST}"
    echo ""
}

kb_add_file() {
    local file_arg="${1:-}"
    section "KB Add from File"
    local token; token=$(_get_token)
    [[ -z "$token" ]] && { err "Gagal auth"; return 1; }

    local fpath="$file_arg"
    if [[ -z "$fpath" ]]; then
        echo -n "  Path file Markdown / TXT: "; read -r fpath
    fi
    [[ -z "$fpath" ]] && { err "Path file diperlukan"; return 1; }
    [[ ! -f "$fpath" ]] && { err "File tidak ditemukan: $fpath"; return 1; }

    local fname; fname=$(basename "$fpath")
    echo -n "  Vuln class (optional): "; read -r kb_vuln
    echo -n "  Tags (space-separated, optional): "; read -r kb_tags_raw

    echo ""
    info "Uploading: $fpath ($(wc -c < "$fpath") bytes)"

    local curl_extra=()
    [[ -n "$kb_vuln" ]]    && curl_extra+=(-F "vuln_class=${kb_vuln}")
    [[ -n "$kb_tags_raw" ]] && for tag in $kb_tags_raw; do curl_extra+=(-F "tags=${tag}"); done

    local result
    result=$(curl -s -X POST "http://localhost:${API_PORT}/knowledge/inject/file" \
        -H "Authorization: Bearer $token" \
        -F "file=@${fpath};type=text/plain" \
        "${curl_extra[@]}" 2>/dev/null)

    echo "$result" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'detail' in d:
    print(f'  Error: {d[\"detail\"]}')
    sys.exit(1)
print(f'  ID     : {d.get(\"record_id\", d.get(\"id\", \"?\"))}')
print(f'  Status : {d.get(\"status\", \"?\")}')
print(f'  Message: {d.get(\"message\", str(d))}')
" 2>/dev/null || echo "$result"
    echo ""
    ok "File diproses — worker akan embed pada siklus berikutnya"
    echo ""
}

# ═══════════════════════════════════════════════════════════
# SCAN
# ═══════════════════════════════════════════════════════════

run_scan() {
    local domain="${1:-}"
    local burp_forced="${2:-false}"

    if [[ -z "$domain" ]]; then
        echo -n "  Target domain (contoh: testaspnet.vulnweb.com): "
        read -r domain
    fi
    [[ -z "$domain" ]] && { err "Domain diperlukan"; exit 1; }

    local log_file="/tmp/pentra_scan_${domain//./_}_$(date +%s).log"
    section "Live Scan  →  $domain"

    local burp_status=""
    if [[ "$burp_forced" == "true" ]]; then
        if ! _check_burp_silent 2>/dev/null; then
            err "Burp tidak tersambung. Jalankan burp:check atau scan biasa."
            echo -e "  ${DIM}./start.sh burp:setup${RST}"; return 1
        fi
        burp_status="ENABLED (forced)"
    elif _check_burp_silent 2>/dev/null; then
        burp_status="ENABLED (auto-detected)"
    else
        burp_status="DISABLED (passive mode)"
    fi

    echo -e "  Domain : ${CYN}${domain}${RST}"
    echo -e "  Burp   : ${YLW}${burp_status}${RST}"
    echo -e "  Log    : ${DIM}${log_file}${RST}"
    echo -e "  Model  : ${DIM}$(grep OLLAMA_MODEL_DEFAULT "$REPO_ROOT/apps/api/.env" 2>/dev/null | cut -d= -f2 || echo 'qwen2.5:32b')${RST}"
    echo ""

    cd "$REPO_ROOT/apps/api"
    uv run python "$REPO_ROOT/scripts/live_scan.py" --domain "$domain" 2>&1 | tee "$log_file"

    echo ""
    ok "Scan selesai  |  Log: $log_file"
    echo -e "  ${DIM}Tail: ./start.sh logs:scan${RST}"
    echo ""
}

# ═══════════════════════════════════════════════════════════
# STATUS
# ═══════════════════════════════════════════════════════════

show_status() {
    section "Pentra AI Status"
    echo ""
    echo -e "  ${WHT}Infrastructure${RST}"

    for item in "PostgreSQL:5432" "Redis:6379" "Qdrant:6333"; do
        local name="${item%:*}" port="${item#*:}"
        if _port_up "$port"; then echo -e "    ${GRN}●${RST} ${name} :${port}"
        else echo -e "    ${RED}●${RST} ${name} :${port}  (down)"; fi
    done

    if _http_up "http://localhost:11434/api/tags"; then
        local models
        models=$(curl -sf "http://localhost:11434/api/tags" 2>/dev/null | \
            python3 -c "import sys,json; print(', '.join(m['name'] for m in json.load(sys.stdin).get('models',[])))" 2>/dev/null)
        echo -e "    ${GRN}●${RST} Ollama :11434  ${DIM}[${models}]${RST}"
    else
        echo -e "    ${YLW}●${RST} Ollama  (not reachable)"
    fi

    echo ""
    echo -e "  ${WHT}Services${RST}"

    local api_code
    api_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://localhost:${API_PORT}/api/v1/auth/me" 2>/dev/null)
    if [[ "$api_code" =~ ^[234] ]]; then
        local apid=""
        [[ -f "$LOG_DIR/api.pid" ]] && apid="  PID $(cat "$LOG_DIR/api.pid")"
        echo -e "    ${GRN}●${RST} API     http://localhost:${API_PORT}${DIM}${apid}${RST}"
    else echo -e "    ${RED}●${RST} API     (not running)"; fi

    # Worker: look for the actual celery worker process (not uv wrapper)
    local w_pid; w_pid=$(pgrep -f "python.*celery.*app\.worker.*worker" | head -1)
    if [[ -n "$w_pid" ]]; then
        echo -e "    ${GRN}●${RST} Worker  PID ${w_pid}"
    else echo -e "    ${RED}●${RST} Worker  (not running)  ${DIM}./start.sh worker${RST}"; fi

    local b_pid; b_pid=$(pgrep -f "python.*celery.*beat" | head -1)
    if [[ -n "$b_pid" ]]; then
        echo -e "    ${GRN}●${RST} Beat    PID ${b_pid}"
    else echo -e "    ${YLW}●${RST} Beat    (not running)"; fi

    if fuser 5173/tcp >/dev/null 2>&1; then
        echo -e "    ${GRN}●${RST} Web     http://localhost:5173"
    else echo -e "    ${YLW}●${RST} Web     (not running)"; fi

    echo ""
    echo -e "  ${WHT}Burp Suite${RST}"

    if [[ -n "$(curl -s --max-time 2 "${BURP_MCP_URL}/" 2>/dev/null)" ]]; then
        echo -e "    ${GRN}●${RST} MCP    ${BURP_MCP_URL}"
    else
        echo -e "    ${YLW}●${RST} MCP    (not connected)  ${DIM}./start.sh burp:setup${RST}"
    fi

    local proxy_code
    proxy_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --proxy "${BURP_PROXY_URL}" --max-time 3 \
        "http://testaspnet.vulnweb.com/" 2>/dev/null || echo "000")
    if [[ "$proxy_code" =~ ^[123456] ]] && [[ "$proxy_code" != "000" ]]; then
        echo -e "    ${GRN}●${RST} Proxy  ${BURP_PROXY_URL}"
    else
        echo -e "    ${YLW}●${RST} Proxy  (not connected)  ${DIM}port ${BURP_PROXY_PORT} di Burp${RST}"
    fi

    echo ""
    echo -e "  ${WHT}Log Files${RST}  ${DIM}(${LOG_DIR}/)${RST}"
    for svc in api worker beat web; do
        local f="$LOG_DIR/${svc}.log"
        if [[ -f "$f" && -s "$f" ]]; then
            local size last
            size=$(du -sh "$f" 2>/dev/null | cut -f1)
            last=$(tail -1 "$f" 2>/dev/null | cut -c1-55)
            echo -e "    ${DIM}${svc}.log${RST}  ${size}  ${DIM}← ${last}${RST}"
        fi
    done

    local scan_count
    scan_count=$(ls /tmp/pentra_scan_*.log 2>/dev/null | wc -l || echo 0)
    [[ "$scan_count" -gt 0 ]] && \
        echo -e "    ${DIM}scan logs: ${scan_count} di /tmp  (./start.sh logs:scan)${RST}"
    echo ""
}

# ═══════════════════════════════════════════════════════════
# SUMMARY AFTER START
# ═══════════════════════════════════════════════════════════

print_summary() {
    echo ""
    echo -e "${GRN}╔══════════════════════════════════════════════════╗${RST}"
    echo -e "${GRN}║          Pentra AI  —  Ready                     ║${RST}"
    echo -e "${GRN}╚══════════════════════════════════════════════════╝${RST}"
    echo ""
    echo -e "  ${WHT}Akses${RST}"
    echo -e "    Web UI   ${CYN}http://localhost:5173${RST}"
    echo -e "    API      ${CYN}http://localhost:${API_PORT}${RST}"
    echo -e "    API Docs ${CYN}http://localhost:${API_PORT}/docs${RST}"
    echo -e "    Login    ${YLW}admin / Pentra@2026!${RST}"
    echo ""
    echo -e "  ${WHT}Burp Suite${RST}"
    echo -e "    ${CYN}./start.sh burp:setup${RST}   panduan setup interaktif"
    echo -e "    ${CYN}./start.sh burp:check${RST}   cek koneksi MCP + Proxy"
    echo -e "    ${CYN}./start.sh burp:test${RST}    kirim request uji via Proxy"
    echo ""
    echo -e "  ${WHT}Scan${RST}"
    echo -e "    ${CYN}./start.sh scan testaspnet.vulnweb.com${RST}"
    echo -e "    ${CYN}./start.sh scan:burp testaspnet.vulnweb.com${RST}  (force Burp)"
    echo ""
    echo -e "  ${WHT}Logs${RST}"
    echo -e "    ${CYN}./start.sh logs${RST}           semua service"
    echo -e "    ${CYN}./start.sh logs ERROR${RST}     filter keyword"
    echo -e "    ${CYN}./start.sh logs:api${RST}        API only"
    echo -e "    ${CYN}./start.sh logs:worker${RST}     Worker only"
    echo -e "    ${CYN}./start.sh logs:scan${RST}       scan terakhir"
    echo -e "    ${CYN}./start.sh logs:rotate${RST}     gzip + rotate"
    echo ""
    echo -e "  ${WHT}Control${RST}"
    echo -e "    ${CYN}./start.sh status${RST}          full status"
    echo -e "    ${CYN}./start.sh restart api${RST}     restart service"
    echo -e "    ${CYN}./start.sh stop${RST}            stop semua"
    echo ""
    echo -e "  ${WHT}Knowledge Base${RST}"
    echo -e "    ${CYN}./start.sh kb:stats${RST}        stats KB"
    echo -e "    ${CYN}./start.sh kb:list${RST}         distribusi vuln class"
    echo -e "    ${CYN}./start.sh kb:search \"XSS\"${RST}  cari records"
    echo -e "    ${CYN}./start.sh kb:view <id>${RST}    lihat detail record"
    echo -e "    ${CYN}./start.sh kb:add${RST}          tambah knowledge (interaktif)"
    echo -e "    ${CYN}./start.sh kb:add:url <url>${RST} tambah dari URL write-up"
    echo -e "    ${CYN}./start.sh kb:add:file <f>${RST} tambah dari file .md/.txt"
    echo -e "    ${CYN}./start.sh kb:reembed${RST}      re-embed dengan bge-m3"
    echo ""
}

# ═══════════════════════════════════════════════════════════
# MAIN DISPATCH
# ═══════════════════════════════════════════════════════════

CMD="${1:-all}"
shift || true

case "$CMD" in
    all|start)
        section "Starting Pentra AI"
        start_infra
        check_infra
        run_migrations
        start_api
        start_worker
        start_beat
        start_web
        print_summary
        ;;
    api)      start_infra; run_migrations; start_api ;;
    worker)   start_infra; start_worker; start_beat ;;
    web)      start_web ;;
    infra)    start_infra ;;
    scan)       run_scan "${1:-}" "false" ;;
    scan:burp)  run_scan "${1:-}" "true" ;;
    burp:check)  check_burp ;;
    burp:setup)  setup_burp ;;
    burp:test)   test_burp_proxy "${1:-}" ;;
    logs)          tail_logs "${1:-}" ;;
    logs:api)      _tail_one api ;;
    logs:worker)   _tail_one worker ;;
    logs:beat)     _tail_one beat ;;
    logs:scan)     tail_scan_log ;;
    logs:rotate)   rotate_logs ;;
    logs:clear)    clear_logs ;;
    status)         show_status ;;
    stop)           stop_all ;;
    restart)        restart_svc "${1:-all}" ;;
    kb:stats)      kb_stats ;;
    kb:list)       kb_list "${1:-}" "${2:-}" ;;
    kb:search)     kb_search "${1:-}" "${2:-}" "${3:-}" ;;
    kb:view)       kb_view "${1:-}" ;;
    kb:add)        kb_add ;;
    kb:add:url)    kb_add_url "${1:-}" ;;
    kb:add:file)   kb_add_file "${1:-}" ;;
    kb:reembed)    kb_reembed ;;
    help|-h|--help)
        cat << 'HELP'

  Pentra AI — start.sh

  SERVICES
    ./start.sh [all]          Start semua (api + worker + web)
    ./start.sh api            Start API + migrations
    ./start.sh worker         Start Celery worker + beat
    ./start.sh web            Start frontend :5173
    ./start.sh infra          Start Docker infra
    ./start.sh stop           Stop semua service
    ./start.sh restart [svc]  Restart (api|worker|web|all)
    ./start.sh status         Full status

  SCAN
    ./start.sh scan [domain]       Live scan
    ./start.sh scan:burp [domain]  Scan dengan Burp forced

  BURP SUITE
    ./start.sh burp:check    Cek koneksi MCP + Proxy
    ./start.sh burp:setup    Panduan setup interaktif (WSL2 tips included)
    ./start.sh burp:test     Kirim request uji via Proxy

  LOGS
    ./start.sh logs              Tail semua service logs
    ./start.sh logs [keyword]    Tail dengan grep filter
    ./start.sh logs:api          API only
    ./start.sh logs:worker       Worker only
    ./start.sh logs:scan         Scan log terakhir
    ./start.sh logs:rotate       Gzip + rotate semua log
    ./start.sh logs:clear        Hapus semua log

  KNOWLEDGE BASE
    ./start.sh kb:stats                    KB statistics + distribusi source
    ./start.sh kb:list [vuln] [sev]        Distribusi vuln class + sample records
    ./start.sh kb:search "query" [vc] [s]  Cari records (max 10 hasil)
    ./start.sh kb:view <id>                Detail satu record (full text)
    ./start.sh kb:add                      Tambah record manual (interaktif)
    ./start.sh kb:add:url <url>            Inject dari URL blog/write-up
    ./start.sh kb:add:file <file.md>       Inject dari file Markdown/TXT
    ./start.sh kb:reembed                  Reset + re-embed semua (bge-m3)

  ENV OVERRIDES
    API_PORT=8001           Port API server
    BURP_MCP_URL=...        URL Burp MCP Server
    BURP_PROXY_URL=...      URL Burp HTTP Proxy

HELP
        ;;
    *)
        err "Unknown command: $CMD"
        echo "  Run: ./start.sh help"
        exit 1
        ;;
esac
