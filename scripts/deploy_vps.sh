#!/usr/bin/env bash
# =============================================================================
#  HashGuard — VPS Deploy Script
#  Automação para deploy inicial em uma VPS Ubuntu 22.04+ com Docker
#
#  Uso:
#    scp scripts/deploy_vps.sh user@your-vps:/tmp/
#    ssh user@your-vps 'sudo bash /tmp/deploy_vps.sh'
# =============================================================================
set -euo pipefail

# ── Config ───────────────────────────────────────────────────────────────────
DOMAIN="${DOMAIN:-hashguard.org}"
APP_DIR="/opt/hashguard"
REPO_URL="https://github.com/albertotijunelis/hashguard.git"
BRANCH="main"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${CYAN}[HashGuard]${NC} $1"; }
ok()   { echo -e "${GREEN}[✔]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║  HashGuard — VPS Production Deploy               ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Check root ────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    fail "Run as root: sudo bash $0"
fi

# ── 2. System updates + deps ────────────────────────────────────────────────
log "Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq curl git ufw fail2ban unzip awscli
ok "System updated"

# ── 3. Install Docker ───────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    ok "Docker installed"
else
    ok "Docker already installed"
fi

if ! command -v docker compose version &>/dev/null 2>&1; then
    log "Installing Docker Compose plugin..."
    apt-get install -y -qq docker-compose-plugin
    ok "Docker Compose installed"
else
    ok "Docker Compose already installed"
fi

# ── 4. Firewall (UFW) ───────────────────────────────────────────────────────
log "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable
ok "Firewall configured (SSH + HTTP + HTTPS)"

# ── 5. Fail2Ban ─────────────────────────────────────────────────────────────
log "Configuring Fail2Ban..."
systemctl enable fail2ban
systemctl start fail2ban
ok "Fail2Ban active"

# ── 6. Clone repo ───────────────────────────────────────────────────────────
if [ -d "$APP_DIR" ]; then
    log "Updating existing installation..."
    cd "$APP_DIR"
    git pull origin "$BRANCH"
    ok "Repository updated"
else
    log "Cloning HashGuard..."
    git clone -b "$BRANCH" "$REPO_URL" "$APP_DIR"
    cd "$APP_DIR"
    ok "Repository cloned to $APP_DIR"
fi

# ── 7. Generate .env if missing ─────────────────────────────────────────────
if [ ! -f "$APP_DIR/.env" ]; then
    log "Creating .env from production template..."
    cp "$APP_DIR/.env.production" "$APP_DIR/.env"

    # Auto-generate secrets
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
    PG_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || openssl rand -base64 32)

    sed -i "s|HASHGUARD_SECRET_KEY=CHANGE_ME|HASHGUARD_SECRET_KEY=${SECRET_KEY}|" "$APP_DIR/.env"
    sed -i "s|POSTGRES_PASSWORD=CHANGE_ME|POSTGRES_PASSWORD=${PG_PASSWORD}|" "$APP_DIR/.env"

    warn ".env created with auto-generated secrets."
    warn "You MUST edit $APP_DIR/.env to fill in:"
    warn "  - S3 credentials (HG_S3_ACCESS_KEY, HG_S3_SECRET_KEY)"
    warn "  - Stripe keys (when ready)"
    warn "  - Email SMTP password"
    echo ""
    ok ".env generated"
else
    ok ".env already exists — skipping"
fi

# ── 8. Create data directories ──────────────────────────────────────────────
mkdir -p "$APP_DIR/data/certbot/conf"
mkdir -p "$APP_DIR/data/certbot/www"
mkdir -p "$APP_DIR/data/nginx/logs"

# ── 9. Set "Em Breve" mode ──────────────────────────────────────────────────
if ! grep -q "HASHGUARD_COMING_SOON" "$APP_DIR/.env"; then
    echo "" >> "$APP_DIR/.env"
    echo "# Coming soon landing page (set to 0 when ready to launch)" >> "$APP_DIR/.env"
    echo "HASHGUARD_COMING_SOON=1" >> "$APP_DIR/.env"
    ok "Coming soon mode enabled"
fi

# ── 10. Build and Start ─────────────────────────────────────────────────────
log "Building and starting HashGuard..."
cd "$APP_DIR"
docker compose -f docker-compose.production.yml build
docker compose -f docker-compose.production.yml up -d
ok "Stack started"

# ── 11. Wait for health ─────────────────────────────────────────────────────
log "Waiting for API health check..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:8000/api/health >/dev/null 2>&1; then
        ok "API is healthy!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        warn "API not responding after 30s — check logs: docker compose -f docker-compose.production.yml logs api"
    fi
    sleep 2
done

# ── 12. SSL Certificate ─────────────────────────────────────────────────────
echo ""
log "SSL Certificate Setup"
echo -e "Run the following to get your SSL certificate:"
echo ""
echo -e "  ${CYAN}cd $APP_DIR${NC}"
echo -e "  ${CYAN}docker compose -f docker-compose.production.yml run --rm certbot \\${NC}"
echo -e "  ${CYAN}  certonly --webroot -w /var/www/certbot -d ${DOMAIN} -d www.${DOMAIN}${NC}"
echo ""
echo -e "Then restart nginx:"
echo -e "  ${CYAN}docker compose -f docker-compose.production.yml restart nginx${NC}"
echo ""

# ── 13. Setup auto-renewal cron ──────────────────────────────────────────────
CRON_CMD="0 3 * * 1 cd $APP_DIR && docker compose -f docker-compose.production.yml run --rm certbot renew && docker compose -f docker-compose.production.yml exec nginx nginx -s reload"
if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    (crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -
    ok "SSL auto-renewal cron added (weekly Monday 3am)"
fi

# ── 14. Setup daily backup cron ──────────────────────────────────────────────
BACKUP_CMD="0 2 * * * cd $APP_DIR && docker compose -f docker-compose.production.yml run --rm backup"
if ! crontab -l 2>/dev/null | grep -q "backup"; then
    (crontab -l 2>/dev/null; echo "$BACKUP_CMD") | crontab -
    ok "Daily backup cron added (2am)"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Deploy Complete!                                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  App dir:     ${APP_DIR}"
echo -e "  Landing:     http://${DOMAIN} (Em Breve page)"
echo -e "  API:         http://localhost:8000/api/health"
echo ""
echo -e "${YELLOW}Próximos passos:${NC}"
echo -e "  1. Editar ${APP_DIR}/.env com credenciais S3"
echo -e "  2. Obter certificado SSL (comando acima)"
echo -e "  3. Activar Stripe production (ver docs/STRIPE_PRODUCTION.md)"
echo -e "  4. Iniciar ingest: bash scripts/ingest_200k.sh"
echo -e "  5. Quando pronto: HASHGUARD_COMING_SOON=0 e restart"
echo ""
