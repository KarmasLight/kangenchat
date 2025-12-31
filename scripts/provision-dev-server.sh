#!/usr/bin/env bash
set -euo pipefail

# One-time provisioning script for the Lightsail development server.
# Run as root (or with sudo) on a fresh Ubuntu 22.04 instance.

APP_USER=${APP_USER:-kangenapp}
APP_GROUP=${APP_GROUP:-${APP_USER}}
APP_DIR=${APP_DIR:-/home/kangenapp/kangenchat}
NODE_MAJOR=${NODE_MAJOR:-20}
DB_NAME=${DB_NAME:-kangenchat_dev}
DB_USER=${DB_USER:-kangenapp}
DB_PASSWORD=${DB_PASSWORD:-change-me-now}
APP_PORT=${APP_PORT:-5010}
FRONTEND_PORT=${FRONTEND_PORT:-3000}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root (sudo)." >&2
    exit 1
  fi
}

apt_install() {
  echo "[*] Updating apt repositories..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
  echo "[*] Installing base packages..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git curl build-essential ca-certificates gnupg lsb-release \
    nginx ufw fail2ban postgresql postgresql-contrib \
    software-properties-common certbot python3-certbot-nginx
}

install_node() {
  if command -v node >/dev/null 2>&1; then
    echo "[+] Node already installed: $(node -v)"
    return
  fi
  echo "[*] Installing Node.js ${NODE_MAJOR}.x via NodeSource..."
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
  npm install -g pm2
}

create_app_user() {
  if id -u "$APP_USER" >/dev/null 2>&1; then
    echo "[+] User $APP_USER already exists"
  else
    echo "[*] Creating system user $APP_USER"
    useradd --system --create-home --shell /bin/bash "$APP_USER"
  fi
  mkdir -p "$APP_DIR"
  chown -R "$APP_USER":"$APP_GROUP" "$APP_DIR"
  chmod 755 "$APP_DIR"
}

configure_firewall() {
  echo "[*] Configuring UFW..."
  ufw allow OpenSSH
  ufw allow 80
  ufw allow 443
  ufw allow "Nginx Full" || true
  ufw --force enable
}

configure_fail2ban() {
  systemctl enable --now fail2ban
}

setup_postgres() {
  echo "[*] Configuring PostgreSQL..."
  sudo -u postgres psql <<SQL
DO
\$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_USER}') THEN
      CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}';
   END IF;
END
\$\$;

CREATE DATABASE ${DB_NAME}
  OWNER ${DB_USER}
  TEMPLATE template0
  ENCODING 'UTF8'
  LC_COLLATE 'en_US.utf8'
  LC_CTYPE 'en_US.utf8'
ON CONFLICT DO NOTHING;
SQL
}

create_env_placeholder() {
  ENV_FILE="$APP_DIR/.env"
  if [[ -f "$ENV_FILE" ]]; then
    echo "[+] .env already exists at $ENV_FILE"
    return
  fi
  cat <<EOF > "$ENV_FILE"
PORT=${APP_PORT}
FRONTEND_URL=http://23.22.209.53
NEXT_PUBLIC_BACKEND_URL=http://23.22.209.53
JWT_SECRET=replace-with-random
FORCE_LOGOUT_SECRET=replace-with-random
DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@127.0.0.1:5432/${DB_NAME}?schema=public"
DEFAULT_ADMIN_EMAIL=admin@kangen.dev
DEFAULT_ADMIN_PASSWORD=ChangeMe123!
DEFAULT_ADMIN_NAME="Dev Admin"
EOF
  chown "$APP_USER":"$APP_GROUP" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "[+] Wrote placeholder env file to $ENV_FILE"
}

install_nginx_unit() {
  cat <<EOF > /etc/nginx/sites-available/kangenchat.conf
map $http_upgrade $connection_upgrade {
  default upgrade;
  ''      close;
}
server {
  listen 80;
  server_name 23.22.209.53;

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
  }

  location /socket.io/ {
    proxy_pass http://127.0.0.1:${APP_PORT}/socket.io/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
  }

  location /api/ {
    proxy_pass http://127.0.0.1:${APP_PORT}/api/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
EOF

EOF

  ln -sf /etc/nginx/sites-available/kangenchat.conf /etc/nginx/sites-enabled/kangenchat.conf
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl restart nginx
}

main() {
  require_root
  apt_install
  install_node
  create_app_user
  configure_firewall
  configure_fail2ban
  setup_postgres
  create_env_placeholder
  install_nginx_unit

  echo "[*] Base provisioning complete. Next steps:"
  echo "    1. Copy application code into ${APP_DIR} (owned by ${APP_USER})."
  echo "    2. Replace secrets in ${APP_DIR}/.env and keep chmod 600."
  echo "    3. Run 'sudo -u ${APP_USER} npm install && pm2 start ...' for frontend/back-end."
  echo "    4. Use certbot to issue TLS certs once DNS points to this server."
}

main "$@"
