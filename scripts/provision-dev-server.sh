#!/usr/bin/env bash
set -euo pipefail

# One-time provisioning script for the Lightsail development server.
# Run as root (or with sudo) on a fresh Ubuntu 22.04 instance.

APP_USER=${APP_USER:-ubuntu}
APP_GROUP=${APP_GROUP:-${APP_USER}}
APP_DIR=${APP_DIR:-/home/ubuntu/kangenchat}
NODE_MAJOR=${NODE_MAJOR:-20}
DB_NAME=${DB_NAME:-kangenchat_dev}
DB_USER=${DB_USER:-kangenapp}
DB_PASSWORD=${DB_PASSWORD:-kangendev!0621}
APP_PORT=${APP_PORT:-5010}
FRONTEND_PORT=${FRONTEND_PORT:-3000}
SERVER_NAME=${SERVER_NAME:-23.22.209.53}
APP_REPO=${APP_REPO:-}
APP_REPO_BRANCH=${APP_REPO_BRANCH:-main}
RUN_APP_BUILD=${RUN_APP_BUILD:-true}
ENABLE_PM2=${ENABLE_PM2:-true}
FRONTEND_PM2_NAME=${FRONTEND_PM2_NAME:-kangenchat-frontend}
BACKEND_PM2_NAME=${BACKEND_PM2_NAME:-kangenchat-backend}
CERTBOT_DOMAIN=${CERTBOT_DOMAIN:-}
CERTBOT_EXTRA_DOMAINS=${CERTBOT_EXTRA_DOMAINS:-}
LETSENCRYPT_EMAIL=${LETSENCRYPT_EMAIL:-admin@kangen.dev}
USE_SELF_SIGNED_TLS=${USE_SELF_SIGNED_TLS:-false}
SELF_SIGNED_CN=${SELF_SIGNED_CN:-kangenchat.local}
SELF_SIGNED_CERT_PATH=${SELF_SIGNED_CERT_PATH:-/etc/ssl/kangenchat-selfsigned.crt}
SELF_SIGNED_KEY_PATH=${SELF_SIGNED_KEY_PATH:-/etc/ssl/private/kangenchat-selfsigned.key}

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
    git curl build-essential ca-certificates gnupg lsb-release openssl \
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
  cat > /etc/systemd/system/pm2.service <<EOF
[Unit]
Description=PM2 process manager
Documentation=https://pm2.keymetrics.io/
After=network.target

[Service]
User=${APP_USER}
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
Environment=PATH=/usr/local/lib/node_modules/pm2/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PM2_HOME=/home/${APP_USER}/.pm2
ExecStart=/usr/lib/node_modules/pm2/bin/pm2 resurrect
ExecReload=/usr/lib/node_modules/pm2/bin/pm2 reload all
ExecStop=/usr/lib/node_modules/pm2/bin/pm2 kill

[Install]
WantedBy=multi-user.target
EOF
  systemctl enable pm2
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
  if ! sudo -u postgres psql -tAqc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1; then
    sudo -u postgres psql -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}'"
  else
    echo "[+] Role ${DB_USER} already exists"
  fi

  if ! sudo -u postgres psql -tAqc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
    sudo -u postgres createdb "${DB_NAME}" \
      --owner="${DB_USER}" \
      --template=template0 \
      --encoding='UTF8' \
      --lc-collate='en_US.utf8' \
      --lc-ctype='en_US.utf8'
  else
    echo "[+] Database ${DB_NAME} already exists"
  fi
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
  local nginx_conf="/etc/nginx/sites-available/kangenchat.conf"
  cat <<EOF > "$nginx_conf"
map \$http_upgrade \$connection_upgrade {
  default upgrade;
  ''      close;
}
EOF

  if [[ "${USE_SELF_SIGNED_TLS}" == "true" ]]; then
    cat <<EOF >> "$nginx_conf"
server {
  listen 80;
  server_name ${SERVER_NAME};
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl;
  server_name ${SERVER_NAME};

  ssl_certificate ${SELF_SIGNED_CERT_PATH};
  ssl_certificate_key ${SELF_SIGNED_KEY_PATH};
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
  }

  location /socket.io/ {
    proxy_pass http://127.0.0.1:${APP_PORT}/socket.io/;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
  }

  location /api/ {
    proxy_pass http://127.0.0.1:${APP_PORT}/api/;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
  }
}
EOF
  else
    cat <<EOF >> "$nginx_conf"
server {
  listen 80;
  server_name ${SERVER_NAME};

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
  }

  location /socket.io/ {
    proxy_pass http://127.0.0.1:${APP_PORT}/socket.io/;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
  }

  location /api/ {
    proxy_pass http://127.0.0.1:${APP_PORT}/api/;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
  }
}
EOF
  fi

  ln -sf /etc/nginx/sites-available/kangenchat.conf /etc/nginx/sites-enabled/kangenchat.conf
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl restart nginx
}

generate_self_signed_cert() {
  if [[ "${USE_SELF_SIGNED_TLS}" != "true" ]]; then
    return
  fi

  if [[ -f "${SELF_SIGNED_CERT_PATH}" && -f "${SELF_SIGNED_KEY_PATH}" ]]; then
    echo "[+] Self-signed cert already exists at ${SELF_SIGNED_CERT_PATH}"
    return
  fi

  echo "[*] Generating self-signed TLS certificate for CN=${SELF_SIGNED_CN}..."
  mkdir -p "$(dirname "${SELF_SIGNED_CERT_PATH}")"
  mkdir -p "$(dirname "${SELF_SIGNED_KEY_PATH}")"

  openssl req -x509 -nodes -days 365 \
    -subj "/CN=${SELF_SIGNED_CN}" \
    -newkey rsa:4096 \
    -keyout "${SELF_SIGNED_KEY_PATH}" \
    -out "${SELF_SIGNED_CERT_PATH}"

  chmod 600 "${SELF_SIGNED_KEY_PATH}"
  chmod 644 "${SELF_SIGNED_CERT_PATH}"
}

sync_application_code() {
  if [[ -z "${APP_REPO}" ]]; then
    echo "[*] APP_REPO not set; skipping automatic code sync."
    return
  fi

  if [[ -d "$APP_DIR/.git" ]]; then
    echo "[*] Updating existing repository in $APP_DIR..."
    sudo -u "$APP_USER" git -C "$APP_DIR" fetch --all --tags
    sudo -u "$APP_USER" git -C "$APP_DIR" checkout "${APP_REPO_BRANCH}"
    sudo -u "$APP_USER" git -C "$APP_DIR" pull --ff-only origin "${APP_REPO_BRANCH}"
  else
    if [[ -d "$APP_DIR" && -n "$(ls -A "$APP_DIR" 2>/dev/null || true)" ]]; then
      echo "[!] $APP_DIR is not empty and not a git repo; skipping clone."
      return
    fi
    echo "[*] Cloning ${APP_REPO} into ${APP_DIR}..."
    sudo -u "$APP_USER" git clone "$APP_REPO" "$APP_DIR"
    sudo -u "$APP_USER" git -C "$APP_DIR" checkout "${APP_REPO_BRANCH}"
  fi

  chown -R "$APP_USER":"$APP_GROUP" "$APP_DIR"
}

install_app_dependencies() {
  if [[ ! -f "$APP_DIR/package.json" ]]; then
    echo "[!] package.json not found in $APP_DIR; skipping npm install."
    return
  fi
  echo "[*] Installing npm dependencies..."
  sudo -u "$APP_USER" bash -c "cd \"$APP_DIR\" && npm install"

  if [[ "${RUN_APP_BUILD}" == "true" ]]; then
    echo "[*] Running npm run build (set RUN_APP_BUILD=false to skip)..."
    if ! sudo -u "$APP_USER" bash -c "cd \"$APP_DIR\" && npm run build"; then
      echo "[!] npm run build failed—check logs before continuing."
    fi
  else
    echo "[*] RUN_APP_BUILD=false, skipping build."
  fi
}

setup_pm2_services() {
  if [[ "${ENABLE_PM2}" != "true" ]]; then
    echo "[*] ENABLE_PM2=false, skipping PM2 process setup."
    return
  fi
  if [[ ! -f "$APP_DIR/package.json" ]]; then
    echo "[!] package.json not found; PM2 setup skipped."
    return
  fi

  local app_home
  app_home=$(getent passwd "$APP_USER" | cut -d: -f6)

  echo "[*] Configuring PM2 services..."
  sudo -u "$APP_USER" bash -c "pm2 delete ${FRONTEND_PM2_NAME} >/dev/null 2>&1 || true"
  sudo -u "$APP_USER" bash -c "pm2 delete ${BACKEND_PM2_NAME} >/dev/null 2>&1 || true"

  sudo -u "$APP_USER" bash -c "cd \"$APP_DIR\" && pm2 start npm --name ${FRONTEND_PM2_NAME} -- start"
  sudo -u "$APP_USER" bash -c "cd \"$APP_DIR\" && pm2 start npm --name ${BACKEND_PM2_NAME} -- run dev:server"

  pm2 startup systemd -u "$APP_USER" --hp "$app_home" >/dev/null
  sudo -u "$APP_USER" pm2 save
}

obtain_tls_certificate() {
  if [[ -z "${CERTBOT_DOMAIN}" ]]; then
    echo "[*] CERTBOT_DOMAIN not set; skipping automatic TLS issuance."
    return
  fi

  local domains=(-d "${CERTBOT_DOMAIN}")
  if [[ -n "${CERTBOT_EXTRA_DOMAINS}" ]]; then
    for d in ${CERTBOT_EXTRA_DOMAINS}; do
      domains+=(-d "$d")
    done
  fi

  echo "[*] Requesting Let's Encrypt certificate for ${CERTBOT_DOMAIN}..."
  if ! certbot --nginx --non-interactive --agree-tos -m "${LETSENCRYPT_EMAIL}" "${domains[@]}"; then
    echo "[!] Certbot failed. Verify DNS and rerun manually if needed."
  fi
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
  generate_self_signed_cert
  install_nginx_unit
  sync_application_code
  install_app_dependencies
  setup_pm2_services
  obtain_tls_certificate

  echo "[*] Provisioning complete."
  if [[ -z "${APP_REPO}" ]]; then
    echo "    - APP_REPO not set, so code sync was skipped. Copy code manually if needed."
  fi
  if [[ -z "${CERTBOT_DOMAIN}" ]]; then
    echo "    - CERTBOT_DOMAIN not set, so TLS issuance was skipped."
  fi
}

main "$@"
