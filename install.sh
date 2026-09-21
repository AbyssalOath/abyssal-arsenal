#!/bin/bash
set -e # exit immediately if any command fails, rather than plowing ahead

echo "=== Abyssal Arsenal Installer ==="

# --- Check prerequisites ---
if ! command -v docker &> /dev/null; then
        echo "Docker is not installed. Install Docker first: https://docs.docker.com/engine/install/"
        exit 1
fi

if ! docker compose version &> /dev/null; then
        echo "Docker Compose plugin is not available. Install it before continuing."
        exit 1
fi

if ! command -v openssl &> /dev/null; then
        echo "openssl is required to generate secrets. Install it before continuing."
        exit 1
fi

# --- Port availability helper ---
# Needed below both for the database's host-side port (DATABASE_URL is
# generated as part of .env, so this has to run before that) and again
# further down for HTTP_PORT.
port_in_use() {
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# --- Generate .env if it doesn't exist ---
if [ -f .env ]; then
        echo ".env already exists -- skipping secret generation (existing install detected)."
else
        echo "Generating secrets..."
        MARIADB_ROOT_PASSWORD=$(openssl rand -hex 24)
        MARIADB_PASSWORD=$(openssl rand -hex 24)
        # AES-256-GCM master key for Panopticon switches' stored SNMP
        # community strings (crates/core/src/crypto.rs) -- optional at
        # runtime (only needed if a switch is ever added), but generated
        # unconditionally here so it's simply already there if one is.
        ENCRYPTION_KEY=$(openssl rand -base64 32)

        # --- Host port (database) ---
        # MariaDB is bound to 127.0.0.1 only (see docker-compose.yml) so host-side
        # tooling (scripts/migrate.sh, sqlx-cli) can reach it without exposing it to
        # the network; only the host-side port is configurable, in case 3306 is
        # already taken by another MySQL/MariaDB instance on this machine. Resolved
        # here, before .env generation, since DATABASE_URL below needs it.
        default_db_port=3306
        while port_in_use "$default_db_port"; do
                default_db_port=$((default_db_port + 1))
        done
        if [ "$default_db_port" != "3306" ]; then
                echo ""
                echo "Port 3306 already looks taken on this machine (another MySQL/MariaDB?)."
        fi
        echo ""
        read -rp "Host port to expose MariaDB on [default: ${default_db_port}]: " db_port
        db_port=${db_port:-$default_db_port}

        cat > .env << EOF
MARIADB_ROOT_PASSWORD=${MARIADB_ROOT_PASSWORD}
MARIADB_DATABASE=abyssal_arsenal
MARIADB_USER=abyssal
MARIADB_PASSWORD=${MARIADB_PASSWORD}
DB_PORT=${db_port}
DATABASE_URL=mysql://abyssal:${MARIADB_PASSWORD}@127.0.0.1:${db_port}/abyssal_arsenal
ENCRYPTION_KEY=${ENCRYPTION_KEY}
EOF

        chmod 600 .env # restrict readability to the owning user only
        echo ".env generated with strong random secrets."
fi

# --- Host port (web) ---
# The container always listens on 8080 internally; only the host-side
# mapping is configurable (docker-compose.yml's HTTP_PORT), in case
# something else on this machine already has 8080.
if grep -q "^HTTP_PORT=" .env 2>/dev/null; then
        http_port=$(grep -E '^HTTP_PORT=' .env | cut -d '=' -f2-)
        echo "Host port already recorded in .env (${http_port}) -- skipping prompt."
else
        default_port=8080
        while port_in_use "$default_port"; do
                default_port=$((default_port + 1))
        done
        if [ "$default_port" != "8080" ]; then
                echo ""
                echo "Port 8080 already looks taken on this machine."
        fi
        echo ""
        read -rp "Host port to expose Abyssal Arsenal on [default: ${default_port}]: " http_port
        http_port=${http_port:-$default_port}
        echo "HTTP_PORT=${http_port}" >> .env
fi

# --- Reverse proxy setup ---
# HTTPS is good practice generally, and matters specifically for the
# /ws/agent connection managed Linux hosts use (wss:// vs ws://) -- but
# nothing in the app itself enforces it, so local testing over plain HTTP
# is fine.
if grep -q "^COMPOSE_PROFILES=" .env 2>/dev/null; then
        echo "Reverse proxy choice already recorded in .env -- skipping prompt."
else
        echo ""
        echo "Do you already have a reverse proxy in front of this host"
        echo "(NGINX Proxy Manager, Traefik, etc.)?"
        echo "  1) Yes -- I'll point my own proxy at it"
        echo "  2) No -- set one up for me (Caddy, automatic TLS)"
        echo "  3) No -- I'm just testing locally for now, skip HTTPS"
        read -rp "Choice [1/2/3]: " proxy_choice

        if [ "$proxy_choice" = "3" ]; then
                echo "COMPOSE_PROFILES=" >> .env
                echo "COOKIE_SECURE=false" >> .env
                public_base_url="http://localhost:${http_port}"
                echo ""
                echo "Skipping HTTPS/reverse proxy. Once containers are up, the app is"
                echo "reachable directly at ${public_base_url}."
                echo "Set up a reverse proxy (or Caddy) before using this for anything"
                echo "beyond local testing -- session cookies and managed-host agent"
                echo "connections both expect TLS on a real deployment."
        elif [ "$proxy_choice" = "2" ]; then
                echo ""
                read -rp "Domain name pointing at this server (leave blank if none / using a bare IP): " domain

                if [ -n "$domain" ]; then
                        cat > Caddyfile << EOF
${domain} {
    reverse_proxy app:8080
}
EOF

                        echo "Caddyfile written for domain '${domain}' -- Caddy will obtain a real cert automatically via Let's Encrypt."
                        public_base_url="https://${domain}"
                else
                        cat > Caddyfile << EOF
:443 {
    tls internal
    reverse_proxy app:8080
}
EOF

                        echo "Caddyfile written for IP-only access -- Caddy will use a self-signed cert."
                        echo "Your browser (and any agent binaries) will need to trust or skip that cert."
                        public_base_url="https://<this-host-ip>"
                fi

                echo "COMPOSE_PROFILES=caddy" >> .env
                echo "COOKIE_SECURE=true" >> .env
        else
                echo "COMPOSE_PROFILES=" >> .env
                echo "COOKIE_SECURE=true" >> .env
                echo ""
                read -rp "Public HTTPS URL your existing reverse proxy serves Abyssal Arsenal at (e.g. https://arsenal.example.com): " public_base_url
                echo ""
                echo "Point your existing reverse proxy's upstream at:"
                echo "  http://<this-host-ip>:${http_port}"
                echo "and make sure it terminates HTTPS on the browser-facing side (and"
                echo "passes WebSocket upgrades through for /ws/agent -- most proxies do"
                echo "this by default for HTTP/1.1 upstreams)."
        fi
fi

# --- SMTP (optional) ---
if grep -q "^SMTP_HOST=" .env 2>/dev/null; then
        echo "SMTP settings already recorded in .env -- skipping prompt."
else
        echo ""
        echo "Configure SMTP now for email notifications? Leave blank to skip --"
        echo "you can add this to .env and restart later, or configure it from"
        echo "within the app once other notification providers exist."
        read -rp "SMTP host (blank to skip): " smtp_host

        if [ -n "$smtp_host" ]; then
                read -rp "SMTP port [default: 587]: " smtp_port
                smtp_port=${smtp_port:-587}
                read -rp "SMTP username: " smtp_username
                read -rsp "SMTP password (input hidden): " smtp_password
                echo ""
                read -rp "\"From\" address for outgoing mail: " smtp_from

                cat >> .env << EOF
SMTP_HOST=${smtp_host}
SMTP_PORT=${smtp_port}
SMTP_USERNAME=${smtp_username}
SMTP_PASSWORD=${smtp_password}
SMTP_FROM=${smtp_from}
EOF
                echo "SMTP settings saved to .env."
        else
                cat >> .env << EOF
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=
EOF
                echo "Skipping SMTP setup for now."
        fi
fi

# --- Build and start ---
echo ""
echo "Building and starting containers..."
docker compose up -d --build

echo ""
echo "=== Done ==="

if grep -q "^COMPOSE_PROFILES=caddy" .env 2>/dev/null; then
        echo "Abyssal Arsenal is starting up behind Caddy. Give it a few seconds, then visit:"
        echo "  https://<this-host-ip-or-domain>"
else
        echo "Abyssal Arsenal is starting up. Give it a few seconds, then visit:"
        echo "  ${public_base_url:-http://localhost:${http_port:-8080}}"
fi

echo ""
echo "Visit /setup to create the first administrator account -- there is no"
echo "default password to change, the account simply doesn't exist until you"
echo "create it there."
echo ""
echo "To manage a Linux host, sign in, go to /admin/hosts, generate an"
echo "enrollment token, and run the abyssal-agent binary on that host with it"
echo "(download it from the project's releases, or build it with"
echo "\`cargo build --release -p abyssal-agent\`). Arsenals operate on"
echo "enrolled hosts, not on this container."
echo ""
echo "Installation complete."
