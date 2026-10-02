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

# --- Internal TLS helpers ---
# The "Caddy, no public domain" path: the app creates a private CA and the
# server certificate Caddy serves (crates/web/src/internal_tls.rs) the first
# time it starts, from INTERNAL_TLS_ADDRESSES, and renews/rotates them from
# then on -- see /admin/health/tls. This script only records the address(es)
# and writes the Caddyfile.
write_internal_caddyfile() {
        cat > Caddyfile << 'EOF'
# Written by install.sh for the internal (no public domain) setup.
{
    # Admin API on a Unix socket shared only with the app container, which
    # uses it to make Caddy load a renewed certificate. Never on a network.
    admin unix//run/caddy-admin/admin.sock|0666
}

# Plain HTTP (port 80) redirects to HTTPS so visiting http://<host> lands on
# the working TLS site instead of a dead port. {host} keeps whatever
# IP/hostname the browser used.
:80 {
    redir https://{host}{uri}
}

# Server certificate issued by the app's private CA, served for every
# connection on :443 -- no SNI/IP guesswork, which is what Caddy's automatic
# 'tls internal' can't do for a bare IP. Clients trust the CA (served at
# /ca.crt), never this certificate. Managed at /admin/health/tls.
:443 {
    tls /etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem
    reverse_proxy app:8080
}
EOF
}
internal_tls_new=0

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
                echo "PUBLIC_URL=${public_base_url}" >> .env
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
                        caddy_public_url="https://${domain}"
                else
                        # Internal / IP-only: no public DNS, so Let's Encrypt
                        # isn't an option and Caddy's internal CA can't reliably
                        # serve a bare IP over TLS (browsers send no SNI for an
                        # IP, so Caddy has no name to pick a cert for and aborts
                        # the handshake). Instead the app runs a private CA and
                        # issues a server certificate for the exact address(es)
                        # the browser will use; Caddy serves that for every
                        # connection on :443 regardless of SNI.
                        default_access_host="$(hostname -I 2>/dev/null | awk '{print $1}')"
                        echo ""
                        echo "No public domain, so this will use a private certificate authority (CA)."
                        echo "Enter the IP address and/or internal hostname(s) you'll reach this server"
                        echo "at, comma-separated (e.g. '10.0.0.5, arsenal.corp.local'). They go onto the"
                        echo "certificate so the URL matches; you can change them later from the web UI"
                        echo "(/admin/health/tls)."
                        read -rp "Address(es) [default: ${default_access_host:-<none detected>}]: " access_hosts
                        access_hosts="${access_hosts:-$default_access_host}"
                        if [ -z "$access_hosts" ]; then
                                echo "No address given and none could be detected; defaulting to 'localhost'."
                                access_hosts="localhost"
                        fi
                        access_host="$(printf '%s' "$access_hosts" | tr ',' ' ' | awk '{print $1}')"

                        write_internal_caddyfile
                        echo "INTERNAL_TLS_ADDRESSES=${access_hosts}" >> .env
                        internal_tls_new=1

                        echo "Caddyfile written for internal access at https://${access_host}"
                        public_base_url="https://${access_host}"
                        caddy_public_url="https://${access_host}"
                fi

                echo "COMPOSE_PROFILES=caddy" >> .env
                echo "COOKIE_SECURE=true" >> .env
                echo "PUBLIC_URL=${caddy_public_url}" >> .env
                # Behind Caddy the app must NOT be reachable over plain HTTP from
                # the network: Caddy talks to it over the internal Docker network,
                # and COOKIE_SECURE is on, so a browser hitting the app's own
                # http://<ip>:${http_port} directly would have its Secure session
                # cookie dropped and loop the login. Bind that port to localhost
                # only; all real traffic goes through Caddy's HTTPS on 443.
                echo "APP_HTTP_BIND=127.0.0.1" >> .env
        else
                echo "COMPOSE_PROFILES=" >> .env
                echo "COOKIE_SECURE=true" >> .env
                echo ""
                read -rp "Public HTTPS URL your existing reverse proxy serves Abyssal Arsenal at (e.g. https://arsenal.example.com): " public_base_url
                echo "PUBLIC_URL=${public_base_url}" >> .env
                echo ""
                echo "Point your existing reverse proxy's upstream at:"
                echo "  http://<this-host-ip>:${http_port}"
                echo "and make sure it terminates HTTPS on the browser-facing side (and"
                echo "passes WebSocket upgrades through for /ws/agent -- most proxies do"
                echo "this by default for HTTP/1.1 upstreams)."
        fi
fi

# --- Internal TLS on existing installs ---
# Installs from before the app managed internal TLS have either the original
# lone self-signed certificate (CA:TRUE -- agents reject it with
# CaUsedAsEndEntity) or a Caddyfile without the admin socket. Move them onto
# the managed setup: the app creates a private CA on its next start.
if [ "$internal_tls_new" = "0" ] && grep -qs '/etc/caddy/certs/cert.pem' Caddyfile; then
        if ! grep -q "^INTERNAL_TLS_ADDRESSES=" .env; then
                access_host="$(grep -E '^PUBLIC_URL=' .env | cut -d '=' -f2- | sed -E 's#^https?://##; s#[:/].*$##')"
                if [ -z "$access_host" ]; then
                        echo "ERROR: this is an internal-TLS install but .env has no PUBLIC_URL to take its"
                        echo "address from. Add INTERNAL_TLS_ADDRESSES=<ip-or-hostname> to .env and re-run."
                        exit 1
                fi
                echo ""
                echo "Upgrading internal TLS to the managed private CA (address: ${access_host})."
                echo "The original self-signed certificate is replaced: agents reject it"
                echo "(\"CaUsedAsEndEntity\"). Machines that trusted it (GPO, Import-Certificate,"
                echo "update-ca-certificates, browsers) must trust the new CA instead -- its"
                echo "fingerprint is printed below and shown at /admin/health/tls, and the agent"
                echo "commands on /admin/hosts trust it automatically. The old caddy_certs/"
                echo "directory is no longer used and can be deleted."
                echo "INTERNAL_TLS_ADDRESSES=${access_host}" >> .env
                internal_tls_new=1
        fi
        if ! grep -qs 'admin unix//run/caddy-admin/admin.sock' Caddyfile; then
                write_internal_caddyfile
                echo "Caddyfile updated so the app can reload renewed certificates in Caddy."
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

# --- Syslog / external SIEM export (optional) ---
if grep -q "^SYSLOG_HOST=" .env 2>/dev/null; then
        echo "Syslog settings already recorded in .env -- skipping prompt."
else
        echo ""
        echo "Forward logs to an external syslog/SIEM collector (RFC 5424 over"
        echo "UDP)? Leave blank to skip -- you can add this to .env and restart"
        echo "later. (Thanatos findings stream here once set; the audit-trail"
        echo "export is a separate toggle in /admin/settings.)"
        read -rp "Syslog host (blank to skip): " syslog_host

        if [ -n "$syslog_host" ]; then
                read -rp "Syslog port [default: 514]: " syslog_port
                syslog_port=${syslog_port:-514}
                cat >> .env << EOF
SYSLOG_HOST=${syslog_host}
SYSLOG_PORT=${syslog_port}
SYSLOG_APP_NAME=abyssal-arsenal
EOF
                echo "Syslog settings saved to .env."
        else
                cat >> .env << EOF
SYSLOG_HOST=
SYSLOG_PORT=514
SYSLOG_APP_NAME=abyssal-arsenal
EOF
                echo "Skipping syslog setup for now."
        fi
fi

# --- Build and start ---
echo ""
echo "Building and starting containers..."
docker compose up -d --build
# Caddy reads its Caddyfile only at startup; pick up a rewritten one.
if grep -qs 'admin unix//run/caddy-admin/admin.sock' Caddyfile; then
        docker compose restart caddy >/dev/null 2>&1 || true
fi

echo ""
echo "=== Done ==="

if grep -q "^COMPOSE_PROFILES=caddy" .env 2>/dev/null; then
        echo "Abyssal Arsenal is starting up behind Caddy. Give it a few seconds, then visit:"
        echo "  ${public_base_url:-https://<this-host-ip-or-domain>}"
        echo ""
        echo "Important: use https:// on the default port 443 -- do NOT add the"
        echo "app port (${http_port:-8080}) to the URL. Behind Caddy the app is reached"
        echo "only through Caddy's HTTPS; it is intentionally not exposed over plain"
        echo "HTTP on the network (signing in over http:// would loop the login,"
        echo "because the session cookie is HTTPS-only)."
        if grep -q "^INTERNAL_TLS_ADDRESSES=" .env 2>/dev/null; then
                echo ""
                # The app creates the CA on first start, before it's healthy.
                tls_status=""
                for _ in $(seq 1 30); do
                        tls_status="$(docker compose exec -T app /app/abyssal-arsenal tls status 2>/dev/null || true)"
                        case "$tls_status" in *SHA-256*) break ;; esac
                        tls_status=""
                        sleep 2
                done
                if [ -n "$tls_status" ]; then
                        printf '%s\n' "$tls_status"
                else
                        echo "(The internal CA's details will be at /admin/health/tls once the app is up.)"
                fi
                echo ""
                echo "Agent install commands on /admin/hosts verify the CA fingerprint"
                echo "automatically -- no certificate needs copying to the hosts. Renewal is"
                echo "automatic; rotation and address changes are done at /admin/health/tls."
                echo "Browsers warn ('unknown issuer') until the CA is trusted: download it from"
                echo "/ca.crt and import it into the trusted roots, or push it by GPO."
        fi
else
        echo "Abyssal Arsenal is starting up. Give it a few seconds, then visit:"
        echo "  ${public_base_url:-http://localhost:${http_port:-8080}}"
fi

echo ""
echo "Visit /setup to create the first administrator account -- there is no"
echo "default password to change, the account simply doesn't exist until you"
echo "create it there."
echo ""
echo "To manage a Linux or Windows host, sign in, go to /admin/hosts, generate"
echo "an enrollment token, and run the command shown there on that host."
echo "Arsenals operate on enrolled hosts, not on this container."
echo ""
echo "Installation complete."
