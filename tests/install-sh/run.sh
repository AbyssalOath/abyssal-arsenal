#!/bin/bash
# Runs the real install.sh end to end, once per scenario, against fake
# `docker`, `sudo` and `uname` and a fake agent -- so CI catches what only
# breaks when a line actually runs (`bash -n` and shellcheck can't: the
# v0.2.2 `${var:-...'...}` bad substitution only failed at the end of a real
# install). Nothing is installed and nothing touches Docker.
#
#   tests/install-sh/run.sh           every scenario
#   tests/install-sh/run.sh caddy_ip  just the ones whose name matches
#
# Each scenario runs in its own scratch directory with its answers on stdin.
# The fake docker logs every call and fails on any it doesn't know, so a new
# `docker` command in install.sh needs a case here (and a thought about how
# it fails).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FILTER="${1:-}"
PASSED=0
FAILED=0

# --- Fakes ---------------------------------------------------------------
BIN="$WORK/bin"
mkdir -p "$BIN"

cat > "$BIN/docker" <<'EOF'
#!/bin/bash
echo "docker $*" >> "$FAKE_LOG"
case "$*" in
"compose version")
        [ "${FAKE_NO_COMPOSE:-}" = 1 ] && exit 1
        echo "Docker Compose version v2.29.0" ;;
"compose up -d --build" | "compose restart caddy") ;;
"compose exec -T app /app/abyssal-arsenal tls status")
        printf 'Internal CA: 10.0.0.5\n  SHA-256 AB:CD:EF\n' ;;
"compose exec -T app /app/abyssal-arsenal aat show")
        echo "AAT1-test-install-token" ;;
"compose exec -T app /app/abyssal-arsenal control-plane enrollment-token")
        echo "cp-enroll-token-123" ;;
"compose exec -T app /app/abyssal-arsenal control-plane ca-bundle")
        if [ "${FAKE_CA:-}" = 1 ]; then
                printf -- '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n'
        fi ;;
"compose cp app:/app/agent-bundle/abyssal-agent-linux.tar.gz "*)
        [ "${FAKE_CP_FAIL:-}" = 1 ] && exit 1
        cp "$FAKE_TARBALL" "${*: -1}" ;;
*)
        echo "UNEXPECTED docker $*" >> "$FAKE_LOG"
        echo "fake docker: unexpected call: docker $*" >&2
        exit 97 ;;
esac
EOF

# install.sh uses sudo only to run the agent's installer.
cat > "$BIN/sudo" <<'EOF'
#!/bin/bash
echo "sudo $*" >> "$FAKE_LOG"
exec "$@"
EOF

# The bundled agent is x86_64 Linux; pin that so the scenarios run the same
# on any machine.
cat > "$BIN/uname" <<'EOF'
#!/bin/bash
case "${1:-}" in
-s) echo Linux ;;
-m) echo x86_64 ;;
*) command -p uname "$@" ;;
esac
EOF
chmod +x "$BIN/docker" "$BIN/sudo" "$BIN/uname"

# The agent bundle: an "abyssal-agent" that records how it was invoked,
# the token it was handed and whether the CA file was there.
STAGE="$WORK/bundle/abyssal-agent-v0.0.0-x86_64-unknown-linux-gnu"
mkdir -p "$STAGE"
cat > "$STAGE/abyssal-agent" <<'EOF'
#!/bin/bash
echo "agent $*" >> "$FAKE_LOG"
prev=""
for arg in "$@"; do
        case "$prev" in
        --enrollment-token-file) echo "agent-token $(cat "$arg")" >> "$FAKE_LOG" ;;
        --ca-cert) grep -q "BEGIN CERTIFICATE" "$arg" && echo "agent-ca present" >> "$FAKE_LOG" ;;
        esac
        prev="$arg"
done
exit "${FAKE_AGENT_EXIT:-0}"
EOF
chmod +x "$STAGE/abyssal-agent"
FAKE_TARBALL="$WORK/agent.tar.gz"
tar -czf "$FAKE_TARBALL" -C "$WORK/bundle" .
export FAKE_TARBALL

# --- Harness --------------------------------------------------------------
# run_install <dir> <stdin> [install.sh args...]: runs install.sh in <dir>
# with the fakes, recording output, exit code and the fake call log.
run_install() {
        local dir="$1" answers="$2"
        shift 2
        mkdir -p "$dir"
        cp "$ROOT/install.sh" "$dir/install.sh"
        : > "$dir/calls.log"
        set +e
        (
                cd "$dir" &&
                        printf '%b' "$answers" |
                        env PATH="$BIN:$PATH" FAKE_LOG="$dir/calls.log" \
                                ABYSSAL_AGENT_CREDENTIALS="$dir/agent-credentials.json" \
                                bash ./install.sh "$@"
        ) > "$dir/out.log" 2>&1
        echo $? > "$dir/exit"
        set -e
}

CURRENT=""
ERRORS=()
fail() { ERRORS+=("$1"); }

expect_exit() {
        local got
        got="$(cat "$CURRENT/exit")"
        [ "$got" = "$1" ] || fail "exit code $got, expected $1"
}
expect_out() { grep -qF -- "$1" "$CURRENT/out.log" || fail "output lacks: $1"; }
reject_out() { ! grep -qF -- "$1" "$CURRENT/out.log" || fail "output has: $1"; }
expect_call() { grep -qF -- "$1" "$CURRENT/calls.log" || fail "no call: $1"; }
reject_call() { ! grep -qF -- "$1" "$CURRENT/calls.log" || fail "unexpected call: $1"; }
expect_env() {
        grep -qxF -- "$1" "$CURRENT/.env" || fail ".env lacks the line: $1"
}
reject_env() { ! grep -q -- "^$1" "$CURRENT/.env" || fail ".env has: $1"; }
expect_file_has() { grep -qF -- "$2" "$CURRENT/$1" || fail "$1 lacks: $2"; }

# The AAT summary, both commands in full. Asserting the content, not just
# "no error", is what catches a broken `${...}`: depending on the bash
# version that's an error or a silently swallowed line.
expect_aat_summary() {
        expect_out "Windows (exe):  abyssal-agent.exe /install /quiet /norestart SERVER=$1 AAT=AAT1-test-install-token"
        expect_out "Windows (MSI):  msiexec /i AbyssalAgent.msi /qn /norestart SERVER=$1 AAT=AAT1-test-install-token"
}

# What every completed run must (not) show.
expect_clean_finish() {
        expect_exit 0
        expect_out "Installation complete."
        for bad in "bad substitution" "command not found" "unbound variable" \
                "syntax error" "unexpected call" "No such file"; do
                reject_out "$bad"
        done
        reject_call "UNEXPECTED"
}

scenario() {
        local name="$1"
        shift
        if [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]]; then
                return
        fi
        CURRENT="$WORK/$name"
        ERRORS=()
        "$@"
        if [ "${#ERRORS[@]}" -eq 0 ]; then
                echo "ok   $name"
                PASSED=$((PASSED + 1))
        else
                echo "FAIL $name"
                printf '       %s\n' "${ERRORS[@]}"
                echo "     --- install.sh output ($CURRENT/out.log):"
                sed 's/^/     | /' "$CURRENT/out.log" | tail -n 40
                FAILED=$((FAILED + 1))
                KEEP=1
        fi
}

# --- Scenarios ------------------------------------------------------------
# Prompt order on a fresh install: MariaDB port, app port, proxy choice
# (+ its follow-ups), SMTP host (+ follow-ups), syslog host (+ follow-ups).
# The self-agent question is only asked on a terminal; piped, it's "yes".

fresh_local() {
        FAKE_CA=0 run_install "$CURRENT" '33306\n18080\n3\n\n\n'
        expect_clean_finish
        expect_env "DB_PORT=33306"
        expect_env "HTTP_PORT=18080"
        expect_env "COMPOSE_PROFILES="
        expect_env "COOKIE_SECURE=false"
        expect_env "PUBLIC_URL=http://localhost:18080"
        expect_env "SMTP_HOST="
        expect_env "SYSLOG_HOST="
        expect_env "CONTROL_PLANE_AGENT=yes"
        grep -q '^ENCRYPTION_KEY=.\{40,\}' "$CURRENT/.env" || fail "no ENCRYPTION_KEY"
        grep -q '^MARIADB_PASSWORD=[0-9a-f]\{48\}$' "$CURRENT/.env" || fail "no MariaDB password"
        [ "$(stat -c %a "$CURRENT/.env")" = 600 ] || fail ".env isn't mode 600"
        expect_call "docker compose up -d --build"
        reject_call "docker compose restart caddy"
        expect_out "http://localhost:18080"
        expect_aat_summary "http://localhost:18080"
        expect_call "agent install --non-interactive --control-plane-url http://localhost:18080 --enrollment-token-file"
        expect_call "agent-token cp-enroll-token-123"
        reject_call "--ca-cert"
        expect_out "This server is now a managed host"
}

fresh_caddy_internal_ip() {
        # Address list, then SMTP on 465 with a password Compose would mangle
        # unquoted, then a syslog host.
        FAKE_CA=1 run_install "$CURRENT" \
                '\n\n2\n\n10.0.0.5, arsenal.corp.local\nsmtp.example.com\n465\n\nmailer\npa$$ '"'"'w"#rd\nalerts@example.com\nsiem.example.com\n\n'
        expect_clean_finish
        expect_env "INTERNAL_TLS_ADDRESSES=10.0.0.5, arsenal.corp.local"
        expect_env "COMPOSE_PROFILES=caddy"
        expect_env "COOKIE_SECURE=true"
        expect_env "APP_HTTP_BIND=127.0.0.1"
        expect_env "PUBLIC_URL=https://10.0.0.5"
        expect_env "SMTP_HOST=smtp.example.com"
        expect_env "SMTP_PORT=465"
        expect_env "SMTP_TLS=tls"
        expect_env 'SMTP_PASSWORD="pa$$$$ '"'"'w\"#rd"'
        expect_env "SYSLOG_HOST=siem.example.com"
        expect_env "SYSLOG_PORT=514"
        expect_file_has Caddyfile "admin unix//run/caddy-admin/admin.sock"
        expect_file_has Caddyfile "tls /etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem"
        expect_call "docker compose restart caddy"
        expect_out "SHA-256 AB:CD:EF"
        expect_aat_summary "https://10.0.0.5"
        expect_call "agent-ca present"
        expect_call "--control-plane-url https://10.0.0.5"
}

fresh_caddy_domain_no_agent() {
        # SMTP with a password that has no single quote (the other quoting
        # branch), STARTTLS by default on 587.
        run_install "$CURRENT" \
                '\n\n2\narsenal.example.com\nsmtp.office365.com\n\n\nme@corp.com\np@ss$word#1\nme@corp.com\n\n' \
                --no-agent
        expect_clean_finish
        expect_aat_summary "https://arsenal.example.com"
        expect_env "SMTP_PORT=587"
        expect_env "SMTP_TLS=starttls"
        expect_env "SMTP_PASSWORD='p@ss\$word#1'"
        expect_env "COMPOSE_PROFILES=caddy"
        expect_env "PUBLIC_URL=https://arsenal.example.com"
        reject_env "INTERNAL_TLS_ADDRESSES"
        reject_env "CONTROL_PLANE_AGENT"
        expect_file_has Caddyfile "arsenal.example.com {"
        expect_out "Not installing an agent on this server"
        reject_call "agent install"
        reject_call "enrollment-token"
}

fresh_own_proxy_agent_unavailable() {
        FAKE_CP_FAIL=1 run_install "$CURRENT" '\n\n1\nhttps://arsenal.corp\n\n\n'
        expect_clean_finish
        expect_env "COMPOSE_PROFILES="
        expect_env "COOKIE_SECURE=true"
        expect_env "PUBLIC_URL=https://arsenal.corp"
        expect_out "Couldn't get the agent from the app container -- skipped."
        reject_call "agent install"
}

agent_install_fails() {
        FAKE_AGENT_EXIT=3 run_install "$CURRENT" '\n\n3\n\n\n'
        # The agent failing must not fail the install.
        expect_clean_finish
        expect_out "The agent on this server didn't install"
}

rerun_skips_every_prompt() {
        run_install "$CURRENT" '33306\n18080\n3\n\n\n'
        cp "$CURRENT/.env" "$CURRENT/env.first"
        : > "$CURRENT/agent-credentials.json" # "already enrolled"
        run_install "$CURRENT" '' # no answers: any prompt would read EOF
        expect_clean_finish
        expect_out ".env already exists"
        expect_out "Host port already recorded in .env (18080)"
        expect_out "Reverse proxy choice already recorded"
        expect_out "SMTP settings already recorded"
        expect_out "Syslog settings already recorded"
        expect_out "This server already has an enrolled agent"
        # The summary uses the recorded URL, not a placeholder.
        expect_aat_summary "http://localhost:18080"
        reject_out "<server URL>"
        cmp -s "$CURRENT/.env" "$CURRENT/env.first" || fail ".env changed on a re-run"
        reject_call "agent install"
}

rerun_respects_a_recorded_no() {
        mkdir -p "$CURRENT"
        printf 'HTTP_PORT=8080\nCOMPOSE_PROFILES=\nPUBLIC_URL=http://localhost:8080\nSMTP_HOST=\nSYSLOG_HOST=\nCONTROL_PLANE_AGENT=no\n' > "$CURRENT/.env"
        run_install "$CURRENT" ''
        expect_clean_finish
        expect_out "Not installing an agent on this server (CONTROL_PLANE_AGENT=no in .env)."
        reject_call "agent install"
}

legacy_internal_tls_upgrade() {
        # An install from before the managed CA: a Caddyfile serving the old
        # self-signed certificate, no admin socket, no INTERNAL_TLS_ADDRESSES.
        mkdir -p "$CURRENT"
        printf 'HTTP_PORT=8080\nCOMPOSE_PROFILES=caddy\nPUBLIC_URL=https://10.1.2.3\nSMTP_HOST=\nSYSLOG_HOST=\nCONTROL_PLANE_AGENT=no\n' > "$CURRENT/.env"
        printf ':443 {\n    tls /etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem\n    reverse_proxy app:8080\n}\n' > "$CURRENT/Caddyfile"
        run_install "$CURRENT" ''
        expect_clean_finish
        expect_env "INTERNAL_TLS_ADDRESSES=10.1.2.3"
        expect_out "Upgrading internal TLS to the managed private CA (address: 10.1.2.3)"
        expect_file_has Caddyfile "admin unix//run/caddy-admin/admin.sock"
        expect_call "docker compose restart caddy"
}

env_var_opt_out() {
        ABYSSAL_SELF_AGENT=no run_install "$CURRENT" '\n\n3\n\n\n'
        expect_clean_finish
        expect_out "Not installing an agent on this server"
        reject_call "agent install"
}

options() {
        run_install "$CURRENT/help" '' --help
        CURRENT="$CURRENT/help"
        expect_exit 0
        expect_out "Usage: ./install.sh [--no-agent]"
        CURRENT="${CURRENT%/help}"
        run_install "$CURRENT/bad" '' --frobnicate
        CURRENT="$CURRENT/bad"
        expect_exit 1
        expect_out "Unknown option: --frobnicate"
        CURRENT="${CURRENT%/bad}"
}

missing_compose_plugin() {
        FAKE_NO_COMPOSE=1 run_install "$CURRENT" ''
        expect_exit 1
        expect_out "Docker Compose plugin is not available"
        [ ! -e "$CURRENT/.env" ] || fail "wrote .env before checking prerequisites"
}

scenario fresh_local fresh_local
scenario fresh_caddy_internal_ip fresh_caddy_internal_ip
scenario fresh_caddy_domain_no_agent fresh_caddy_domain_no_agent
scenario fresh_own_proxy_agent_unavailable fresh_own_proxy_agent_unavailable
scenario agent_install_fails agent_install_fails
scenario rerun_skips_every_prompt rerun_skips_every_prompt
scenario rerun_respects_a_recorded_no rerun_respects_a_recorded_no
scenario legacy_internal_tls_upgrade legacy_internal_tls_upgrade
scenario env_var_opt_out env_var_opt_out
scenario options options
scenario missing_compose_plugin missing_compose_plugin

echo
echo "$PASSED passed, $FAILED failed"
if [ "${KEEP:-0}" = 1 ]; then
        # Keep the scratch directories of failures for a look.
        trap - EXIT
        echo "(scratch kept in $WORK)"
fi
[ "$FAILED" -eq 0 ]
