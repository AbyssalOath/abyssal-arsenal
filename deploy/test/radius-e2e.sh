#!/bin/sh
# End-to-end test of Panopticon's RADIUS decisions (docs/roadmap/0.2.9.md,
# Q1): the real app against a real MariaDB, configured through its own web
# forms, then asked by a real RADIUS client (radclient, from the FreeRADIUS
# image) through the embedded server, and by curl through the FreeRADIUS
# API (/internal/radius/*) that deploy/freeradius calls. What FreeRADIUS
# itself does with the replies is deploy/freeradius/test/run.sh.
#
#   deploy/test/radius-e2e.sh            # builds the app (cargo build)
#   APP_BIN=target/release/abyssal-arsenal deploy/test/radius-e2e.sh
#   KEEP=1 deploy/test/radius-e2e.sh     # leave the database container
#
# Needs Docker and, without APP_BIN, cargo. Runs the app on the host
# (127.0.0.1 only); touches nothing outside its own container, a temp
# directory and these local ports (override with the variables):
#   APP_PORT (18480), DB_PORT (33199), RADIUS_PORT (18812, +1 accounting,
#   +2 the stand-in NAS's CoA port, +3 the SNMP trap listener).
#
# Checks: the setup, RADIUS settings, signals, NAS client and group rule
# forms (and that bad values are refused); through the embedded server, on
# the wire: VLAN, Filter-Id and Aruba-User-Role roles per NAS client, none
# for a client without a role attribute, Session-Timeout with
# Termination-Action, quarantine by security signal, reject by signal, the
# control plane exempt, a wrong secret ignored, password/EAP/MAC-mismatch
# requests rejected, accounting; through the FreeRADIUS API: the token
# gate, roles per NAS (none for an unknown one), role-only quarantine on a
# role NAS and reject elsewhere, a role-only AD group rule, signals at
# post-auth, a registered guest's timeout capped at its registration,
# remediation, and a signal that can't be read (logged, admitted); the
# decision records both front ends write (what was sent and why), the
# Decisions page, "test a login" (not recorded), each session's decision,
# and the policy engine's Simulate results across two starts; live
# re-evaluation: a posture drop mid-session re-authorizes the session through
# a stand-in NAS (fake_nas.py, a signed Disconnect-ACK), audited with why,
# while an unchanged session and the control plane are left alone, and a
# session that re-authenticated isn't re-authorized again; rogue DHCP
# servers (seen servers seeded, since the capture needs CAP_NET_RAW): the
# allowed list and its validation, rogue/allowed on the DHCP page, Allow,
# Forget, and the rogue_dhcp policy trigger matching the rogue's device
# (by the MAC it answered from); SNMP traps (send_trap.py): a link trap
# recorded and polled at once, the wrong community and a non-switch source
# dropped, a burst debounced to two polls, a Cisco MAC notification.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
app_port=${APP_PORT:-18480}
db_port=${DB_PORT:-33199}
radius_port=${RADIUS_PORT:-18812}
acct_port=$((radius_port + 1))
coa_port=$((radius_port + 2))
trap_port=$((radius_port + 3))
db=aa-radius-e2e-db
nas=aa-radius-e2e-nas
fr_image=abyssal-arsenal-freeradius:3.2.7
token=0123456789abcdef0123456789abcdef0123
secret=e2e-shared-secret
password='E2e-Test-Password-1!'
base=http://127.0.0.1:$app_port

if [ -z "${APP_BIN:-}" ]; then
  (cd "$root" && cargo build -q --bin abyssal-arsenal)
  APP_BIN=$root/target/debug/abyssal-arsenal
fi
docker build -q -t $fr_image "$root/deploy/freeradius/image" >/dev/null

tmp=$(mktemp -d)
jar=$tmp/cookies
key=$(openssl rand -base64 32)
app_pid=
# shellcheck disable=SC2317 # called through the trap
cleanup() {
  if [ -n "$app_pid" ]; then kill "$app_pid" 2>/dev/null || true; fi
  if [ -z "${KEEP:-}" ]; then docker rm -f "$db" "$nas" >/dev/null 2>&1 || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

fail=0
check() { if echo "$2" | grep -q -- "$3"; then echo "ok   $1"; else echo "FAIL $1"; echo "$2" | sed 's/^/     /'; fail=1; fi; }
check_not() { if echo "$2" | grep -q -- "$3"; then echo "FAIL $1"; echo "$2" | sed 's/^/     /'; fail=1; else echo "ok   $1"; fi; }

sql() { docker exec -i $db mariadb -uroot -ppw -N -r t; }
setting() { echo "INSERT INTO settings (\`key\`, value) VALUES ('$1', '$2') ON DUPLICATE KEY UPDATE value = VALUES(value);" | sql; }

# The app, started fresh each phase. $1: "api" sets FREERADIUS_API_TOKEN
# (FreeRADIUS answers RADIUS, so the embedded server stays off).
start_app() {
  stop_app
  : > "$tmp/app.log"
  if [ "$1" = api ]; then t=$token; else t=; fi
  (cd "$root/crates/web" && FREERADIUS_API_TOKEN=$t \
    DATABASE_URL=mysql://root:pw@127.0.0.1:$db_port/t PORT=$app_port COOKIE_SECURE=false \
    STATIC_DIR=static ENCRYPTION_KEY=$key RELIQUARY_BACKUP_DESTINATION_PATH=$tmp/backups \
    RUST_LOG=info,abyssal_web::panopticon_reevaluate=debug,abyssal_web::panopticon_snmp_traps=debug exec "$APP_BIN" >> "$tmp/app.log" 2>&1) &
  app_pid=$!
  for _ in $(seq 1 90); do
    curl -s -o /dev/null "$base/login" && return 0
    sleep 1
  done
  echo "the app didn't start:"; tail -30 "$tmp/app.log"; exit 1
}
stop_app() {
  if [ -n "$app_pid" ]; then kill "$app_pid" 2>/dev/null || true; wait "$app_pid" 2>/dev/null || true; app_pid=; fi
  # The subshell's child: wait for the port to close.
  for _ in $(seq 1 30); do curl -s -o /dev/null "$base/login" || return 0; sleep 1; done
}
# The app's log without colour codes.
app_log() { sed 's/\x1b\[[0-9;]*m//g' "$tmp/app.log"; }

# A form POST as the signed-in admin: the HTTP status (303 = saved).
csrf() { awk '$6 == "abyssal_csrf" { print $7 }' "$jar"; }
form() {
  path=$1; shift
  set -- --data-urlencode "csrf_token=$(csrf)" "$@"
  curl -s -o "$tmp/form.out" -w '%{http_code}' -b "$jar" -c "$jar" "$@" "$base$path"
}

# radclient on the host network. $1: auth|acct, $2: the secret, stdin:
# the attributes. Prints the reply (or radclient's error).
radclient() {
  port=$radius_port; [ "$1" = acct ] && port=$acct_port
  docker run --rm -i --network host $fr_image radclient -x -t 2 -r 1 "127.0.0.1:$port" "$1" "$2" 2>&1 || true
}
mab() { printf 'User-Name = "%s"\nCalling-Station-Id = "%s"\n' "$1" "$1" | radclient auth $secret; }

# The FreeRADIUS API. $1: mab|post-auth, $2: the ?src= NAS address, $3:
# the JSON body. Prints the reply.
api() { curl -s -u "freeradius:$token" -H 'Content-Type: application/json' -d "$3" "$base/internal/radius/$1?src=$2"; }
attrs() {
  # MAC [identity [AD groups]] as rlm_rest JSON.
  printf '{"User-Name":{"type":"string","value":["%s"]},"Calling-Station-Id":{"type":"string","value":["%s"]}' "${2:-$1}" "$1"
  [ -n "${3:-}" ] && printf ',"Abyssal-AD-Groups":{"type":"string","value":["%s"]}' "$3"
  printf '}'
}

# ---- Database, schema (the app migrates at startup) and seed data ------
docker rm -f $db >/dev/null 2>&1 || true
docker run -d --name $db -e MARIADB_ROOT_PASSWORD=pw -e MARIADB_DATABASE=t \
  -p "127.0.0.1:$db_port:3306" mariadb:11 >/dev/null
for _ in $(seq 1 60); do docker exec $db healthcheck.sh --connect >/dev/null 2>&1 && break; sleep 2; done
start_app plain

# Devices (MAC aa:bb:cc:00:00:NN), the managed hosts behind them, and what
# the other arsenals say about those hosts.
#   01 trusted, linked host, latest posture 40   -> posture signal
#   02 trusted, host found by address, open high Thanatos event -> reject
#   03 trusted, a critical Scourge alert from its address -> quarantine
#   04 trusted, the control plane itself, posture 10 -> never restricted
#   05 trusted, nothing against it
#   06 untrusted
#   07, 08 not in the inventory, with approved guest registrations
sql <<'EOF'
INSERT INTO hosts (id, name, credential_hash, last_seen_ip, last_seen_at, is_control_plane) VALUES
 ('b1111111-1111-1111-1111-111111111111','pc-linked','h1',NULL,NOW(),0),
 ('b2222222-2222-2222-2222-222222222222','pc-byip','h2','10.0.0.52',NOW(),0),
 ('b4444444-4444-4444-4444-444444444444','control','h4','10.0.0.54',NOW(),1);
INSERT INTO panopticon_devices (id, ip_address, mac_address, trust_state, host_id) VALUES
 ('d1111111-1111-1111-1111-111111111111','10.0.0.51','aa:bb:cc:00:00:01','trusted','b1111111-1111-1111-1111-111111111111'),
 ('d2222222-2222-2222-2222-222222222222','10.0.0.52','aa:bb:cc:00:00:02','trusted',NULL),
 ('d3333333-3333-3333-3333-333333333333','10.0.0.53','aa:bb:cc:00:00:03','trusted',NULL),
 ('d4444444-4444-4444-4444-444444444444','10.0.0.54','aa:bb:cc:00:00:04','trusted','b4444444-4444-4444-4444-444444444444'),
 ('d5555555-5555-5555-5555-555555555555','10.0.0.55','aa:bb:cc:00:00:05','trusted',NULL),
 ('d6666666-6666-6666-6666-666666666666','10.0.0.56','aa:bb:cc:00:00:06','untrusted',NULL);
INSERT INTO posture_runs (id, host_id, platform, started_by, passed, failed, not_applicable, score, created_at) VALUES
 ('e2e-p0','b1111111-1111-1111-1111-111111111111','linux','e2e',10,0,0,100,NOW() - INTERVAL 1 DAY),
 ('e2e-p1','b1111111-1111-1111-1111-111111111111','linux','e2e',4,6,0,40,NOW()),
 ('e2e-p4','b4444444-4444-4444-4444-444444444444','linux','e2e',1,9,0,10,NOW());
INSERT INTO thanatos_events (id, host_id, line_hash, source, severity, label, raw_line, status, occurred_at) VALUES
 ('e2e-e2','b2222222-2222-2222-2222-222222222222','e2e-lh2','auth','high','SSH brute force','raw','open',NOW());
INSERT INTO scourge_alerts (id, host_id, occurred_at, severity, signature, line_hash, src_ip) VALUES
 ('e2e-a3','b4444444-4444-4444-4444-444444444444',NOW(),'critical','ET MALWARE Test C2','e2e-lh3','10.0.0.53');
INSERT INTO panopticon_registrations (mac_address, name, status, requested_at, decided_at, expires_at) VALUES
 ('aa:bb:cc:00:00:07','Guest A','approved',NOW(),NOW(),UTC_TIMESTAMP() + INTERVAL 20 MINUTE),
 ('aa:bb:cc:00:00:08','Guest B','approved',NOW(),NOW(),UTC_TIMESTAMP() + INTERVAL 3 HOUR);
INSERT INTO settings (`key`, value) VALUES ('panopticon.quarantine_vlan', '999');
EOF

# ---- Configuration, through the web forms -------------------------------
echo "--- web forms"
curl -s -o /dev/null -c "$jar" "$base/setup"
check "setup creates the first admin" "$(form /setup -d intent=create -d username=admin \
  --data-urlencode email=admin@example.test --data-urlencode "password=$password" \
  --data-urlencode "password_confirm=$password")" 303

radius_settings() {
  form /arsenals/panopticon/radius/settings -d enabled=true -d "auth_port=$radius_port" \
    -d "acct_port=$acct_port" -d trusted_vlan=10 -d guest_vlan=50 -d untrusted_action=quarantine \
    -d unknown_action=accept -d role_trusted=EMPLOYEE.in -d role_quarantine=QUARANTINE.in \
    -d role_unknown=UNKNOWN.in --data-urlencode "role_guest=${GUEST_ROLE:-GUEST.in}" -d role_registration= \
    -d timeout_quarantine=10 -d timeout_unknown=30 -d timeout_guest=60 \
    -d timeout_registration=5 "$@"
}
check "RADIUS settings: a 3-minute re-authentication is refused" "$(radius_settings -d timeout_trusted=3)" 400
check "RADIUS settings: a role with a space is refused" "$(GUEST_ROLE='GUEST VLAN' radius_settings -d timeout_trusted=480)" 400
check "RADIUS settings: saved" "$(radius_settings -d timeout_trusted=480)" 303
check "... and stored" "$(echo "SELECT value FROM settings WHERE \`key\` IN ('panopticon.radius_timeout_trusted_minutes','panopticon.radius_role_trusted') ORDER BY \`key\`;" | sql | tr '\n' ' ')" '"EMPLOYEE.in" 480'

signals() {
  form /arsenals/panopticon/radius/signals -d posture_below=60 -d posture_action=quarantine \
    -d event_action=reject -d ids_min_severity=medium -d ids_action=quarantine "$@"
}
check "signals: an unknown severity is refused" "$(signals -d event_min_severity=severe)" 400
check "signals: saved" "$(signals -d event_min_severity=high)" 303

check "NAS client added (the app encrypts its secret)" "$(form /arsenals/panopticon/radius/clients \
  -d name=lab-sw -d nas_address=127.0.0.1 --data-urlencode "shared_secret=$secret" \
  -d coa_mode=disconnect -d "coa_port=$coa_port" -d role_attribute=filter_id)" 303
form /arsenals/panopticon/radius/clients -d name=plain-sw -d nas_address=10.9.9.9 \
  -d shared_secret=other-secret -d role_attribute=none >/dev/null
lab_sw=$(echo "SELECT id FROM panopticon_radius_clients WHERE name = 'lab-sw';" | sql)
check "AD group rule with a role and no VLAN added" "$(form /arsenals/panopticon/radius/group-rules \
  --data-urlencode 'group_name=CORP\Finance' -d vlan= -d role=FINANCE.in -d position=10)" 303
# A switch at 127.0.0.1 (no SNMP agent there: its polls fail, which is
# fine, they only have to happen), and the trap listener (on at the next
# start).
form /arsenals/panopticon/switches -d name=lab-core -d ip_address=127.0.0.1 -d snmp_port=1 \
  -d snmp_version=v2c -d community=e2e-community >/dev/null
check "switch added" "$(echo "SELECT name FROM panopticon_switches;" | sql)" "^lab-core$"
check "SNMP traps: a port of 0 is refused" "$(form /arsenals/panopticon/switches/traps -d enabled=true -d port=0 -d min_interval=5)" 400
check "SNMP traps turned on" "$(form /arsenals/panopticon/switches/traps -d enabled=true -d "port=$trap_port" -d min_interval=5)" 303
check "policy engine set to Simulate" "$(form /arsenals/panopticon/policy/mode -d mode=simulate \
  -d new_window_minutes=60 -d cooldown_minutes=60)" 303
check "policy rule added (posture failing: quarantine)" "$(form /arsenals/panopticon/policy/rules \
  -d name=Posture -d trigger=posture_failing -d posture_below=60 -d action=quarantine)" 303
check "policy rule added (rogue DHCP server: quarantine)" "$(form /arsenals/panopticon/policy/rules \
  -d name=RogueDHCP -d trigger=rogue_dhcp -d action=quarantine)" 303

# ---- Rogue DHCP detection (0.2.9 Q4) ------------------------------------
# The capture needs CAP_NET_RAW, which this test doesn't run the app with:
# the servers it would have seen are seeded. 10.0.0.10 is the real one; the
# untrusted device 06 (10.0.0.56) answers DHCP too, and so does 10.0.0.77.
# 10.0.0.55 is device 05's address, only ever *named* as a server in
# requests (anyone can forge that): it must never get 05 quarantined.
echo "--- rogue DHCP servers"
sql <<'EOF2'
INSERT INTO panopticon_dhcp_servers (server_ip, server_mac, replies, chosen, last_client_mac) VALUES
 ('10.0.0.10', NULL, 0, 40, 'aa:bb:cc:00:00:05'),
 ('10.0.0.56', 'aa:bb:cc:00:00:06', 3, 2, 'aa:bb:cc:00:00:01'),
 ('10.0.0.77', NULL, 1, 0, 'aa:bb:cc:00:00:02'),
 ('10.0.0.55', NULL, 0, 5, 'aa:bb:cc:00:00:03');
EOF2
dhcp_page() { curl -s -b "$jar" "$base/arsenals/panopticon/dhcp"; }
check "no allowed list: detection off" "$(dhcp_page)" "detection off"
form /arsenals/panopticon/dhcp/servers/allowed --data-urlencode "allowed_servers=10.0.0.10, dhcp.example" >/dev/null
check "an allowed list with a name in it is refused" "$(cat "$tmp/form.out")" "Not saved: &quot;dhcp.example&quot; isn&#x27;t an address\\|Not saved: \"dhcp.example\" isn't an address"
check "... and not stored" "$(echo "SELECT COUNT(*) FROM settings WHERE \`key\` = 'panopticon.dhcp_allowed_servers';" | sql)" "^0$"
form /arsenals/panopticon/dhcp/servers/allowed --data-urlencode "allowed_servers=10.0.0.10, 192.0.2.0/24" >/dev/null
out=$(dhcp_page)
check "allowed list saved: one allowed, three rogues" "$(echo "$out" | grep -c 'badge-danger">rogue')|$(echo "$out" | grep -c 'badge-success">allowed')" "^3|1$"
check "... two of them unconfirmed (no reply from their own MAC)" "$(echo "$out" | grep -c '>unconfirmed</small>')" "^2$"
form /arsenals/panopticon/dhcp/servers/action -d server_ip=10.0.0.77 -d action=allow >/dev/null
check "Allow adds a server to the list" "$(echo "SELECT value FROM settings WHERE \`key\` = 'panopticon.dhcp_allowed_servers';" | sql)" '"10.0.0.10, 192.0.2.0/24, 10.0.0.77"'
form /arsenals/panopticon/dhcp/servers/action -d server_ip=10.0.0.77 -d action=forget >/dev/null
check "Forget removes it from the table" "$(echo "SELECT COUNT(*) FROM panopticon_dhcp_servers WHERE server_ip = '10.0.0.77';" | sql)" "^0$"
# 06 has an open RADIUS session, so the policy engine would act through RADIUS.
echo "INSERT INTO panopticon_radius_sessions (id, username, mac_address, nas_ip, acct_session_id, auth_method, started_at, last_seen_at) VALUES ('5e5e5e5e-0000-0000-0000-000000000006','aabbcc000006','aa:bb:cc:00:00:06','127.0.0.1','e2e-06','mab',NOW(),NOW());" | sql

# ---- The embedded server, on the wire -----------------------------------
echo "--- embedded RADIUS server (radclient)"
start_app plain
for _ in $(seq 1 20); do app_log | grep -q "Panopticon RADIUS listener started" && break; sleep 1; done

out=$(mab aabbcc000005)
check "trusted device: Access-Accept" "$out" "Received Access-Accept"
check "... with its VLAN" "$out" 'Tunnel-Private-Group-Id:1 = "10"'
check "... its role, as Filter-Id" "$out" 'Filter-Id = "EMPLOYEE.in"'
check "... a Session-Timeout (8 h)" "$out" "Session-Timeout = 28800"
check "... that re-authenticates" "$out" "Termination-Action = RADIUS-Request"

out=$(mab aabbcc000006)
check "untrusted device: quarantine VLAN" "$out" 'Tunnel-Private-Group-Id:1 = "999"'
check "... quarantine role and timeout" "$(echo "$out" | tr '\n' ' ')" 'Filter-Id = "QUARANTINE.in".*Session-Timeout = 600'

out=$(mab aabbcc000001)
check "posture below 60: quarantined" "$out" 'Tunnel-Private-Group-Id:1 = "999"'
check "... and the log names the signal" "$(app_log)" "signal=quarantine: Cadavault posture score 40 (below 60)"
check "open high Thanatos event: Access-Reject" "$(mab aabbcc000002)" "Received Access-Reject"
check "critical Scourge alert: quarantined" "$(mab aabbcc000003)" 'Tunnel-Private-Group-Id:1 = "999"'
check "the control plane: never restricted" "$(mab aabbcc000004)" 'Tunnel-Private-Group-Id:1 = "10"'
check "unknown device: admitted with the unknown role" "$(mab aabbcc0000aa)" 'Filter-Id = "UNKNOWN.in"'

form "/arsenals/panopticon/radius/clients/$lab_sw/role-attribute" -d role_attribute=aruba_role >/dev/null
out=$(mab aabbcc000005)
check "Aruba NAS client: the role as Aruba-User-Role" "$out" 'Aruba-User-Role = "EMPLOYEE.in"'
check_not "... and no Filter-Id" "$out" "Filter-Id"
form "/arsenals/panopticon/radius/clients/$lab_sw/role-attribute" -d role_attribute=none >/dev/null
out=$(mab aabbcc000005)
check_not "NAS client without a role attribute: no role" "$out" "Filter-Id\|Aruba-User-Role"
check "... but still its VLAN" "$out" 'Tunnel-Private-Group-Id:1 = "10"'
form "/arsenals/panopticon/radius/clients/$lab_sw/role-attribute" -d role_attribute=filter_id >/dev/null

check "wrong shared secret: no answer" \
  "$(printf 'User-Name = "aabbcc000005"\nCalling-Station-Id = "aabbcc000005"\n' | radclient auth wrong-secret)" "No reply"
check "a password login: Access-Reject" \
  "$(printf 'User-Name = "aabbcc000005"\nCalling-Station-Id = "aabbcc000005"\nUser-Password = "x"\n' | radclient auth $secret)" "Received Access-Reject"
check "an EAP request: Access-Reject" \
  "$(printf 'User-Name = "laptop"\nCalling-Station-Id = "aabbcc000005"\nEAP-Message = 0x0201000a016c6170746f70\n' | radclient auth $secret)" "Received Access-Reject"
check "User-Name and Calling-Station-Id MACs disagree: Access-Reject" \
  "$(printf 'User-Name = "aabbcc000006"\nCalling-Station-Id = "aabbcc000005"\n' | radclient auth $secret)" "Received Access-Reject"
check "accounting Start: acknowledged" \
  "$(printf 'Acct-Status-Type = Start\nAcct-Session-Id = "e2e-1"\nUser-Name = "aabbcc000005"\nCalling-Station-Id = "aabbcc000005"\nNAS-IP-Address = 127.0.0.1\n' | radclient acct $secret)" "Received Accounting-Response"
check "... and recorded as a session" "$(echo "SELECT mac_address FROM panopticon_radius_sessions WHERE acct_session_id = 'e2e-1';" | sql)" "aa:bb:cc:00:00:05"
printf 'Acct-Status-Type = Start\nAcct-Session-Id = "e2e-2"\nUser-Name = "aabbcc000001"\nCalling-Station-Id = "aabbcc000001"\nNAS-IP-Address = 127.0.0.1\n' | radclient acct $secret >/dev/null

echo "--- decision records (0.2.9 Q2)"
sleep 1 # records are written in the background
latest() { echo "SELECT CONCAT_WS(' | ', front_end, admission, outcome, IFNULL(vlan, '-'), IFNULL(role, '-'), IFNULL(session_timeout, '-'), reason, IFNULL(signal_detail, '-'), IFNULL(identity, '-'), IFNULL(ad_groups, '-'), IFNULL(group_rule, '-'), IFNULL(nas_name, '-')) FROM panopticon_radius_decisions WHERE mac_address = '$1' ORDER BY decided_at DESC LIMIT 1;" | sql; }
check "a quarantine by signal is recorded, with what was sent and why" "$(latest aa:bb:cc:00:00:01)" \
  'embedded | mab | accept | 999 | QUARANTINE.in | 600 | security signal: quarantine (otherwise: trusted device) | Cadavault posture score 40 (below 60) | aabbcc000001 | - | - | lab-sw'
check "a reject by signal is recorded" "$(latest aa:bb:cc:00:00:02)" \
  'reject | - | - | - | security signal: reject (otherwise: trusted device) | open Thanatos high event "SSH brute force"'
check "the role recorded is the one sent (none to a NAS without a role attribute)" "$(latest aa:bb:cc:00:00:05)" \
  'embedded | mab | accept | 10 | - | 28800 | trusted device'
page() { curl -s -b "$jar" "$base$1"; }
check "Decisions page, filtered by MAC: the reason" "$(page '/arsenals/panopticon/radius/decisions?mac=AA-BB-CC-00-00-01')" "Cadavault posture score 40 (below 60)"
check_not "... and only that MAC" "$(page '/arsenals/panopticon/radius/decisions?mac=AA-BB-CC-00-00-01')" "aa:bb:cc:00:00:05"
count() { echo "SELECT COUNT(*) FROM panopticon_radius_decisions;" | sql; }
before=$(count)
out=$(page "/arsenals/panopticon/radius/decisions?test_mac=aabbcc000002&test_nas=$lab_sw&test_admission=mab")
check "test a login: the decision and why" "$out" "security signal: reject (otherwise: trusted device)"
sleep 1
check "... and it isn't recorded" "$(count)" "^$before\$"
check "test a login: a MAC that isn't one" "$(page '/arsenals/panopticon/radius/decisions?test_mac=nope')" "isn&#x27;t a MAC address\|isn't a MAC address"
check "the sessions table shows each session's decision" "$(page /arsenals/panopticon/radius)" "accept, VLAN 10, re-auth 8 h"
for _ in $(seq 1 20); do [ -n "$(echo "SELECT 1 FROM panopticon_policy_simulations;" | sql)" ] && break; sleep 1; done
check "Simulate: the policy match is recorded, not enforced (no RADIUS session yet)" \
  "$(echo "SELECT CONCAT_WS(' | ', rule_name, device_ip, action, path, detail, times_seen) FROM panopticon_policy_simulations;" | sql)" \
  "Posture | 10.0.0.51 | quarantine | skipped | its switch port isn't known, and it has no open RADIUS session | 1"
check_not "... and nothing was enforced" "$(echo "SELECT COUNT(*) FROM panopticon_device_enforcements;" | sql)" "^[1-9]"

# ---- The FreeRADIUS API ---------------------------------------------------
echo "--- FreeRADIUS API (/internal/radius)"
start_app api
check "no token: refused" "$(curl -s -o /dev/null -w '%{http_code}' -d '{}' "$base/internal/radius/mab")" 401

out=$(api mab 127.0.0.1 "$(attrs aabbcc000005)")
check "MAB from a Filter-Id NAS: role" "$out" '"reply:Filter-Id":{"do_xlat":false,"value":"EMPLOYEE.in"}'
check "... and Session-Timeout" "$out" '"reply:Session-Timeout":{"do_xlat":false,"value":"28800"}'
check "... that re-authenticates" "$out" '"reply:Termination-Action":{"do_xlat":false,"value":"RADIUS-Request"}'
check_not "MAB from an address that isn't a NAS client: no role" "$(api mab 10.8.8.8 "$(attrs aabbcc000005)")" "Filter-Id"
check "AD group names for FreeRADIUS to look up" \
  "$(curl -s -u "freeradius:$token" "$base/internal/radius/group-names")" 'CORP\\\\Finance'

out=$(api post-auth 127.0.0.1 "$(attrs aa-bb-cc-00-00-aa alice 'CORP\\Finance')")
check "PEAP login in a role-only group rule: its role" "$out" '"value":"FINANCE.in"'
check_not "... and no VLAN" "$out" "Tunnel-Private-Group-Id"
sleep 1
check "a PEAP login is recorded with its identity, AD groups and group rule" "$(latest aa:bb:cc:00:00:aa)" \
  'freeradius | dot1x | accept | - | FINANCE.in | 1800 | unknown device: admitted, by AD group rule | - | alice | CORP\\Finance | CORP\\Finance | lab-sw'
for _ in $(seq 1 20); do [ -n "$(echo "SELECT 1 FROM panopticon_policy_simulations WHERE path = 'radius';" | sql)" ] && break; sleep 1; done
check "Simulate: with a RADIUS session, the same row now says RADIUS" \
  "$(echo "SELECT CONCAT_WS(' | ', path, detail, times_seen) FROM panopticon_policy_simulations;" | sql)" \
  "radius | MAC aa:bb:cc:00:00:01 (enforcement is turned off globally, so not even when active): Cadavault posture score 40 (below 60) | 2"
check "Simulate: the rogue DHCP server's device would be quarantined, and why" \
  "$(echo "SELECT CONCAT_WS(' | ', rule_name, device_ip, path, detail) FROM panopticon_policy_simulations WHERE device_ip = '10.0.0.56';" | sql)" \
  "RogueDHCP | 10.0.0.56 | radius | MAC aa:bb:cc:00:00:06 (enforcement is turned off globally, so not even when active): rogue DHCP server: answered DHCP from aa:bb:cc:00:00:06 (not an allowed server)"
check_not "... but not device 05, whose address was only named as a server (forgeable)" \
  "$(echo "SELECT device_ip FROM panopticon_policy_simulations WHERE rule_name = 'RogueDHCP';" | sql)" "10.0.0.55"
check_not "... and the allowed server's isn't" "$(echo "SELECT device_ip FROM panopticon_policy_simulations;" | sql)" "10.0.0.10"
check "... shown on the policy page" "$(page /arsenals/panopticon/policy)" "Cadavault posture score 40 (below 60)"
check "... and cleared from it" "$(form /arsenals/panopticon/policy/simulations/clear)" 303
check "... (gone)" "$(echo "SELECT COUNT(*) FROM panopticon_policy_simulations;" | sql)" "^0$"
check "PEAP login, posture below 60: quarantined" \
  "$(api post-auth 127.0.0.1 "$(attrs aa-bb-cc-00-00-01 alice)")" '"reply:Tunnel-Private-Group-Id":{"do_xlat":false,"value":"999"}'

setting panopticon.quarantine_vlan 0
check "no quarantine VLAN, role NAS: quarantined by role alone" \
  "$(api mab 127.0.0.1 "$(attrs aabbcc000006)")" '"reply:Filter-Id":{"do_xlat":false,"value":"QUARANTINE.in"}'
check "no quarantine VLAN, NAS without roles: reject" \
  "$(api mab 10.9.9.9 "$(attrs aabbcc000006)")" '"control:Auth-Type":{"do_xlat":false,"value":"Reject"}'
setting panopticon.quarantine_vlan 999

setting panopticon.radius_unknown_action '"register"'
out=$(api mab 127.0.0.1 "$(attrs aabbcc000007)")
check "registered guest: the guest VLAN" "$out" '"reply:Tunnel-Private-Group-Id":{"do_xlat":false,"value":"50"}'
check "... until its registration ends (20 min, not the 60-min guest timeout)" "$out" '"reply:Session-Timeout":{"do_xlat":false,"value":"1[12][0-9][0-9]"}'
check "registered guest with 3 h left: the guest timeout" \
  "$(api mab 127.0.0.1 "$(attrs aabbcc000008)")" '"reply:Session-Timeout":{"do_xlat":false,"value":"3600"}'
setting panopticon.radius_unknown_action '"accept"'

echo "INSERT INTO posture_runs (id, host_id, platform, started_by, passed, failed, not_applicable, score, created_at) VALUES ('e2e-p2','b1111111-1111-1111-1111-111111111111','linux','e2e',9,1,0,90,NOW() + INTERVAL 1 SECOND); UPDATE thanatos_events SET status = 'resolved' WHERE id = 'e2e-e2';" | sql
check "posture fixed: back to the trusted VLAN" \
  "$(api mab 127.0.0.1 "$(attrs aabbcc000001)")" '"reply:Tunnel-Private-Group-Id":{"do_xlat":false,"value":"10"}'
check "Thanatos event resolved: admitted" \
  "$(api mab 127.0.0.1 "$(attrs aabbcc000002)")" '"control:Auth-Type":{"do_xlat":false,"value":"Accept"}'

echo "RENAME TABLE posture_runs TO posture_runs_gone;" | sql
check "posture unreadable: admitted as without the signal" \
  "$(api mab 127.0.0.1 "$(attrs aabbcc000001)")" '"reply:Tunnel-Private-Group-Id":{"do_xlat":false,"value":"10"}'
check "... and logged" "$(app_log)" "couldn't read a security signal"
echo "RENAME TABLE posture_runs_gone TO posture_runs;" | sql

# ---- Live re-evaluation (0.2.9 Q3) ----------------------------------------
echo "--- live re-evaluation (CoA)"
docker rm -f $nas >/dev/null 2>&1 || true
docker run -d --name $nas --network host -v "$here/fake_nas.py:/fake_nas.py:ro" \
  python:3.12-alpine python -u /fake_nas.py 127.0.0.1 "$coa_port" "$secret" >/dev/null
# 01's session (e2e-2) runs on "accept, VLAN 10": its posture now drops.
# The control plane (04) gets a session too, and turns untrusted: its
# decision would change, but it's never touched. 05's (e2e-1) stays as is.
sql <<'EOF2'
INSERT INTO posture_runs (id, host_id, platform, started_by, passed, failed, not_applicable, score, created_at) VALUES ('e2e-p3','b1111111-1111-1111-1111-111111111111','linux','e2e',3,7,0,30,NOW() + INTERVAL 3 SECOND);
INSERT INTO panopticon_radius_sessions (id, username, mac_address, nas_ip, acct_session_id, auth_method, started_at, last_seen_at) VALUES ('5e5e5e5e-0000-0000-0000-000000000004','aabbcc000004','aa:bb:cc:00:00:04','127.0.0.1','e2e-cp','mab',NOW() - INTERVAL 30 MINUTE,NOW());
UPDATE panopticon_devices SET trust_state = 'untrusted' WHERE id = 'd4444444-4444-4444-4444-444444444444';
EOF2
coa() { echo "SELECT CONCAT_WS(' | ', IFNULL(last_coa_result, 'none'), IFNULL(terminate_cause, '-')) FROM panopticon_radius_sessions WHERE acct_session_id = '$1';" | sql; }
check "re-evaluation: an out-of-range interval is refused" \
  "$(radius_settings -d timeout_trusted=480 -d reevaluate_enabled=true -d reevaluate_seconds=5)" 400
check "re-evaluation turned on (every 10 s)" "$(radius_settings -d timeout_trusted=480 -d reevaluate_enabled=true \
  -d reevaluate_seconds=10 -d reevaluate_cooldown_minutes=15 -d reevaluate_max_per_sweep=25)" 303
for _ in $(seq 1 45); do [ "$(coa e2e-2)" != "none | -" ] && break; sleep 1; done
check "posture dropped mid-session: the NAS ACKed a Disconnect, the session closed" "$(coa e2e-2)" "ACK | Disconnected (CoA)"
check "... for that session" "$(docker logs $nas 2>&1)" "request code=40 session=e2e-2"
check "... audited with why" "$(echo "SELECT metadata FROM audit_log WHERE action = 'NETWORK_RADIUS_REAUTHORIZED' ORDER BY occurred_at DESC LIMIT 1;" | sql)" \
  're-evaluation: accept, VLAN 10, role EMPLOYEE.in -> accept, VLAN 999, role QUARANTINE.in (security signal: quarantine (otherwise: trusted device))'
check "a session whose decision didn't change: left alone" "$(coa e2e-1)" "none | -"
check "the control plane's session: left alone" "$(coa e2e-cp)" "none | -"
check_not "... and nothing was sent for it" "$(docker logs $nas 2>&1)" "e2e-cp"
check "... because it's the control plane (its decision did change)" "$(app_log)" "mac=\"aa:bb:cc:00:00:04\".*the control plane's own server; left alone\|the control plane's own server; left alone.*aa:bb:cc:00:00:04"
# The device re-authenticates (now quarantined) and accounts a new session:
# that matches what it runs on, so the next sweeps leave it alone.
api mab 127.0.0.1 "$(attrs aabbcc000001)" >/dev/null
echo "INSERT INTO panopticon_radius_sessions (id, username, mac_address, nas_ip, acct_session_id, auth_method, started_at, last_seen_at) VALUES ('5e5e5e5e-0000-0000-0000-000000000001','aabbcc000001','aa:bb:cc:00:00:01','127.0.0.1','e2e-3','mab',NOW(),NOW());" | sql
sleep 25
check "after re-authenticating, the new session is left alone" "$(coa e2e-3)" "none | -"
check "a policy change reaches a live session too: 06 got in by role while the quarantine VLAN was unset, and it's set again" \
  "$(echo "SELECT JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.why')) FROM audit_log WHERE action = 'NETWORK_RADIUS_REAUTHORIZED' AND JSON_EXTRACT(metadata, '$.session') = 'e2e-06';" | sql)" \
  '^re-evaluation: accept, role QUARANTINE.in -> accept, VLAN 999, role QUARANTINE.in (untrusted device: quarantine)$'
check "two re-authorizations in all (one per changed session, none repeated)" "$(docker logs $nas 2>&1 | grep -c '^request')" "^2$"

# ---- SNMP traps (0.2.9 Q5) ------------------------------------------------
echo "--- SNMP traps"
send_traps() {
  # $1: how many; the rest: send_trap.py's arguments after the port.
  n=$1; shift
  docker run --rm --network host -v "$here/send_trap.py:/send_trap.py:ro" python:3.12-alpine \
    sh -c 'n=$1; shift; i=0; while [ $i -lt $n ]; do python /send_trap.py 127.0.0.1 "$@"; i=$((i + 1)); done' \
    - "$n" "$trap_port" "$@"
}
polls() { app_log | grep -c "SNMP trap: polled the switch"; }
last_trap() { echo "SELECT IFNULL(last_trap, 'none') FROM panopticon_switches WHERE name = 'lab-core';" | sql; }
check "the trap listener started" "$(app_log)" "Panopticon SNMP trap listener started port=$trap_port"
send_traps 1 e2e-community linkdown 3
for _ in $(seq 1 30); do [ "$(polls)" -ge 1 ] && break; sleep 1; done
check "linkDown from the switch, with its community: recorded" "$(last_trap)" "^linkDown ifIndex 3$"
check "... and the switch polled at once" "$(polls)" "^1$"
for _ in $(seq 1 15); do app_log | grep -q "SNMP trap: policy pass run" && break; sleep 1; done
check "... then a policy pass run" "$(app_log)" "SNMP trap: policy pass run switch=lab-core"
send_traps 1 wrong-community linkup 4
sleep 2
check "the wrong community: dropped" "$(app_log)" 'SNMP trap with the wrong community; dropped switch=lab-core\|switch=lab-core.*wrong community'
check "... not recorded" "$(last_trap)" "^linkDown ifIndex 3$"
docker run --rm --add-host=host.docker.internal:host-gateway -v "$here/send_trap.py:/send_trap.py:ro" \
  python:3.12-alpine python /send_trap.py host.docker.internal "$trap_port" e2e-community linkup 5
sleep 2
check "a trap from an address that isn't a polled switch: dropped" "$(app_log)" "isn't a polled v1/v2c switch; dropped"
check "... not recorded" "$(last_trap)" "^linkDown ifIndex 3$"
sleep 6 # past the 5-second window
send_traps 5 e2e-community linkup 6
for _ in $(seq 1 40); do [ "$(polls)" -ge 3 ] && break; sleep 1; done
sleep 7
check "a burst of 5 traps: 2 polls (one now, one at the end of the window)" "$(polls)" "^3$"
send_traps 1 e2e-community mac aa:bb:cc:00:00:09 10 5
sleep 2
check "a Cisco MAC notification: recorded" "$(last_trap)" "^MAC notification: + aa:bb:cc:00:00:09 VLAN 10 port 5$"
check "the switches page shows the last trap" "$(page /arsenals/panopticon/switches)" "MAC notification: + aa:bb:cc:00:00:09 VLAN 10 port 5 ("

[ $fail -eq 0 ] && echo "all RADIUS end-to-end checks passed"
exit $fail
