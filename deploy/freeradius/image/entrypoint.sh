#!/bin/bash
# FreeRADIUS container entrypoint (deploy/freeradius/README.md).
#
# Without AD_REALM: runs FreeRADIUS exactly as the official image does.
# With AD_REALM: writes smb.conf/krb5.conf, joins the domain once (the
# machine account lives in the abyssal_freeradius_samba volume), starts
# winbindd, then FreeRADIUS. If either process exits, the container exits
# and Docker restarts it: a dead winbindd would otherwise reject every
# PEAP login while looking healthy.
set -euo pipefail

log() { echo "abyssal-freeradius: $*" >&2; }

ad_conf=/run/abyssal-ad
rm -rf "$ad_conf"
mkdir -p "$ad_conf"

# A configuration check (freeradius -C / -XC) or any other command needs
# no domain.
config_check=0
for a in "$@"; do [[ "$a" =~ ^-[A-Za-z]*C ]] && config_check=1; done
if [ -z "${AD_REALM:-}" ] || [ "${1:-}" != "freeradius" ] || [ $config_check -eq 1 ]; then
  [ -z "${AD_REALM:-}" ] && [ "${1:-}" = "freeradius" ] && log "AD_REALM is empty: PEAP/MSCHAPv2 logins will be rejected (EAP-TLS and MAB only)"
  exec "$@"
fi

realm=$(echo "$AD_REALM" | tr '[:lower:]' '[:upper:]')
workgroup=$(echo "${AD_WORKGROUP:-${realm%%.*}}" | tr '[:lower:]' '[:upper:]')
netbios=$(echo "${AD_NETBIOS_NAME:-ABYSSAL-RADIUS}" | tr '[:lower:]' '[:upper:]')
if [ ${#netbios} -gt 15 ]; then
  log "AD_NETBIOS_NAME must be 15 characters or fewer: $netbios"
  exit 1
fi
for v in "$realm" "$workgroup" "$netbios" "${AD_DC:-}"; do
  if [[ ! "$v" =~ ^[A-Za-z0-9.,\ -]*$ ]]; then
    log "AD_REALM, AD_WORKGROUP, AD_NETBIOS_NAME and AD_DC may only contain letters, digits, dots, commas, spaces and hyphens"
    exit 1
  fi
done

password_server=""
kdc_lines=""
if [ -n "${AD_DC:-}" ]; then
  password_server="password server = ${AD_DC//,/ }"
  for dc in ${AD_DC//,/ }; do kdc_lines+="    kdc = $dc"$'\n'; done
fi

mkdir -p /etc/samba
cat > /etc/samba/smb.conf <<EOF
# Written by abyssal-freeradius-entrypoint from AD_* at every start.
[global]
   security = ads
   realm = $realm
   workgroup = $workgroup
   netbios name = $netbios
   $password_server
   kerberos method = secrets only
   winbind use default domain = yes
   winbind offline logon = no
   idmap config * : backend = tdb
   idmap config * : range = 3000-7999
   idmap config $workgroup : backend = rid
   idmap config $workgroup : range = 10000-999999
   # No file sharing: winbindd and ntlm_auth only.
   load printers = no
   printing = bsd
   disable spoolss = yes
   log level = ${AD_SAMBA_LOG_LEVEL:-1}
   logging = stderr
EOF

cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = $realm
    dns_lookup_realm = false
    dns_lookup_kdc = true
    rdns = false
EOF
if [ -n "$kdc_lines" ]; then
  printf '[realms]\n    %s = {\n%s    }\n' "$realm" "$kdc_lines" >> /etc/krb5.conf
fi

# Join once. The machine account's secret persists in /var/lib/samba.
if net ads testjoin >/dev/null 2>&1; then
  log "already joined to $realm as $netbios"
elif [ -n "${AD_JOIN_USER:-}" ] && [ -n "${AD_JOIN_PASSWORD:-}" ]; then
  log "joining $realm as $netbios with $AD_JOIN_USER"
  join_args=(ads join --no-dns-updates -U "$AD_JOIN_USER")
  [ -n "${AD_JOIN_OU:-}" ] && join_args+=("createcomputer=$AD_JOIN_OU")
  # Password through $PASSWD, never the command line. A few tries: a DC
  # that has only just started answers LDAP before it can take a join.
  joined=0
  for attempt in 1 2 3 4 5; do
    if PASSWD="$AD_JOIN_PASSWORD" net "${join_args[@]}"; then joined=1; break; fi
    log "join attempt $attempt failed; retrying in 5 seconds"
    sleep 5
  done
  if [ $joined -eq 0 ]; then
    log "domain join failed (see above); check AD_JOIN_USER/AD_JOIN_PASSWORD, DNS for $realm and the clock"
    exit 1
  fi
  log "joined; AD_JOIN_USER and AD_JOIN_PASSWORD can now be removed from .env"
else
  log "not joined to $realm and AD_JOIN_USER/AD_JOIN_PASSWORD are empty: set them for the first start"
  exit 1
fi
unset AD_JOIN_PASSWORD PASSWD

if [ -n "${AD_REQUIRE_GROUP:-}" ]; then
  printf '%s' "$AD_REQUIRE_GROUP" > "$ad_conf/require-group"
fi
touch "$ad_conf/enabled"
chmod 755 "$ad_conf"
chmod 644 "$ad_conf"/*

winbindd --foreground --no-process-group &
wb=$!

# Wait for winbindd to answer and the domain trust to check out. A DC that
# isn't reachable yet isn't fatal: winbindd keeps trying, and logins are
# rejected until it succeeds.
for _ in $(seq 1 30); do
  wbinfo -p >/dev/null 2>&1 && break
  sleep 1
done
if wbinfo -t >/dev/null 2>&1; then
  log "domain trust OK"
else
  log "warning: can't verify the trust with $realm yet; PEAP logins fail until winbindd reaches a DC"
fi
if [ -n "${AD_REQUIRE_GROUP:-}" ] && ! wbinfo --group-info="$AD_REQUIRE_GROUP" >/dev/null 2>&1; then
  log "warning: AD_REQUIRE_GROUP \"$AD_REQUIRE_GROUP\" wasn't found; every PEAP login will be rejected"
fi

"$@" &
fr=$!

trap 'kill -TERM $fr $wb 2>/dev/null; wait' TERM INT
set +e
wait -n $fr $wb
status=$?
log "$( kill -0 $fr 2>/dev/null && echo winbindd || echo freeradius ) exited ($status); stopping"
kill -TERM $fr $wb 2>/dev/null
wait
exit $(( status == 0 ? 1 : status ))
