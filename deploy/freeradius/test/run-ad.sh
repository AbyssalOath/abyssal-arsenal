#!/bin/sh
# Tests PEAP/MSCHAPv2 against Active Directory: the FreeRADIUS image
# (deploy/freeradius/image) joins a real Samba AD domain controller, and
# eapol_test logs in through it. Panopticon is the same stand-in as run.sh
# (fake_api.py). Needs Docker; touches nothing outside its own containers,
# network, volume and a temp directory.
#
#   deploy/freeradius/test/run-ad.sh
#
# Checks: the domain join; PEAP accepted for a user in AD_REQUIRE_GROUP
# (with VLAN, correct MPPE keys, and the inner login reaching Panopticon
# instead of the anonymous outer identity); DOMAIN\user and user@realm
# forms; wrong password, unknown user and a user outside the group
# rejected; Panopticon's reject still wins after a good password; a
# computer (host/...) login; VLAN by AD group (0.2.8 P1): direct and nested
# groups that have a rule reach Panopticon and others don't, the group
# VLAN comes back, a computer brings its own groups, and a failing group
# lookup leaves the login to the device's VLAN; a restart reuses the join
# without the join password; the join password never appears in the logs.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
conf=$(cd "$here/.." && pwd)
image=abyssal-arsenal-freeradius:3.2.7
dc_image=abyssal-test-samba-dc:22.04
token=0123456789abcdef0123456789abcdef
admin_pw='Adm1n!Passw0rd'
net=aa-ad-net
tmp=$(mktemp -d)
chmod 755 "$tmp"
cleanup() {
  [ -n "${KEEP:-}" ] || {
    docker rm -f aa-ad-fr aa-ad-api aa-ad-dc >/dev/null 2>&1 || true
    docker network rm $net >/dev/null 2>&1 || true
    docker volume rm aa-ad-samba >/dev/null 2>&1 || true
  }
  rm -rf "$tmp"
}
trap cleanup EXIT
cleanup_now() { docker rm -f aa-ad-fr aa-ad-api aa-ad-dc >/dev/null 2>&1 || true; docker network rm $net >/dev/null 2>&1 || true; docker volume rm aa-ad-samba >/dev/null 2>&1 || true; }
cleanup_now

docker build -q -t $image "$conf/image" >/dev/null
# eapol_test baked in up front: once on the test network, the container's
# DNS is the test DC, which can't reach a package mirror.
printf 'FROM %s\nRUN apt-get update -qq && apt-get install -y -qq eapoltest >/dev/null && rm -rf /var/lib/apt/lists/*\n' $image \
  | docker build -q -t $image-eapoltest - >/dev/null

# A Samba AD DC: domain TEST (test.lan), users alice (in WiFi-Users), bob
# (not), computer PC1 (in WiFi-Users, known password). Samba's DC refuses
# MSCHAPv2 unless told otherwise; Windows DCs allow it by default.
mkdir "$tmp/dc"
cat > "$tmp/dc/Dockerfile" <<'EOF'
FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba samba-dsdb-modules samba-vfs-modules winbind krb5-user && rm -rf /var/lib/apt/lists/*
COPY start.sh /start.sh
CMD ["sh", "/start.sh"]
EOF
cat > "$tmp/dc/start.sh" <<EOF
set -e
rm -f /etc/samba/smb.conf
samba-tool domain provision --realm=TEST.LAN --domain=TEST --server-role=dc \\
  --dns-backend=SAMBA_INTERNAL --adminpass='$admin_pw' \\
  --option="ntlm auth = mschapv2-and-ntlmv2-only" --option="dns forwarder = 127.0.0.1" >/dev/null
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
samba-tool user create alice 'Passw0rd!' >/dev/null
samba-tool user create bob 'Passw0rd!' >/dev/null
samba-tool group add WiFi-Users >/dev/null
samba-tool computer create PC1 >/dev/null
samba-tool user setpassword 'PC1\$' --newpassword='Mach1ne!Passw0rd' >/dev/null
samba-tool group addmembers WiFi-Users 'alice,PC1\$' >/dev/null
samba-tool group add Staff >/dev/null
samba-tool group addmembers Staff WiFi-Users >/dev/null
echo provisioned
exec samba -i
EOF
docker build -q -t $dc_image "$tmp/dc" >/dev/null

docker network create --subnet 172.29.0.0/24 $net >/dev/null
docker run -d --name aa-ad-dc --hostname dc1 --network $net --ip 172.29.0.2 --dns 172.29.0.2 \
  --cap-add SYS_ADMIN $dc_image >/dev/null
i=0; until docker exec aa-ad-dc sh -c "samba-tool domain info 127.0.0.1 && echo '$admin_pw' | kinit Administrator" >/dev/null 2>&1; do
  i=$((i+1)); [ $i -gt 120 ] && { docker logs aa-ad-dc 2>&1 | tail -20; exit 1; }; sleep 1; done

docker run -d --name aa-ad-api --network $net --ip 172.29.0.3 --dns 172.29.0.2 --dns-search test.lan \
  -v "$here/fake_api.py:/fake_api.py:ro" python:3.12-alpine python -u /fake_api.py >/dev/null

# Throwaway CA and server certificate (PEAP clients check the server).
cd "$tmp"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 1 -subj "/CN=Test CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=radius.test" 2>/dev/null
printf "extendedKeyUsage=serverAuth\n" > s.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 1 -extfile s.ext 2>/dev/null
chmod 644 ./*.key
peap() { # file identity password
  printf 'network={\n key_mgmt=IEEE8021X\n eap=PEAP\n identity="%s"\n anonymous_identity="anonymous"\n password="%s"\n phase2="auth=MSCHAPV2"\n ca_cert="/certs/ca.pem"\n eapol_flags=0\n}\n' "$2" "$3" > "$1.conf"
}
peap alice 'alice' 'Passw0rd!'
peap alice-dom 'TEST\alice' 'Passw0rd!'
peap alice-upn 'alice@test.lan' 'Passw0rd!'
peap alice-bad 'alice' 'wrong-password'
peap bob 'bob' 'Passw0rd!'
peap nobody 'nobody' 'Passw0rd!'
peap pc1 'host/pc1.test.lan' 'Mach1ne!Passw0rd'

mounts="-v $conf/clients.conf:/etc/freeradius/clients.conf:ro
 -v $conf/mods-enabled/eap:/etc/freeradius/mods-enabled/eap:ro
 -v $conf/mods-enabled/abyssal:/etc/freeradius/mods-enabled/abyssal:ro
 -v $conf/mods-enabled/mschap:/etc/freeradius/mods-enabled/mschap:ro
 -v $conf/sites-enabled:/etc/freeradius/sites-enabled:ro
 -v $tmp:/etc/freeradius/certs-abyssal:ro
 -v $tmp:/certs:ro
 -v aa-ad-samba:/var/lib/samba"

start_fr() { # extra docker-run args...
  docker rm -f aa-ad-fr >/dev/null 2>&1 || true
  docker run -d --name aa-ad-fr --network container:aa-ad-api \
    -e ABYSSAL_FREERADIUS_TOKEN=$token -e AD_REALM=test.lan -e AD_DC=dc1.test.lan \
    -e 'AD_REQUIRE_GROUP=TEST\WiFi-Users' "$@" $mounts $image-eapoltest freeradius -X >/dev/null
  i=0; until docker logs aa-ad-fr 2>&1 | grep -q "Ready to process"; do
    i=$((i+1)); [ $i -gt 90 ] && { docker logs aa-ad-fr 2>&1 | tail -30; exit 1; }; sleep 1; done
}

fail=0
check() { if echo "$2" | grep -q "$3"; then echo "ok   $1"; else echo "FAIL $1"; echo "$2" | tail -15 | sed 's/^/     /'; fail=1; fi; }
eap() { docker exec aa-ad-fr eapol_test -c "/certs/$1.conf" -s testing123 -a 127.0.0.1 -M "$2" 2>&1 || true; }

start_fr -e AD_JOIN_USER=Administrator -e "AD_JOIN_PASSWORD=$admin_pw"
check "joins the domain" "$(docker logs aa-ad-fr 2>&1)" "joined; AD_JOIN_USER"
check "domain trust checks out" "$(docker logs aa-ad-fr 2>&1)" "domain trust OK"

out=$(eap alice aa:bb:cc:dd:ee:ff)
check "PEAP: user in the group, right password: Access-Accept" "$out" "code=2 (Access-Accept)"
check "PEAP: ... with Panopticon's VLAN" "$out" "Tunnel-Private-Group-Id"
check "PEAP: ... and correct MPPE keys" "$out" "MPPE keys OK: 1  mismatch: 0"
check "PEAP: ... the real login, not the outer identity, reaches Panopticon" \
  "$(docker logs aa-ad-api 2>&1 | grep post-auth | tail -1)" '"User-Name": {"type": "string", "value": \["alice"\]}'
check "PEAP: DOMAIN\\user form" "$(eap alice-dom aa:bb:cc:dd:ee:ff)" "code=2 (Access-Accept)"
check "PEAP: user@realm form" "$(eap alice-upn aa:bb:cc:dd:ee:ff)" "code=2 (Access-Accept)"
check "PEAP: wrong password: Access-Reject" "$(eap alice-bad aa:bb:cc:dd:ee:ff)" "code=3 (Access-Reject)"
check "PEAP: unknown user: Access-Reject" "$(eap nobody aa:bb:cc:dd:ee:ff)" "code=3 (Access-Reject)"
check "PEAP: user outside AD_REQUIRE_GROUP: Access-Reject" "$(eap bob aa:bb:cc:dd:ee:ff)" "code=3 (Access-Reject)"
check "PEAP: right password, device Panopticon refuses: Access-Reject" "$(eap alice 66:66:66:66:66:66)" "code=3 (Access-Reject)"
check "PEAP: computer login (host/pc1.test.lan): Access-Accept" "$(eap pc1 aa:bb:cc:dd:ee:ff)" "code=2 (Access-Accept)"

# VLAN by AD group (0.2.8 P1). The fake API's rules name
# "TEST\WiFi-Users;Staff;Nobody-Group;Domain Computers", and give Staff VLAN 30.
# The VLAN in an eapol_test transcript, as hex ("3330" is "30").
vlan() { echo "$1" | grep -A1 'Tunnel-Private-Group-Id' | tail -1; }
groups() { docker logs aa-ad-api 2>&1 | grep post-auth | tail -1 | sed -n 's/.*"Abyssal-AD-Groups": {"type": "string", "value": \["\([^"]*\)"\]}.*/\1/p'; }
out=$(eap alice aa:bb:cc:dd:ee:ff)
check "groups: a user's direct and nested groups reach Panopticon, others don't" "$(groups)" '^TEST\\\\WiFi-Users;Staff$'
check "groups: ... and Panopticon's group VLAN (30) is returned" "$(vlan "$out")" "Value: 3330$"
eap pc1 aa:bb:cc:dd:ee:ff >/dev/null
check "groups: a computer login brings the computer's own groups" "$(groups)" '^TEST\\\\WiFi-Users;Staff;Domain Computers$'
docker exec aa-ad-api touch /tmp/group-names-fail
out=$(eap alice aa:bb:cc:dd:ee:ff)
check "groups: a failing group lookup doesn't fail the login" "$out" "code=2 (Access-Accept)"
check "groups: ... the login just arrives without groups" "$(groups)" '^$'
check "groups: ... and gets its device's VLAN (20)" "$(vlan "$out")" "Value: 3230$"
docker exec aa-ad-api rm -f /tmp/group-names-fail

check "the join password never appears in the logs" "$(docker logs aa-ad-fr 2>&1 | grep -c "$admin_pw" || true)" "^0$"

# Restart without the join credentials: the volume keeps the join.
start_fr
check "restart reuses the join, no join password needed" "$(docker logs aa-ad-fr 2>&1)" "already joined to TEST.LAN"
check "PEAP after restart: Access-Accept" "$(eap alice aa:bb:cc:dd:ee:ff)" "code=2 (Access-Accept)"

[ $fail -eq 0 ] && echo "all Active Directory checks passed"
exit $fail
