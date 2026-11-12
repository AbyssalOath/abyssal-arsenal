#!/bin/sh
# Tests deploy/freeradius against the real FreeRADIUS image, with a stand-in
# for Panopticon's /internal/radius API (fake_api.py, same contract and reply
# JSON as crates/web/src/panopticon_freeradius.rs). Needs Docker; touches
# nothing outside its own containers and a temp directory.
#
#   deploy/freeradius/test/run.sh
#
# Checks: config parses; MAB accept (with VLAN) and reject; a non-MAB
# password login rejected; wrong NAS secret ignored; accounting; EAP-TLS
# accepted with VLAN and correct MPPE keys; EAP-TLS rejected by Panopticon's
# decision; EAP-TLS with an untrusted client certificate rejected.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
conf=$(cd "$here/.." && pwd)
image=freeradius/freeradius-server:3.2.7
token=0123456789abcdef0123456789abcdef
tmp=$(mktemp -d)
# FreeRADIUS runs as uid 101: it must be able to read the certificates.
chmod 755 "$tmp"
cleanup() { [ -n "${KEEP:-}" ] || docker rm -f aa-fr aa-fr-api >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT

# Throwaway CA, server and client certificates.
cd "$tmp"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 1 -subj "/CN=Test CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=radius.test" 2>/dev/null
printf "extendedKeyUsage=serverAuth\n" > s.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 1 -extfile s.ext 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=laptop1" 2>/dev/null
printf "extendedKeyUsage=clientAuth\n" > c.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 1 -extfile c.ext 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.pem -days 1 -subj "/CN=rogue" 2>/dev/null
chmod 644 ./*.key
for c in client rogue; do
  printf 'network={\n key_mgmt=IEEE8021X\n eap=TLS\n identity="laptop1"\n ca_cert="/certs/ca.pem"\n client_cert="/certs/%s.pem"\n private_key="/certs/%s.key"\n eapol_flags=0\n}\n' "$c" "$c" > "$c.conf"
done

mounts="-v $conf/clients.conf:/etc/freeradius/clients.conf:ro
 -v $conf/mods-enabled/eap:/etc/freeradius/mods-enabled/eap:ro
 -v $conf/mods-enabled/abyssal:/etc/freeradius/mods-enabled/abyssal:ro
 -v $conf/sites-enabled:/etc/freeradius/sites-enabled:ro
 -v $tmp:/etc/freeradius/certs-abyssal:ro"

fail=0
check() { if echo "$2" | grep -q "$3"; then echo "ok   $1"; else echo "FAIL $1"; echo "$2" | sed 's/^/     /'; fail=1; fi; }

out=$(docker run --rm -e ABYSSAL_FREERADIUS_TOKEN=$token $mounts $image freeradius -XC 2>&1 | tail -1)
check "configuration parses" "$out" "Configuration appears to be OK"

docker run -d --name aa-fr-api -v "$here/fake_api.py:/fake_api.py:ro" python:3.12-alpine python -u /fake_api.py >/dev/null
docker run -d --name aa-fr --network container:aa-fr-api -e ABYSSAL_FREERADIUS_TOKEN=$token $mounts \
  -v "$tmp:/certs:ro" $image freeradius -X >/dev/null
i=0; until docker logs aa-fr 2>&1 | grep -q "Ready to process"; do i=$((i+1)); [ $i -gt 30 ] && { docker logs aa-fr | tail; exit 1; }; sleep 1; done

rc() { docker exec aa-fr sh -c "echo '$1' | radclient -x -r1 -t3 127.0.0.1:$2 $3 $4" 2>&1 || true; }
out=$(rc "User-Name=aabbccddeeff,User-Password=aabbccddeeff,Calling-Station-Id=AA-BB-CC-DD-EE-FF" 1812 auth testing123)
check "MAB: admitted device gets Access-Accept" "$out" "Received Access-Accept"
check "MAB: ... with its VLAN" "$out" 'Tunnel-Private-Group-Id:0 = "10"'
out=$(rc "User-Name=112233445566,User-Password=112233445566,Calling-Station-Id=11-22-33-44-55-66" 1812 auth testing123)
check "MAB: refused device gets Access-Reject" "$out" "Received Access-Reject"
out=$(rc "User-Name=alice,User-Password=hunter2" 1812 auth testing123)
check "a password login that isn't MAB is rejected" "$out" "Received Access-Reject"
check "... and the password never reaches Panopticon" "$(docker logs aa-fr-api 2>&1 | grep -c hunter2 || true)" "^0$"
out=$(rc "User-Name=aabbccddeeff,User-Password=aabbccddeeff,Calling-Station-Id=AA-BB-CC-DD-EE-FF" 1812 auth wrongsecret)
check "a wrong NAS secret gets no answer" "$out" "No reply from server"
check "NAS client names are taken literally, not expanded" "$(docker logs aa-fr 2>&1 | grep -m1 'nas-%' || true)" 'nas-%{User-Name}'
out=$(rc "Acct-Status-Type=Stop,Acct-Session-Id=0A000002,User-Name=aabbccddeeff,Calling-Station-Id=AA-BB-CC-DD-EE-FF,NAS-IP-Address=10.0.0.2" 1813 acct testing123)
check "accounting is acknowledged" "$out" "Received Accounting-Response"

docker exec aa-fr sh -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq eapoltest >/dev/null 2>&1'
eap() { docker exec aa-fr eapol_test -c "/certs/$1.conf" -s testing123 -a 127.0.0.1 -M "$2" 2>&1 || true; }
out=$(eap client aa:bb:cc:dd:ee:ff)
check "EAP-TLS: trusted certificate, admitted device: Access-Accept" "$out" "code=2 (Access-Accept)"
check "EAP-TLS: ... with its VLAN" "$out" "Tunnel-Private-Group-Id"
check "EAP-TLS: ... and correct MPPE keys" "$out" "MPPE keys OK: 1  mismatch: 0"
out=$(eap client 66:66:66:66:66:66)
check "EAP-TLS: device Panopticon refuses: Access-Reject" "$out" "code=3 (Access-Reject)"
out=$(eap rogue aa:bb:cc:dd:ee:ff)
check "EAP-TLS: untrusted client certificate: Access-Reject" "$out" "code=3 (Access-Reject)"

[ $fail -eq 0 ] && echo "all FreeRADIUS checks passed"
exit $fail
