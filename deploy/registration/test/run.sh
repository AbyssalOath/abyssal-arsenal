#!/bin/sh
# Tests the registration VLAN's DHCP server and captive DNS
# (crates/portal-net) against real clients: BusyBox udhcpc and nslookup, on a
# throwaway Docker network. Needs Docker; builds the crate's test harness
# (examples/portal_net.rs) in rust:1-trixie with its own cache, and touches
# nothing outside its own containers, network and temp directory.
#
#   deploy/registration/test/run.sh
set -eu
repo=$(cd "$(dirname "$0")/../../.." && pwd)
tmp=$(mktemp -d)
cache=${PORTAL_TEST_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/abyssal-portal-test}
mkdir -p "$cache/target" "$cache/registry"
net=aa-regtest
cleanup() { docker rm -f aa-reg-srv aa-reg-cli >/dev/null 2>&1 || true; docker network rm $net >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT

echo "building the test harness..."
docker run --rm -v "$repo:/src:ro" -v "$cache/target:/target" -v "$cache/registry:/usr/local/cargo/registry" \
  -e CARGO_TARGET_DIR=/target -w /src rust:1-trixie \
  cargo build --locked -q -p abyssal-portal-net --example portal_net

cat > "$tmp/udhcpc.sh" <<'S'
#!/bin/sh
[ "$1" = bound ] && echo "BOUND ip=$ip subnet=$subnet router=$router dns=$dns lease=$lease serverid=$serverid opt114=$opt114"
exit 0
S
chmod 755 "$tmp" "$tmp/udhcpc.sh"

docker network rm $net >/dev/null 2>&1 || true
docker network create --subnet 10.99.0.0/24 --gateway 10.99.0.254 $net >/dev/null
docker run -d --name aa-reg-srv --network $net --ip 10.99.0.1 \
  -v "$cache/target/debug/examples/portal_net:/portal_net:ro" rust:1-trixie \
  /portal_net eth0 10.99.0.1/24 10.99.0.100 10.99.0.101 60 >/dev/null
i=0; until docker logs aa-reg-srv 2>&1 | grep -q READY; do i=$((i+1)); [ $i -gt 20 ] && { docker logs aa-reg-srv; exit 1; }; sleep 1; done

fail=0
check() { if echo "$2" | grep -q -- "$3"; then echo "ok   $1"; else echo "FAIL $1"; echo "$2" | sed 's/^/     /'; fail=1; fi; }
client() { docker run --rm --network $net -v "$tmp/udhcpc.sh:/s.sh:ro" python:3.12-alpine sh -c "$1" 2>&1 || true; }

out=$(client 'udhcpc -i eth0 -n -q -f -t 3 -T 2 -s /s.sh -V "MSFT 5.0" -x hostname:guest-laptop -O 114')
check "DHCP: a client gets a lease from the pool" "$out" "BOUND ip=10.99.0.10[01] "
check "DHCP: ... with the portal as router and DNS" "$out" "router=10.99.0.1 dns=10.99.0.1"
check "DHCP: ... a /24 mask and the configured lease" "$out" "subnet=255.255.255.0 router=.* lease=60"
check "DHCP: ... and the captive-portal URL (RFC 8910)" "$out" "opt114=687474703a2f2f31302e39392e302e312f"
check "DHCP: the client's fingerprint is recorded" "$(docker logs aa-reg-srv 2>&1)" 'vendor_class: Some("MSFT 5.0"), hostname: Some("guest-laptop")'

out=$(client 'nslookup -type=A captive.apple.com 10.99.0.1; nslookup -type=A www.msftconnecttest.com 10.99.0.1')
check "DNS: Apple's captive check resolves to the portal" "$out" "Address: 10.99.0.1"
check "DNS: ... and so does Windows'" "$(echo "$out" | grep -c 'Address: 10.99.0.1')" "^2$"
out=$(client 'nslookup -type=AAAA example.com 10.99.0.1')
check "DNS: AAAA gets no address" "$(echo "$out" | grep -c 'Address: ' || true)" "^0$"

# The same client (same MAC) asking twice keeps its address.
out=$(client 'udhcpc -i eth0 -n -q -f -t 2 -T 1 -s /s.sh; udhcpc -i eth0 -n -q -f -t 2 -T 1 -s /s.sh')
check "DHCP: the same client gets the same address again" "$(echo "$out" | grep -o 'BOUND ip=[0-9.]*' | sort -u | wc -l)" "^1$"
# The pool holds two addresses and two clients now hold them: a third
# client (another container, another MAC) gets nothing rather than a clash.
out=$(client 'udhcpc -i eth0 -n -q -f -t 2 -T 1 -s /s.sh')
check "DHCP: an exhausted pool offers nothing (no address clash)" "$out" "[Nn]o lease, failing"

[ $fail -eq 0 ] && echo "all registration network checks passed"
exit $fail
