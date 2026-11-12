# Registration portal (guest access)

Panopticon can register guests itself, the way PacketFence does. An unknown
device is put on a **registration VLAN** where Panopticon is the only thing
it can reach. Panopticon runs a small DHCP server and a captive DNS server
there, and serves the registration page. Once the guest is approved,
Panopticon moves the device to the **guest VLAN** (with RADIUS CoA) until the
approval expires.

What the guest sees:

1. They connect (Wi-Fi or a wall port). RADIUS sends the unknown device to the
   registration VLAN.
2. They get an address from Panopticon. Every DNS name resolves to the
   portal, and the lease carries the portal's URL (RFC 8910), so phones and
   laptops pop up their "sign in to network" sheet. If one doesn't, any
   `http://` address in a browser lands on the portal.
3. They enter their name (and optionally an email), and accept the terms.
   - **Self-service:** approved at once.
   - **Sponsor** (the default): a member of staff approves the request on
     **Panopticon → Registration portal**. The guest's page refreshes itself
     until then.
4. Panopticon sends a CoA for the device's RADIUS session. The device
   re-authenticates onto the guest VLAN, renews its address (the
   registration lease is short, 60 seconds by default), and is online.
5. When the approval expires, or staff revoke it, the device goes back to
   the registration VLAN.

Devices that are classified keep their normal treatment: trusted devices
keep their VLAN, and untrusted ones are quarantined or rejected. So do
devices that passed **802.1X** (FreeRADIUS, `deploy/freeradius`): the portal
is only for devices that can't authenticate. A guest on a quarantined port
stays quarantined.

## What keeps the registration VLAN contained

- **DHCP and DNS are bound to the registration interface only**
  (`SO_BINDTODEVICE`). They never answer anything on another network, and
  the DHCP server ignores relayed requests.
- **The portal is a separate web server** on the portal address, port 80,
  serving only the registration pages; every other URL redirects to it.
  The admin UI refuses every request from the registration subnet (HTTP
  404), even though guests can reach the container's address there.
- **Nothing is routed.** The container doesn't forward packets, and the
  Docker network is `internal`, so it never becomes the container's route.
- **A guest is identified by their DHCP lease:** the portal maps the
  requester's address to the MAC it leased it to. Nothing a guest submits
  can name another device.
- **The portal is plain HTTP**, because guests don't trust your certificates.
  So it never asks for a password. A denied device stays denied (it can't
  refill the queue); staff can still approve it later.

## Setup

1. **The VLAN.** Create the registration VLAN on your switches and access
   points, with **no other DHCP server or `ip helper-address`** on it. Trunk
   it to the NIC of the server that runs Abyssal Arsenal.

2. **Attach the container to it.** Add to `.env`:

   ```sh
   REGISTRATION_PARENT=eno1.99          # <host NIC>.<VLAN id>
   REGISTRATION_SUBNET=10.99.0.0/24
   REGISTRATION_PORTAL_IP=10.99.0.1     # the portal's address
   REGISTRATION_DOCKER_GATEWAY=10.99.0.254   # unused; Docker reserves it
   ```

   Then start with the override file:

   ```sh
   docker compose -f docker-compose.yml \
     -f deploy/registration/docker-compose.registration.yml up -d
   ```

   Docker creates the 802.1Q sub-interface (`eno1.99`) if it doesn't
   exist. This uses a macvlan network, and with macvlan the **host itself
   can't reach the container's registration address**; other machines can.
   That's expected.

3. **Portal settings** (Panopticon → Registration portal):
   - **Registration VLAN:** the VLAN id from step 1.
   - **Portal address:** `REGISTRATION_PORTAL_IP` with its prefix
     (`10.99.0.1/24`).
   - **DHCP range:** inside the subnet, not including the portal address,
     the network or broadcast address, or `REGISTRATION_DOCKER_GATEWAY`.
   - **Approval mode, access hours, terms of use.**

   Tick **Run the portal** and **restart the app** (network settings apply at
   startup). The page then shows the interface it's running on and its
   active leases.

4. **RADIUS** (Panopticon → RADIUS / 802.1X): set **Unknown / unclassified
   device action** to **Registration portal**, and set the **guest VLAN**
   approved guests get. Give each switch or AP a **CoA mode**: without CoA, an
   approved guest only moves when they reconnect.

## Testing

`deploy/registration/test/run.sh` tests the DHCP server and captive DNS
(`crates/portal-net`) against real clients on a throwaway Docker network.
The clients are BusyBox `udhcpc` and `nslookup`. It checks:

- the lease, with router, DNS, mask, lease time and the RFC 8910 portal URL;
- the client's DHCP fingerprint is recorded;
- Apple's and Microsoft's captive-portal checks resolve to the portal;
- AAAA queries get no answer;
- the same client gets the same address again;
- an exhausted pool offers nothing rather than a clashing address.

The portal's web pages and the admin-UI guard have unit tests in
`crates/web/src/panopticon_portal.rs`.

Still to check in a lab: the macvlan attachment on a real VLAN, and the
captive sign-in sheet on iOS, Android, macOS and Windows.
