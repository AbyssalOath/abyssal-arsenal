# 802.1X with FreeRADIUS

Panopticon's embedded RADIUS server does MAC Authentication Bypass (MAB)
only. For real 802.1X logins it runs FreeRADIUS in front of it:
**FreeRADIUS authenticates, Panopticon decides.**

- **EAP-TLS** (certificate-based 802.1X): FreeRADIUS checks the client
  certificate against your CA, then asks Panopticon what the device gets,
  by its MAC. The answer is the same as for MAB: a VLAN, the quarantine
  VLAN, or a reject, from its trust state, the RADIUS policy and any
  enforcement on its switch port.
- **MAB**: devices without a supplicant still work. FreeRADIUS passes them
  to Panopticon, which decides as the embedded server does.
- **NAS clients** (switches, APs) stay on Panopticon's RADIUS page. FreeRADIUS
  fetches a NAS's shared secret from Panopticon the first time the NAS
  sends a packet (dynamic clients), and ignores a NAS that isn't listed.
- **Accounting** lands in Panopticon's sessions table, so **CoA** (the
  RADIUS page's per-NAS setting) keeps working.
- Anything else is rejected: a username/password login that isn't MAB has
  no password store to check it against.

How the pieces connect: FreeRADIUS runs in the **app container's network
namespace** (`network_mode: service:app`). It answers on the RADIUS ports the
app already publishes (UDP 1812/1813), and reaches Panopticon on
`127.0.0.1:8080`. Panopticon's `/internal/radius/*` endpoints answer only
loopback connections carrying the shared token, and don't exist unless
`FREERADIUS_API_TOKEN` is set. When it is set, Panopticon's embedded server
doesn't start, even if it's enabled on the RADIUS page, so the two never
fight over the ports.

## Setup

1. **Token.** Put one random value in `.env`, at least 32 characters:

   ```sh
   echo "FREERADIUS_API_TOKEN=$(openssl rand -hex 32)" >> .env
   ```

2. **Certificates.** Put three files in `deploy/freeradius/certs/` (they're
   git-ignored):

   | File | What |
   | --- | --- |
   | `server.pem` | FreeRADIUS's server certificate, plus any intermediates. Clients check it, so issue it from a CA they trust (often your AD CS) and configure that CA and the server name in the clients' 802.1X profile. |
   | `server.key` | Its private key, unencrypted. |
   | `ca.pem` | The CA(s) that issue your **client** certificates. Any client certificate chaining to it is accepted at the EAP layer. |

   FreeRADIUS runs as uid 101 inside its container, so it must be able to
   read them: `chmod 755 deploy/freeradius/certs && chmod 644
   deploy/freeradius/certs/*`. Keep the directory itself off-limits to
   other users on the host. If FreeRADIUS logs `Permission denied` for
   `server.key`, this is why.

3. **NAS clients.** On Panopticon's RADIUS page, add each switch or AP with
   its shared secret, and choose a CoA mode.

4. **Start it:**

   ```sh
   docker compose up -d app        # picks up FREERADIUS_API_TOKEN
   docker compose --profile freeradius up -d
   ```

   The RADIUS page then says FreeRADIUS is configured, and when it last
   called in. `docker logs abyssal-arsenal-freeradius` shows FreeRADIUS's
   side.

5. **Switches.** Point 802.1X and MAB at the control plane's address, as for
   the embedded server: authentication on 1812, accounting on 1813, and
   dynamic authorization (CoA) from the control plane on 3799. Cisco
   example:

   ```text
   radius server ABYSSAL
    address ipv4 <control-plane-ip> auth-port 1812 acct-port 1813
    key <shared secret>
   aaa server radius dynamic-author
    client <control-plane-ip> server-key <shared secret>
   ```

## Notes

- **Message-Authenticator (BlastRADIUS, CVE-2024-3596):** FreeRADIUS's
  default `auto` applies: once a NAS sends Message-Authenticator, every
  later request from it must carry one. Configure your NASes to send it.
- **During a backup restore** Panopticon refuses API calls, so new logins
  are rejected until the restore finishes. Established sessions stay up.
- **A failed call** to Panopticon (app down, timeout) rejects the request.
  The design fails closed.
- **PEAP/MSCHAPv2 against Active Directory** isn't set up. It needs
  FreeRADIUS joined to the domain with Samba/winbind (`ntlm_auth`), which
  this image doesn't include. EAP-TLS is the method to deploy, and it's
  what most 802.1X guidance recommends anyway.

## Testing this configuration

`deploy/freeradius/test/run.sh` runs this configuration in the real
FreeRADIUS image against a stand-in for Panopticon's API. The stand-in
(`test/fake_api.py`) implements the same contract and returns the same
JSON as `crates/web/src/panopticon_freeradius.rs`, and a unit test there
pins that JSON. The script checks: the config parses; MAB accept (with
VLAN) and reject; a non-MAB password login is rejected and its password
never reaches the API; a wrong NAS secret gets no answer; NAS names are
taken literally; accounting; EAP-TLS accepted with VLAN and correct MPPE
keys; EAP-TLS rejected by Panopticon's decision; EAP-TLS with an untrusted
client certificate rejected. It needs Docker and touches nothing outside
its own containers.
