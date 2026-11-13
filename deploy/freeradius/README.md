# 802.1X with FreeRADIUS

Panopticon's embedded RADIUS server does MAC Authentication Bypass (MAB)
only. For real 802.1X logins it runs FreeRADIUS in front of it:
**FreeRADIUS authenticates, Panopticon decides.**

- **EAP-TLS** (certificate-based 802.1X): FreeRADIUS checks the client
  certificate against your CA, then asks Panopticon what the device gets,
  by its MAC. The answer is the same as for MAB: a VLAN, the quarantine
  VLAN, or a reject, from its trust state, the RADIUS policy and any
  enforcement on its switch port.
- **PEAP/MSCHAPv2 against Active Directory** (domain username and
  password, or the computer's own account): FreeRADIUS joins your domain
  and checks each login with a domain controller, optionally only for
  members of one group. Then Panopticon decides by MAC, as for EAP-TLS.
  Off until you set `AD_REALM`; see
  [PEAP against Active Directory](#peap-against-active-directory).
- **MAB**: devices without a supplicant still work. FreeRADIUS passes them
  to Panopticon, which decides as the embedded server does.
- **Roles** (ACL or user-role names) go out as `Filter-Id` or
  `Aruba-User-Role`, per NAS client's *role attribute* on the RADIUS page.
  FreeRADIUS tells Panopticon which NAS asked (the packet's source
  address), so each NAS gets the attribute it understands.
- **Security signals** (Cadavault posture, open Thanatos events, Scourge
  alerts) are checked by Panopticon at every login that reaches it, MAB and
  EAP alike, when they're turned on on the RADIUS page.
- **Session-Timeout** (with *Termination-Action = RADIUS-Request*) goes out
  per outcome when set on the RADIUS page, so NAS clients re-authenticate
  and pick up policy changes without CoA.
- **NAS clients** (switches, APs) stay on Panopticon's RADIUS page. FreeRADIUS
  fetches a NAS's shared secret from Panopticon the first time the NAS
  sends a packet (dynamic clients), and ignores a NAS that isn't listed.
- **Accounting** lands in Panopticon's sessions table, so **CoA** (the
  RADIUS page's per-NAS setting) keeps working.
- Anything else is rejected: a plain username/password login (PAP) that
  isn't MAB has no password store to check it against, and PEAP is
  rejected while no domain is configured.

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
   | `ca.pem` | The CA(s) that issue your **client** certificates. Any client certificate chaining to it is accepted at the EAP layer. Needed even for PEAP only: then use the CA that issued `server.pem`. |

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
   docker compose --profile freeradius up -d --build
   ```

   The FreeRADIUS image is built locally the first time
   (`deploy/freeradius/image`: the official 3.2.7 image plus Samba's
   winbind, for PEAP). `--build` also rebuilds it after an update.

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
- **EAP-TLS or PEAP?** EAP-TLS is stronger (no password to phish, and
  nothing for Credential Guard to block) and is what most 802.1X guidance
  recommends. PEAP is the practical choice when clients don't have
  certificates yet.

## PEAP against Active Directory

FreeRADIUS joins your domain as a computer account (`ABYSSAL-RADIUS` by
default) and checks each PEAP login with a domain controller, through
Samba's winbind and `ntlm_auth`. No password or hash is stored here. A
login succeeds when the password is right, the account is enabled, and
(if you set `AD_REQUIRE_GROUP`) it's in that group, nested groups
included. Then Panopticon decides the device's VLAN, quarantine or reject
by its MAC, exactly as for EAP-TLS. Both user logins (`alice`,
`CORP\alice`, `alice@corp.example.com`) and computer logins
(`host/pc1.corp.example.com`, Windows' "computer authentication") work.

### Before you start

- **DNS:** the Docker host must resolve your AD domain, including its SRV
  records (`_ldap._tcp.dc._msdcs.<domain>`). Usually that means the host
  uses your DCs (or a resolver that forwards to them) as its DNS servers.
  Check with `getent hosts <domain>` on the host.
- **Time:** Kerberos needs the host's clock within 5 minutes of the DCs.
  Run NTP (chrony or systemd-timesyncd) on the host, ideally against
  your DCs.
- **Network:** the host must reach the DCs on TCP/UDP 53, 88 and 389,
  TCP 445, 464 and 135, and the RPC high ports (49152-65535).
- **An account allowed to join computers**: a Domain Admin, or an account
  delegated "Create computer objects" on the target OU. It's needed only
  for the first start.
- **The server certificate** (`certs/server.pem`) must chain to a CA your
  Windows clients trust (AD CS is the easy way), and its name goes in
  their 802.1X profile. Without it, Windows refuses to send the password,
  or worse, users learn to click through the warning.

### Setup

1. Add to `.env`:

   ```sh
   AD_REALM=corp.example.com
   AD_WORKGROUP=CORP                 # NetBIOS domain name; default: first label of AD_REALM
   AD_NETBIOS_NAME=ABYSSAL-RADIUS    # the computer account, 15 characters max
   AD_REQUIRE_GROUP=CORP\WiFi-Users  # optional; no quotes
   AD_DC=                            # optional: dc1.corp.example.com,dc2.corp.example.com
   AD_JOIN_USER=svc-radius-join
   AD_JOIN_PASSWORD=...
   AD_JOIN_OU=                       # optional, e.g. Servers/RADIUS
   ```

2. Start (or restart) FreeRADIUS:

   ```sh
   docker compose --profile freeradius up -d --build
   docker logs abyssal-arsenal-freeradius 2>&1 | grep abyssal-freeradius
   ```

   You should see `joined`, then `domain trust OK`. If it says the join
   failed, the lines above it are Samba's reason. The usual causes are DNS,
   the clock, or the join account's rights.

3. **Remove `AD_JOIN_PASSWORD`** (and `AD_JOIN_USER`) from `.env`, and
   run the same `up -d` again. The join is kept in the
   `abyssal_freeradius_samba` volume. Later starts log `already joined`.

4. **Windows clients** (Group Policy → Computer Configuration → Policies →
   Windows Settings → Security Settings → Wired Network (IEEE 802.3)
   Policies, and the same under Wireless Network for Wi-Fi):
   - Authentication method: **Microsoft: Protected EAP (PEAP)**, inner
     method **Secured password (EAP-MSCHAP v2)**, with "Automatically use
     my Windows logon name and password" ticked.
   - **Verify the server's identity**: tick your root CA, and put
     `server.pem`'s name under "Connect to these servers".
   - Authentication mode: **User or computer authentication**. The
     computer authenticates at boot and the user at logon, so logon
     scripts and GPOs work before anyone signs in.
   - The **Wired AutoConfig** service (`dot3svc`) must run, for wired
     clients.

### VLAN by AD group

On Panopticon's RADIUS page, **VLAN by AD group** maps groups to VLANs:
`CORP\Staff` → 20, `CORP\Finance` → 30, `Domain Computers` → 40. For each
PEAP login, the first rule (in order) whose group the user or computer is
in chooses the VLAN, nested membership included. A plain `Group` matches
that name in any domain.

A rule only chooses the VLAN of a device that would be admitted anyway. A
quarantined or disabled port or device, an *Untrusted* device, and an
unknown device under *Reject* get what they'd get without the rule. MAB
and EAP-TLS logins don't use the rules.

How it works: inside the PEAP tunnel, after the password check,
FreeRADIUS asks Panopticon which groups the rules name, checks the login's
membership of just those (`abyssal-ad-groups`, through winbind), and
passes the ones that match to Panopticon's decision. They travel in
internal attributes (`image/dictionary.abyssal`), which a switch or a
client can't send. If the lookup fails, the login still succeeds, with its
device's VLAN.

With **User or computer authentication** on Windows, the computer logs in
at boot (with its groups, such as `Domain Computers`) and the user at
logon (with theirs), so a PC can move VLAN at logon. A rule change applies
at each device's next login; **Reauthorize** a session to apply it now.

### Things to know

- **Credential Guard** (on by default on Windows 11 22H2+ Enterprise and
  Education) blocks single sign-on for PEAP/MSCHAPv2: *user* logins with
  saved Windows credentials fail, while computer authentication still
  works. If your fleet has Credential Guard, use computer authentication,
  or move to EAP-TLS, which Credential Guard doesn't affect.
- **NTLM must be allowed**: MSCHAPv2 is NTLM-based. If you restrict NTLM by
  GPO ("Network security: Restrict NTLM"), add the RADIUS computer account
  as an exception on the DCs. Windows DCs allow it by default. A **Samba**
  DC needs `ntlm auth = mschapv2-and-ntlmv2-only` in its `smb.conf`.
- **The computer account's password** rotates automatically (winbind does
  that, as Windows does). If someone deletes or resets `ABYSSAL-RADIUS` in
  AD, logins fail with a trust error: put the join account back in `.env`,
  `docker volume rm abyssal-arsenal_abyssal_freeradius_samba`, and start
  again.
- **If winbindd stops**, the container exits and Docker restarts it.
  While it's down, PEAP logins are rejected (fail closed). EAP-TLS and MAB
  don't depend on it.
- **Group changes** take effect at the user's next login, within winbind's
  cache time (a few minutes).
- **Accounts that can't log in** (disabled, locked out, expired password)
  are rejected. "Must change password at next logon" is also rejected:
  there are no password changes over RADIUS.

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
client certificate rejected; PEAP rejected while no domain is
configured; a role reaching the NAS as `Filter-Id` (MAB) and as
`Aruba-User-Role` (EAP-TLS), a re-authenticating `Session-Timeout`, and
the NAS's address reaching Panopticon. It needs Docker and touches
nothing outside its own containers.

`deploy/freeradius/test/run-ad.sh` tests PEAP against a **real Samba AD
domain controller** in a throwaway container. FreeRADIUS joins it, then
`eapol_test` logs in. It checks: the join and trust; PEAP accept with
VLAN and correct MPPE keys; the real login, not the anonymous identity,
reaching Panopticon; `DOMAIN\user` and `user@realm`; wrong password,
unknown user and a user outside `AD_REQUIRE_GROUP` rejected; Panopticon's
reject winning over a good password; a computer login; a restart that
reuses the join without the join password; and the join password never
appearing in the logs. It also covers VLAN by AD group: direct and nested
groups that have a rule reach Panopticon and others don't, the group's
VLAN comes back, a computer brings its own groups, and a failing group
lookup leaves the login to its device's VLAN.

Both scripts stand in for Panopticon. The other half, Panopticon's real
decisions against a real database, is `deploy/test/radius-e2e.sh`: the
app is configured through its own forms, then asked through the
FreeRADIUS API (as this configuration calls it) and through the embedded
server, by `radclient`.
