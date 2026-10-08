//! SNMP polling (v1, v2c, or v3 -- `PanopticonSwitch::snmp_version`) of
//! managed switches for BRIDGE-MIB MAC-to-port data -- the mechanism that
//! gives Panopticon actual NAC-grade visibility (which physical switch
//! port a device's MAC currently sits behind), and the prerequisite for
//! any future bandwidth-per-port work.
//!
//! A poll only ever *enriches* a device Panopticon already knows about by
//! IP (active scan, passive `ip neigh` refresh, mDNS, or ARP sniffing) --
//! a MAC the switch's forwarding database reports that Panopticon has
//! never otherwise seen at the IP layer has no inventory row to attach a
//! port to, and this doesn't create one. Real switch/IP correlation would
//! need either DHCP lease data or ARP-table cross-referencing this phase
//! doesn't have; documented scope boundary, not an oversight.

use std::collections::HashMap;
use std::time::Duration;

use abyssal_core::{
    EncryptionKey, Permission, SnmpAuthProtocol, SnmpPrivProtocol, SnmpSecurityLevel, SnmpVersion,
};
use abyssal_database::{DbPool, repo};
use abyssal_execution::{
    ExecutionError, Operation, OperationKind, OperationOutput, OperationParams,
};
use chrono::Utc;
use snmp2::v3::{Auth, AuthProtocol, Cipher, Security};
use snmp2::{AsyncSession, Oid, Value};
use zeroize::Zeroizing;

/// Every SNMP request (not just the initial connect) gets this long before
/// the poll gives up on that switch -- an unreachable or firewalled switch
/// must never hang the whole sweep indefinitely, since `AsyncSession`
/// itself has no built-in timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Safety cap on how many rows a single table walk will collect --
/// protects against a pathological or hostile agent that never returns
/// `endOfMibView` from looping forever.
const MAX_WALK_ENTRIES: usize = 20_000;

const DOT1D_TP_FDB_PORT: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
const DOT1D_BASE_PORT_IF_INDEX: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];
const IF_DESCR: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2];
/// IF-MIB port-state columns (M2, read-only). `ifAdminStatus`/`ifOperStatus`
/// are INTEGER (decode to `OwnedValue::Integer`); `ifHighSpeed` (Mbps) and
/// the legacy `ifSpeed` (bps) are Gauge32, which shares SNMP's `Unsigned32`
/// ASN.1 tag and so decodes to `OwnedValue::Counter` in `walk_table`.
const IF_ADMIN_STATUS: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 7];
const IF_OPER_STATUS: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 8];
const IF_SPEED: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 5];
const IF_HIGH_SPEED: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15];
/// ifXTable's 64-bit "high capacity" counters (RFC 2863) -- preferred over
/// the legacy 32-bit ones below whenever a switch supports them, since a
/// 32-bit byte counter wraps roughly every 34 seconds at 1 Gbps line rate,
/// far faster than any reasonable poll interval can track reliably (see
/// `panopticon_traffic.rs::rates_from_raw`).
const IF_HC_IN_OCTETS: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6];
const IF_HC_OUT_OCTETS: &[u64] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10];
/// Legacy 32-bit fallback (RFC 1213) for a switch whose ifXTable doesn't
/// expose the HC counters above.
const IF_IN_OCTETS: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 10];
const IF_OUT_OCTETS: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 16];

/// Q-BRIDGE-MIB columns used by VLAN-quarantine enforcement (phase 3). All
/// indexed differently from IF-MIB: `dot1qPvid` by bridge port number (the
/// `dot1dBasePort` index, NOT ifIndex -- convert via `DOT1D_BASE_PORT_IF_INDEX`),
/// and the two `PortList` bitmaps by VLAN id (`dot1qVlanIndex`).
const DOT1Q_PVID: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 1];
const DOT1Q_VLAN_STATIC_EGRESS_PORTS: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 2];
const DOT1Q_VLAN_STATIC_UNTAGGED_PORTS: &[u64] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 4];

/// IF-MIB `ifAdminStatus` value for an administratively-up/down port.
const IF_ADMIN_UP: i64 = 1;
const IF_ADMIN_DOWN: i64 = 2;

#[derive(Debug, thiserror::Error)]
pub enum SnmpPollError {
    #[error("could not decrypt this switch's stored SNMP credentials: {0}")]
    Decrypt(#[from] abyssal_core::CryptoError),
    #[error("SNMP request to {0} timed out")]
    Timeout(String),
    #[error("SNMP error: {0}")]
    Protocol(String),
    #[error("SNMP I/O error: {0}")]
    Io(String),
    /// A switch row is missing a field its own `snmp_version` requires --
    /// should never happen given `switch_add`/`switch_edit`'s validation,
    /// but this is the last line of defense before treating a `None` as
    /// an empty credential instead of a config bug.
    #[error("switch is misconfigured for {0}: {1}")]
    Config(&'static str, String),
}

/// Decrypted, ready-to-use SNMP credentials for one poll -- built by
/// `poll_and_record` from the switch's encrypted-at-rest fields
/// immediately before use and never persisted or logged.
enum SnmpCredentials {
    V1(Zeroizing<String>),
    V2c(Zeroizing<String>),
    V3 {
        username: String,
        security_level: SnmpSecurityLevel,
        auth_protocol: SnmpAuthProtocol,
        auth_password: Option<Zeroizing<String>>,
        priv_protocol: SnmpPrivProtocol,
        priv_password: Option<Zeroizing<String>>,
    },
}

impl SnmpCredentials {
    /// Builds the `snmp2::v3::Security` this credential set describes.
    /// Only ever called for `SnmpCredentials::V3` -- see `poll_switch`.
    fn v3_security(
        username: &str,
        security_level: SnmpSecurityLevel,
        auth_protocol: SnmpAuthProtocol,
        auth_password: Option<&str>,
        priv_protocol: SnmpPrivProtocol,
        priv_password: Option<&str>,
    ) -> Result<Security, SnmpPollError> {
        let auth = match security_level {
            SnmpSecurityLevel::NoAuthNoPriv => Auth::NoAuthNoPriv,
            SnmpSecurityLevel::AuthNoPriv => Auth::AuthNoPriv,
            SnmpSecurityLevel::AuthPriv => {
                let privacy_password = priv_password.ok_or_else(|| {
                    SnmpPollError::Config("v3 authPriv", "missing privacy password".into())
                })?;
                Auth::AuthPriv {
                    cipher: match priv_protocol {
                        SnmpPrivProtocol::Des => Cipher::Des,
                        SnmpPrivProtocol::Aes128 => Cipher::Aes128,
                        SnmpPrivProtocol::Aes192 => Cipher::Aes192,
                        SnmpPrivProtocol::Aes256 => Cipher::Aes256,
                    },
                    privacy_password: privacy_password.as_bytes().to_vec(),
                }
            }
        };
        let auth_password = if security_level == SnmpSecurityLevel::NoAuthNoPriv {
            ""
        } else {
            auth_password.ok_or_else(|| {
                SnmpPollError::Config("v3 auth", "missing authentication password".into())
            })?
        };
        Ok(Security::new(username.as_bytes(), auth_password.as_bytes())
            .with_auth(auth)
            .with_auth_protocol(match auth_protocol {
                SnmpAuthProtocol::Md5 => AuthProtocol::Md5,
                SnmpAuthProtocol::Sha1 => AuthProtocol::Sha1,
                SnmpAuthProtocol::Sha224 => AuthProtocol::Sha224,
                SnmpAuthProtocol::Sha256 => AuthProtocol::Sha256,
                SnmpAuthProtocol::Sha384 => AuthProtocol::Sha384,
                SnmpAuthProtocol::Sha512 => AuthProtocol::Sha512,
            }))
    }
}

#[derive(Clone)]
enum OwnedValue {
    Integer(i64),
    OctetString(Vec<u8>),
    /// Unifies `Counter32`/`Unsigned32`/`Counter64` -- all three are just
    /// an unsigned magnitude as far as this module cares; only the OID
    /// walked (HC vs. legacy) determines whether a caller should treat a
    /// decrease as a 32-bit wrap or a reset.
    Counter(u64),
}

fn oid_suffix(oid: &Oid<'_>, base: &Oid<'_>) -> Option<Vec<u64>> {
    let full: Vec<u64> = oid.iter()?.collect();
    let base_v: Vec<u64> = base.iter()?.collect();
    if full.len() <= base_v.len() {
        return None;
    }
    Some(full[base_v.len()..].to_vec())
}

/// GETNEXT-walks every varbind under `base`, converting each to an owned
/// value immediately (a `snmp2::Value` borrows from the session's receive
/// buffer, which the next `getnext` call overwrites) and stopping either
/// at the first OID that falls outside `base`'s subtree or at
/// `MAX_WALK_ENTRIES`.
async fn walk_table(
    sess: &mut AsyncSession,
    base: &[u64],
    switch_addr: &str,
) -> Result<Vec<(Vec<u64>, OwnedValue)>, SnmpPollError> {
    let base_oid = Oid::from(base).expect("hand-written OID constant is well-formed");
    let mut results = Vec::new();
    let mut current = base_oid.clone();

    loop {
        let pdu = tokio::time::timeout(REQUEST_TIMEOUT, sess.getnext(&current))
            .await
            .map_err(|_| SnmpPollError::Timeout(switch_addr.to_string()))?
            .map_err(|e| SnmpPollError::Protocol(format!("{e:?}")))?;

        let mut advanced = false;
        for (oid, value) in pdu.varbinds {
            if !oid.starts_with(&base_oid) {
                continue;
            }
            let Some(suffix) = oid_suffix(&oid, &base_oid) else {
                continue;
            };
            let owned = match value {
                Value::Integer(n) => OwnedValue::Integer(n),
                Value::OctetString(bytes) => OwnedValue::OctetString(bytes.to_vec()),
                Value::Counter32(n) | Value::Unsigned32(n) => OwnedValue::Counter(u64::from(n)),
                Value::Counter64(n) => OwnedValue::Counter(n),
                _ => continue,
            };
            results.push((suffix, owned));
            current = oid.to_owned();
            advanced = true;
        }
        if !advanced || results.len() >= MAX_WALK_ENTRIES {
            break;
        }
    }
    Ok(results)
}

/// Polls one switch: BRIDGE-MIB's `dot1dTpFdbPort` (MAC -> bridge port
/// number) joined through `dot1dBasePortIfIndex` (bridge port -> ifIndex)
/// and IF-MIB's `ifDescr` (ifIndex -> human-readable port label), then
/// applies the resulting MAC -> port-label map to the inventory. Returns
/// the number of already-known devices this poll matched and updated.
async fn poll_switch(
    pool: &DbPool,
    switch: &abyssal_core::PanopticonSwitch,
    credentials: &SnmpCredentials,
) -> Result<usize, SnmpPollError> {
    let addr = format!("{}:{}", switch.ip_address, switch.snmp_port);
    let mut sess = connect(&addr, credentials).await?;

    let fdb = walk_table(&mut sess, DOT1D_TP_FDB_PORT, &addr).await?;
    let base_port_map = walk_table(&mut sess, DOT1D_BASE_PORT_IF_INDEX, &addr).await?;
    let if_descr_map = walk_table(&mut sess, IF_DESCR, &addr).await?;

    // bridge port number -> ifIndex
    let mut port_to_if: HashMap<i64, i64> = HashMap::new();
    for (suffix, value) in &base_port_map {
        if let (Some(&bridge_port), OwnedValue::Integer(if_index)) = (suffix.first(), value) {
            port_to_if.insert(bridge_port as i64, *if_index);
        }
    }
    // ifIndex -> ifDescr
    let mut if_to_descr: HashMap<i64, String> = HashMap::new();
    for (suffix, value) in &if_descr_map {
        if let (Some(&if_index), OwnedValue::OctetString(bytes)) = (suffix.first(), value) {
            if_to_descr.insert(if_index as i64, String::from_utf8_lossy(bytes).into_owned());
        }
    }

    repo::network_devices::clear_switch_location(pool, switch.id)
        .await
        .map_err(|e| SnmpPollError::Protocol(e.to_string()))?;

    let mut matched = 0usize;
    for (suffix, value) in &fdb {
        // dot1dTpFdbPort's index is the 6-octet MAC address itself.
        if suffix.len() != 6 {
            continue;
        }
        let OwnedValue::Integer(bridge_port) = value else {
            continue;
        };
        if *bridge_port == 0 {
            continue; // 0 means "not learned on any port"
        }
        let mac = suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let label = port_to_if
            .get(bridge_port)
            .and_then(|if_index| if_to_descr.get(if_index).cloned())
            .or_else(|| port_to_if.get(bridge_port).map(|idx| format!("if{idx}")))
            .unwrap_or_else(|| format!("port{bridge_port}"));

        match repo::network_devices::update_switch_location(pool, &mac, switch.id, &label).await {
            Ok(true) => matched += 1,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(error = %e, mac = %mac, switch = %switch.name, "failed to record switch location for device");
            }
        }
    }

    // Port-state (M2) and bandwidth collection both reuse this same
    // session/poll but are entirely best-effort: a switch that doesn't
    // support IF-MIB's status or octet columns (or a transient error
    // walking them) shouldn't take down FDB-based port matching above,
    // which already succeeded. Errors are logged, never propagated.
    collect_port_status(pool, &mut sess, switch, &addr, &if_to_descr).await;
    collect_port_traffic(pool, &mut sess, switch, &addr, &if_to_descr).await;

    Ok(matched)
}

/// Walks IF-MIB's `ifAdminStatus`, `ifOperStatus`, `ifHighSpeed` (Mbps) and
/// legacy `ifSpeed` (bps) and records each port's current state (M2). Purely
/// read-only visibility -- no SNMP SET is ever issued here. Best-effort like
/// `collect_port_traffic`: this runs after `poll_switch` has already matched
/// MACs to ports, so a failure walking status never undoes that work.
///
/// Status is recorded for every ifIndex the admin/oper walks return, not
/// just ports with a live device behind them -- an admin needs to see that
/// an *empty* port is admin-up (open for anyone to plug into) just as much
/// as a busy one.
async fn collect_port_status(
    pool: &DbPool,
    sess: &mut AsyncSession,
    switch: &abyssal_core::PanopticonSwitch,
    addr: &str,
    if_to_descr: &HashMap<i64, String>,
) {
    let admin = match walk_table(sess, IF_ADMIN_STATUS, addr).await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, switch = %switch.name, "failed to walk ifAdminStatus");
            return;
        }
    };
    let oper = match walk_table(sess, IF_OPER_STATUS, addr).await {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(error = %e, switch = %switch.name, "failed to walk ifOperStatus");
            return;
        }
    };
    // Speed is strictly optional -- a switch may expose status but not the
    // speed columns, which must not suppress the status we did read.
    let high_speed = walk_table(sess, IF_HIGH_SPEED, addr)
        .await
        .unwrap_or_default();
    let speed = walk_table(sess, IF_SPEED, addr).await.unwrap_or_default();

    let admin_map = integer_map(&admin);
    let oper_map = integer_map(&oper);
    let high_speed_map = counter_map(&high_speed);
    let speed_map = counter_map(&speed);

    // Every ifIndex either status walk reported -- the union, so a port that
    // somehow appears in only one of the two is still recorded.
    let mut if_indexes: Vec<i64> = admin_map.keys().chain(oper_map.keys()).copied().collect();
    if_indexes.sort_unstable();
    if_indexes.dedup();

    for if_index in if_indexes {
        // Prefer ifHighSpeed (already Mbps); fall back to ifSpeed (bps) only
        // when the HC column is absent or zero, and clamp the conversion to
        // u32 so a bogus giant counter can't overflow the column.
        let speed_mbps = match high_speed_map.get(&if_index).copied() {
            Some(mbps) if mbps > 0 => Some(mbps.min(u64::from(u32::MAX)) as u32),
            _ => speed_map
                .get(&if_index)
                .copied()
                .filter(|bps| *bps > 0)
                .map(|bps| (bps / 1_000_000).min(u64::from(u32::MAX)) as u32),
        };
        if let Err(e) = repo::panopticon_traffic::update_port_status(
            pool,
            switch.id,
            if_index as u32,
            if_to_descr.get(&if_index).map(String::as_str),
            admin_map.get(&if_index).copied(),
            oper_map.get(&if_index).copied(),
            speed_mbps,
        )
        .await
        {
            tracing::warn!(error = %e, switch = %switch.name, if_index, "failed to record port status");
        }
    }
}

/// Extracts a single-integer-suffix -> `Integer` walk result into a plain
/// `ifIndex -> code` map, ignoring anything not shaped that way.
fn integer_map(entries: &[(Vec<u64>, OwnedValue)]) -> HashMap<i64, i64> {
    let mut map = HashMap::new();
    for (suffix, value) in entries {
        if let (Some(&if_index), OwnedValue::Integer(n)) = (suffix.first(), value) {
            map.insert(if_index as i64, *n);
        }
    }
    map
}

/// Walks IF-MIB's 64-bit `ifHCIn/OutOctets`, falling back to the legacy
/// 32-bit `ifIn/OutOctets` when a switch's ifXTable doesn't expose them,
/// and records one raw sample per port Panopticon has ever seen ifDescr
/// for on this switch (`if_to_descr`, from the FDB-matching walk above --
/// not just ports with a live FDB entry, since a bandwidth graph is
/// useful for every port, including uplinks with no single device behind
/// them). Best-effort throughout: logs and moves on rather than failing
/// the whole poll, since this is strictly additive to what `poll_switch`
/// already accomplished by the time this runs.
async fn collect_port_traffic(
    pool: &DbPool,
    sess: &mut AsyncSession,
    switch: &abyssal_core::PanopticonSwitch,
    addr: &str,
    if_to_descr: &HashMap<i64, String>,
) {
    let hc_in = walk_table(sess, IF_HC_IN_OCTETS, addr).await;
    let hc_out = walk_table(sess, IF_HC_OUT_OCTETS, addr).await;

    let (in_map, out_map, bits): (HashMap<i64, u64>, HashMap<i64, u64>, u8) = match (hc_in, hc_out)
    {
        (Ok(hc_in), Ok(hc_out)) if !hc_in.is_empty() && !hc_out.is_empty() => {
            (counter_map(&hc_in), counter_map(&hc_out), 64)
        }
        _ => {
            let in32 = walk_table(sess, IF_IN_OCTETS, addr).await;
            let out32 = walk_table(sess, IF_OUT_OCTETS, addr).await;
            match (in32, out32) {
                (Ok(in32), Ok(out32)) => (counter_map(&in32), counter_map(&out32), 32),
                (Err(e), _) | (_, Err(e)) => {
                    tracing::warn!(error = %e, switch = %switch.name, "failed to walk IF-MIB octet counters");
                    return;
                }
            }
        }
    };

    let now = Utc::now();
    for (&if_index, &in_octets) in &in_map {
        let Some(&out_octets) = out_map.get(&if_index) else {
            continue;
        };
        let if_index_u32 = if_index as u32;
        if let Err(e) = repo::panopticon_traffic::upsert_port(
            pool,
            switch.id,
            if_index_u32,
            if_to_descr.get(&if_index).map(String::as_str),
        )
        .await
        {
            tracing::warn!(error = %e, switch = %switch.name, if_index, "failed to record switch port");
        }
        if let Err(e) = repo::panopticon_traffic::insert_raw_sample(
            pool,
            switch.id,
            if_index_u32,
            in_octets,
            out_octets,
            bits,
            now,
        )
        .await
        {
            tracing::warn!(error = %e, switch = %switch.name, if_index, "failed to record traffic sample");
        }
    }
}

/// Extracts a single-integer-suffix -> `Counter` walk result into a plain
/// `ifIndex -> value` map, ignoring anything that isn't shaped that way.
fn counter_map(entries: &[(Vec<u64>, OwnedValue)]) -> HashMap<i64, u64> {
    let mut map = HashMap::new();
    for (suffix, value) in entries {
        if let (Some(&if_index), OwnedValue::Counter(n)) = (suffix.first(), value) {
            map.insert(if_index as i64, *n);
        }
    }
    map
}

/// Builds this switch's `SnmpCredentials`, decrypting exactly the
/// ciphertext fields its `snmp_version` actually uses. A `None` where a
/// value is required (e.g. no `community_encrypted` on a v1/v2c switch)
/// means the row is misconfigured -- shouldn't happen given
/// `switch_add`/`switch_edit`'s validation, but this is the last line of
/// defense before treating it as an empty credential instead of a bug.
fn decrypt_credentials(
    switch: &abyssal_core::PanopticonSwitch,
    encryption_key: &EncryptionKey,
) -> Result<SnmpCredentials, SnmpPollError> {
    match switch.snmp_version {
        SnmpVersion::V1 | SnmpVersion::V2c => {
            let Some(community_encrypted) = &switch.community_encrypted else {
                return Err(SnmpPollError::Config(
                    "v1/v2c",
                    "missing community string".into(),
                ));
            };
            let community = encryption_key.decrypt(community_encrypted)?;
            Ok(if switch.snmp_version == SnmpVersion::V1 {
                SnmpCredentials::V1(community)
            } else {
                SnmpCredentials::V2c(community)
            })
        }
        SnmpVersion::V3 => {
            let Some(username) = &switch.snmp_v3_username else {
                return Err(SnmpPollError::Config("v3", "missing username".into()));
            };
            let security_level = switch.snmp_v3_security_level.unwrap_or_default();
            let auth_password = switch
                .snmp_v3_auth_password_encrypted
                .as_deref()
                .map(|enc| encryption_key.decrypt(enc))
                .transpose()?;
            let priv_password = switch
                .snmp_v3_priv_password_encrypted
                .as_deref()
                .map(|enc| encryption_key.decrypt(enc))
                .transpose()?;
            Ok(SnmpCredentials::V3 {
                username: username.clone(),
                security_level,
                auth_protocol: switch.snmp_v3_auth_protocol.unwrap_or_default(),
                auth_password,
                priv_protocol: switch.snmp_v3_priv_protocol.unwrap_or_default(),
                priv_password,
            })
        }
    }
}

/// Decrypts whichever of `switch`'s credential fields its `snmp_version`
/// actually uses and polls it, recording the outcome (success or error
/// message) on the switch row either way. Shared by the manual "Poll now"
/// action (`SnmpPollOperation`) and the unattended SNMP sweep
/// (`spawn_panopticon_snmp_sweep`).
pub async fn poll_and_record(
    pool: &DbPool,
    switch: &abyssal_core::PanopticonSwitch,
    encryption_key: &EncryptionKey,
) -> Result<usize, SnmpPollError> {
    let credentials = decrypt_credentials(switch, encryption_key)?;
    let result = poll_switch(pool, switch, &credentials).await;
    let error_message = result.as_ref().err().map(ToString::to_string);
    if let Err(e) =
        repo::panopticon_switches::record_poll_result(pool, switch.id, error_message.as_deref())
            .await
    {
        tracing::error!(error = %e, switch = %switch.name, "failed to record poll result");
    }
    result
}

// =====================================================================
// NAC enforcement (phase 3): SNMP SET primitives + port disable / VLAN
// quarantine. Everything below *writes* to a live switch; it is only ever
// reached after the caller (abyssal_web::panopticon_enforcement) has checked
// the global kill-switch, the per-switch opt-in, and the operator's
// permission. `snmp2`'s `set` returns Ok even when the switch rejects the
// write (read-only community, noAccess), so every SET here checks the
// response PDU's `error_status` itself -- that check is what distinguishes
// "the write landed" from "the switch said no".
// =====================================================================

/// Opens an `AsyncSession` for this switch over whichever SNMP version its
/// credentials describe. Shared by the read-only poll and the enforcement
/// writes so both connect identically.
async fn connect(addr: &str, credentials: &SnmpCredentials) -> Result<AsyncSession, SnmpPollError> {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        match credentials {
            SnmpCredentials::V1(community) => {
                AsyncSession::new_v1(addr.to_string(), community.as_bytes(), 1).await
            }
            SnmpCredentials::V2c(community) => {
                AsyncSession::new_v2c(addr.to_string(), community.as_bytes(), 1).await
            }
            SnmpCredentials::V3 {
                username,
                security_level,
                auth_protocol,
                auth_password,
                priv_protocol,
                priv_password,
            } => {
                let security = SnmpCredentials::v3_security(
                    username,
                    *security_level,
                    *auth_protocol,
                    auth_password.as_deref().map(|s| s.as_str()),
                    *priv_protocol,
                    priv_password.as_deref().map(|s| s.as_str()),
                )
                .map_err(|e| std::io::Error::other(e.to_string()))?;
                AsyncSession::new_v3(addr.to_string(), 1, security).await
            }
        }
    })
    .await
    .map_err(|_| SnmpPollError::Timeout(addr.to_string()))?
    .map_err(|e| SnmpPollError::Io(e.to_string()))
}

/// Builds an instance OID (a column base plus its trailing instance sub-ids).
fn instance_oid(base: &[u64], instance: &[u64]) -> Vec<u64> {
    let mut v = Vec::with_capacity(base.len() + instance.len());
    v.extend_from_slice(base);
    v.extend_from_slice(instance);
    v
}

/// SNMP GET of a single scalar/instance OID, returned as an `OwnedValue`.
/// Treats a non-zero `error_status` or a v2c exception value (`noSuchObject`/
/// `noSuchInstance`/`endOfMibView`) as an error rather than silently yielding
/// nothing -- the enforcement path must know for certain it read real prior
/// state before it overwrites it.
async fn snmp_get(
    sess: &mut AsyncSession,
    oid_parts: &[u64],
    addr: &str,
) -> Result<OwnedValue, SnmpPollError> {
    let oid = Oid::from(oid_parts).map_err(|e| SnmpPollError::Protocol(format!("{e:?}")))?;
    let pdu = tokio::time::timeout(REQUEST_TIMEOUT, sess.get(&oid))
        .await
        .map_err(|_| SnmpPollError::Timeout(addr.to_string()))?
        .map_err(|e| SnmpPollError::Protocol(format!("{e:?}")))?;
    if pdu.error_status != 0 {
        return Err(SnmpPollError::Protocol(format!(
            "GET {oid_parts:?} returned error-status {}",
            pdu.error_status
        )));
    }
    let mut varbinds = pdu.varbinds;
    let Some((_oid, value)) = varbinds.next() else {
        return Err(SnmpPollError::Protocol(format!(
            "GET {oid_parts:?} returned an empty response"
        )));
    };
    match value {
        Value::Integer(n) => Ok(OwnedValue::Integer(n)),
        Value::OctetString(bytes) => Ok(OwnedValue::OctetString(bytes.to_vec())),
        Value::Counter32(n) | Value::Unsigned32(n) => Ok(OwnedValue::Counter(u64::from(n))),
        Value::Counter64(n) => Ok(OwnedValue::Counter(n)),
        Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => Err(
            SnmpPollError::Protocol(format!("{oid_parts:?} has no such instance on this switch")),
        ),
        other => Err(SnmpPollError::Protocol(format!(
            "{oid_parts:?} returned an unexpected type: {other:?}"
        ))),
    }
}

/// Convenience wrapper: GET an OID that must be an INTEGER.
async fn snmp_get_int(
    sess: &mut AsyncSession,
    oid_parts: &[u64],
    addr: &str,
) -> Result<i64, SnmpPollError> {
    match snmp_get(sess, oid_parts, addr).await? {
        OwnedValue::Integer(n) => Ok(n),
        other => {
            let _ = other;
            Err(SnmpPollError::Protocol(format!(
                "{oid_parts:?} was expected to be an integer but wasn't"
            )))
        }
    }
}

/// Issues one SNMP SET and verifies the switch accepted it. A non-zero
/// `error_status` in the response (readOnly, noAccess, wrongValue, etc.) is the
/// normal way a switch refuses a write it doesn't permit, and `snmp2` surfaces
/// that only through the returned PDU -- never as a transport error -- so this
/// is the sole place that refusal is detected.
async fn snmp_set(
    sess: &mut AsyncSession,
    varbinds: &[(&Oid<'_>, Value<'_>)],
    addr: &str,
    what: &str,
) -> Result<(), SnmpPollError> {
    let pdu = tokio::time::timeout(REQUEST_TIMEOUT, sess.set(varbinds))
        .await
        .map_err(|_| SnmpPollError::Timeout(addr.to_string()))?
        .map_err(|e| SnmpPollError::Protocol(format!("{e:?}")))?;
    if pdu.error_status != 0 {
        return Err(SnmpPollError::Protocol(format!(
            "switch rejected SET of {what} (SNMP error-status {}, index {}) -- \
             the stored SNMP credentials likely lack write access",
            pdu.error_status, pdu.error_index
        )));
    }
    Ok(())
}

/// Finds the BRIDGE-MIB bridge port number (`dot1dBasePort`, the index
/// Q-BRIDGE columns use) for an IF-MIB `ifIndex`, by walking
/// `dot1dBasePortIfIndex` and inverting it. VLAN quarantine needs this because
/// `dot1qPvid` and the `PortList` bitmaps are keyed by bridge port, not ifIndex.
async fn bridge_port_for_ifindex(
    sess: &mut AsyncSession,
    addr: &str,
    if_index: u32,
) -> Result<u32, SnmpPollError> {
    let map = walk_table(sess, DOT1D_BASE_PORT_IF_INDEX, addr).await?;
    for (suffix, value) in map {
        if let (Some(&bridge_port), OwnedValue::Integer(idx)) = (suffix.first(), &value)
            && *idx == i64::from(if_index)
        {
            return Ok(bridge_port as u32);
        }
    }
    Err(SnmpPollError::Protocol(format!(
        "no bridge port maps to ifIndex {if_index} on this switch -- cannot locate it for VLAN ops"
    )))
}

/// RFC 2674 `PortList`: a bitmap over bridge port numbers where port N is bit
/// (N-1), the most-significant bit of each octet being the lowest-numbered
/// port. Grows `bytes` as needed when setting a high port. Returns whether the
/// bitmap actually changed (so a no-op write can be skipped).
fn portlist_set(bytes: &mut Vec<u8>, bridge_port: u32, on: bool) -> bool {
    if bridge_port == 0 {
        return false;
    }
    let bit = bridge_port - 1;
    let byte_idx = (bit / 8) as usize;
    let mask = 0x80u8 >> (bit % 8);
    if on {
        if byte_idx >= bytes.len() {
            bytes.resize(byte_idx + 1, 0);
        }
        let before = bytes[byte_idx];
        bytes[byte_idx] |= mask;
        bytes[byte_idx] != before
    } else {
        if byte_idx >= bytes.len() {
            return false; // bit already clear (beyond the bitmap)
        }
        let before = bytes[byte_idx];
        bytes[byte_idx] &= !mask;
        bytes[byte_idx] != before
    }
}

/// Reads a VLAN's `PortList` bitmap, flips this bridge port's bit, and writes
/// it back -- the read-modify-write both quarantine and its revert need for
/// the static egress and untagged port maps. A GET that finds no such VLAN
/// row is an error (the quarantine VLAN must already exist); a write that
/// wouldn't change anything is skipped.
async fn edit_vlan_portlist(
    sess: &mut AsyncSession,
    addr: &str,
    base: &[u64],
    vlan: u32,
    bridge_port: u32,
    on: bool,
    what: &str,
) -> Result<(), SnmpPollError> {
    let oid_parts = instance_oid(base, &[u64::from(vlan)]);
    let mut bytes = match snmp_get(sess, &oid_parts, addr).await? {
        OwnedValue::OctetString(b) => b,
        _ => {
            return Err(SnmpPollError::Protocol(format!(
                "{what} for VLAN {vlan} was not a PortList octet string"
            )));
        }
    };
    if !portlist_set(&mut bytes, bridge_port, on) {
        return Ok(()); // already in the desired state
    }
    let oid =
        Oid::from(oid_parts.as_slice()).map_err(|e| SnmpPollError::Protocol(format!("{e:?}")))?;
    snmp_set(sess, &[(&oid, Value::OctetString(&bytes))], addr, what).await
}

/// Decrypts the switch's credentials and opens a session -- the shared prologue
/// of every enforcement entry point below.
async fn connect_for(
    switch: &abyssal_core::PanopticonSwitch,
    encryption_key: &EncryptionKey,
) -> Result<(AsyncSession, String), SnmpPollError> {
    let credentials = decrypt_credentials(switch, encryption_key)?;
    let addr = format!("{}:{}", switch.ip_address, switch.snmp_port);
    let sess = connect(&addr, &credentials).await?;
    Ok((sess, addr))
}

/// Disables a port (`ifAdminStatus` = down) after snapshotting its current
/// admin status, which is returned so the caller can persist it for an exact
/// revert. If the port is already administratively down, its real prior value
/// is still returned and the SET is a harmless no-op the switch accepts.
pub async fn enforce_disable_port(
    switch: &abyssal_core::PanopticonSwitch,
    encryption_key: &EncryptionKey,
    if_index: u32,
) -> Result<i64, SnmpPollError> {
    let (mut sess, addr) = connect_for(switch, encryption_key).await?;
    let admin_oid = instance_oid(IF_ADMIN_STATUS, &[u64::from(if_index)]);
    let original = snmp_get_int(&mut sess, &admin_oid, &addr).await?;
    let oid =
        Oid::from(admin_oid.as_slice()).map_err(|e| SnmpPollError::Protocol(format!("{e:?}")))?;
    snmp_set(
        &mut sess,
        &[(&oid, Value::Integer(IF_ADMIN_DOWN))],
        &addr,
        "ifAdminStatus = down",
    )
    .await?;
    Ok(original)
}

/// Restores a previously-disabled port's `ifAdminStatus` to its snapshotted
/// value (or `up` if the snapshot was itself down/unknown -- a port reverted to
/// "down" would defeat the revert, so `up` is the floor).
pub async fn revert_disable_port(
    switch: &abyssal_core::PanopticonSwitch,
    encryption_key: &EncryptionKey,
    if_index: u32,
    restore_to: Option<i64>,
) -> Result<(), SnmpPollError> {
    let (mut sess, addr) = connect_for(switch, encryption_key).await?;
    let target = match restore_to {
        Some(s) if s == IF_ADMIN_UP || s == IF_ADMIN_DOWN || s == 3 => s,
        _ => IF_ADMIN_UP,
    };
    // Never restore to "down" -- that's not a revert. Fall back to up.
    let target = if target == IF_ADMIN_DOWN {
        IF_ADMIN_UP
    } else {
        target
    };
    let admin_oid = instance_oid(IF_ADMIN_STATUS, &[u64::from(if_index)]);
    let oid =
        Oid::from(admin_oid.as_slice()).map_err(|e| SnmpPollError::Protocol(format!("{e:?}")))?;
    snmp_set(
        &mut sess,
        &[(&oid, Value::Integer(target))],
        &addr,
        "ifAdminStatus (revert)",
    )
    .await
}

/// Moves a port onto the quarantine VLAN: snapshots the port's current PVID,
/// sets `dot1qPvid` to `quarantine_vlan`, and adds the bridge port to that
/// VLAN's static egress + untagged `PortList`s so traffic actually flows
/// untagged on it. Returns the original PVID for an exact revert. Vendor
/// support for these Q-BRIDGE writes varies; a switch that refuses any step
/// surfaces as an error and the caller records the action as failed.
pub async fn enforce_quarantine_port(
    switch: &abyssal_core::PanopticonSwitch,
    encryption_key: &EncryptionKey,
    if_index: u32,
    quarantine_vlan: u32,
) -> Result<i64, SnmpPollError> {
    let (mut sess, addr) = connect_for(switch, encryption_key).await?;
    let bridge_port = bridge_port_for_ifindex(&mut sess, &addr, if_index).await?;

    let pvid_oid = instance_oid(DOT1Q_PVID, &[u64::from(bridge_port)]);
    let original_pvid = snmp_get_int(&mut sess, &pvid_oid, &addr).await?;

    // Add the port to the quarantine VLAN's egress + untagged sets first, so it
    // has somewhere to land before its PVID points there.
    edit_vlan_portlist(
        &mut sess,
        &addr,
        DOT1Q_VLAN_STATIC_EGRESS_PORTS,
        quarantine_vlan,
        bridge_port,
        true,
        "quarantine VLAN egress ports",
    )
    .await?;
    edit_vlan_portlist(
        &mut sess,
        &addr,
        DOT1Q_VLAN_STATIC_UNTAGGED_PORTS,
        quarantine_vlan,
        bridge_port,
        true,
        "quarantine VLAN untagged ports",
    )
    .await?;

    let oid =
        Oid::from(pvid_oid.as_slice()).map_err(|e| SnmpPollError::Protocol(format!("{e:?}")))?;
    snmp_set(
        &mut sess,
        &[(&oid, Value::Integer(i64::from(quarantine_vlan)))],
        &addr,
        "dot1qPvid = quarantine VLAN",
    )
    .await?;
    Ok(original_pvid)
}

/// Reverses a quarantine: restores the port's original PVID and removes the
/// bridge port from the quarantine VLAN's egress + untagged `PortList`s. PVID
/// is restored first so the port is back on its real VLAN before it's pulled
/// from the quarantine one.
pub async fn revert_quarantine_port(
    switch: &abyssal_core::PanopticonSwitch,
    encryption_key: &EncryptionKey,
    if_index: u32,
    restore_pvid: Option<i64>,
    quarantine_vlan: u32,
) -> Result<(), SnmpPollError> {
    let (mut sess, addr) = connect_for(switch, encryption_key).await?;
    let bridge_port = bridge_port_for_ifindex(&mut sess, &addr, if_index).await?;

    if let Some(pvid) = restore_pvid
        && pvid > 0
    {
        let pvid_oid = instance_oid(DOT1Q_PVID, &[u64::from(bridge_port)]);
        let oid = Oid::from(pvid_oid.as_slice())
            .map_err(|e| SnmpPollError::Protocol(format!("{e:?}")))?;
        snmp_set(
            &mut sess,
            &[(&oid, Value::Integer(pvid))],
            &addr,
            "dot1qPvid (revert)",
        )
        .await?;
    }
    edit_vlan_portlist(
        &mut sess,
        &addr,
        DOT1Q_VLAN_STATIC_UNTAGGED_PORTS,
        quarantine_vlan,
        bridge_port,
        false,
        "quarantine VLAN untagged ports (revert)",
    )
    .await?;
    edit_vlan_portlist(
        &mut sess,
        &addr,
        DOT1Q_VLAN_STATIC_EGRESS_PORTS,
        quarantine_vlan,
        bridge_port,
        false,
        "quarantine VLAN egress ports (revert)",
    )
    .await?;
    Ok(())
}

/// Manual, admin-triggered "Poll now" for one switch -- gated by
/// `Executor`'s permission machinery like every other Panopticon
/// operation. `Write`, not `Destructive`: this only ever reads from the
/// switch and writes to Panopticon's own inventory, nothing sent anywhere
/// risks tripping intrusion detection the way an nmap scan can.
pub struct SnmpPollOperation {
    pub pool: DbPool,
    pub switch: abyssal_core::PanopticonSwitch,
    pub encryption_key: std::sync::Arc<EncryptionKey>,
}

#[async_trait::async_trait]
impl Operation for SnmpPollOperation {
    fn name(&self) -> &str {
        "panopticon.snmp_poll"
    }

    fn kind(&self) -> OperationKind {
        OperationKind::Write
    }

    fn required_permission(&self) -> Permission {
        Permission::NetworkScan
    }

    async fn run(&self, _params: &OperationParams) -> Result<OperationOutput, ExecutionError> {
        match poll_and_record(&self.pool, &self.switch, &self.encryption_key).await {
            Ok(matched) => Ok(OperationOutput {
                stdout: format!(
                    "Polled \"{}\": {matched} known device(s) matched to a port.",
                    self.switch.name
                ),
                stderr: String::new(),
                exit_code: Some(0),
            }),
            Err(e) => Err(ExecutionError::Failed(e.to_string())),
        }
    }
}

const SNMP_SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Spawns the unattended SNMP sweep -- every `SNMP_SWEEP_INTERVAL`, polls
/// every enabled switch in turn. Does nothing (no-ops the whole tick) when
/// no `ENCRYPTION_KEY` is configured, since there's then no way to decrypt
/// any switch's stored community string; a deployment that never sets
/// `ENCRYPTION_KEY` and never adds a switch pays nothing for this loop
/// beyond one settings read every 5 minutes.
pub fn spawn_panopticon_snmp_sweep(
    pool: DbPool,
    encryption_key: Option<std::sync::Arc<EncryptionKey>>,
    heartbeats: crate::task_health::TaskHeartbeats,
) {
    use crate::task_health::names;
    const SNMP_SWEEP_INTERVAL_SECS: u64 = 5 * 60;
    tokio::spawn(async move {
        heartbeats
            .register(names::PANOPTICON_SNMP_SWEEP, SNMP_SWEEP_INTERVAL_SECS)
            .await;
        let mut interval = tokio::time::interval(SNMP_SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            // Beat at the top: alive even with no encryption key / no switches.
            heartbeats
                .ok(names::PANOPTICON_SNMP_SWEEP, SNMP_SWEEP_INTERVAL_SECS)
                .await;

            let Some(key) = &encryption_key else {
                continue;
            };

            let switches = match repo::panopticon_switches::list_enabled(&pool).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "SNMP sweep failed to list switches");
                    continue;
                }
            };

            for switch in switches {
                match poll_and_record(&pool, &switch, key).await {
                    Ok(matched) => {
                        tracing::info!(switch = %switch.name, matched, "SNMP sweep polled switch");
                    }
                    Err(e) => {
                        tracing::warn!(switch = %switch.name, error = %e, "SNMP sweep failed to poll switch");
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portlist_sets_the_right_bit_msb_first() {
        // Bridge port 1 is the MSB of the first octet (RFC 2674).
        let mut b = Vec::new();
        assert!(portlist_set(&mut b, 1, true));
        assert_eq!(b, vec![0b1000_0000]);
        // Port 8 is the LSB of the first octet.
        let mut b = Vec::new();
        assert!(portlist_set(&mut b, 8, true));
        assert_eq!(b, vec![0b0000_0001]);
        // Port 9 starts a second octet (MSB).
        let mut b = Vec::new();
        assert!(portlist_set(&mut b, 9, true));
        assert_eq!(b, vec![0, 0b1000_0000]);
    }

    #[test]
    fn portlist_grows_and_clears_without_touching_neighbors() {
        let mut b = vec![0b0000_0000];
        // Set ports 2 and 3, leave the rest alone.
        portlist_set(&mut b, 2, true);
        portlist_set(&mut b, 3, true);
        assert_eq!(b, vec![0b0110_0000]);
        // Clearing port 2 leaves port 3 set.
        assert!(portlist_set(&mut b, 2, false));
        assert_eq!(b, vec![0b0010_0000]);
        // Clearing a bit already clear reports no change.
        assert!(!portlist_set(&mut b, 2, false));
    }

    #[test]
    fn portlist_clear_beyond_bitmap_is_a_noop() {
        let mut b = vec![0b1000_0000];
        // Port 50 isn't even in the one-octet bitmap; clearing it changes nothing.
        assert!(!portlist_set(&mut b, 50, false));
        assert_eq!(b, vec![0b1000_0000]);
    }

    #[test]
    fn portlist_ignores_bridge_port_zero() {
        let mut b = Vec::new();
        assert!(!portlist_set(&mut b, 0, true));
        assert!(b.is_empty());
    }

    #[test]
    fn instance_oid_appends_the_instance() {
        assert_eq!(
            instance_oid(IF_ADMIN_STATUS, &[12]),
            vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 12]
        );
    }
}
