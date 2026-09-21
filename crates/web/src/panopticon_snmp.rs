//! SNMP v2c polling of managed switches for BRIDGE-MIB MAC-to-port data --
//! the mechanism that gives Panopticon actual NAC-grade visibility (which
//! physical switch port a device's MAC currently sits behind), and the
//! prerequisite for any future bandwidth-per-port work. v2c (community
//! string) only, deliberately: v3 (per-user auth/privacy protocols, engine
//! ID discovery) is real additional complexity this phase doesn't need --
//! a switch that only offers v3 simply can't be polled yet, a documented
//! limitation rather than a silent gap.
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

use abyssal_core::{EncryptionKey, Permission};
use abyssal_database::{DbPool, repo};
use abyssal_execution::{
    ExecutionError, Operation, OperationKind, OperationOutput, OperationParams,
};
use chrono::Utc;
use snmp2::{AsyncSession, Oid, Value};

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

#[derive(Debug, thiserror::Error)]
pub enum SnmpPollError {
    #[error("could not decrypt this switch's stored community string: {0}")]
    Decrypt(#[from] abyssal_core::CryptoError),
    #[error("SNMP request to {0} timed out")]
    Timeout(String),
    #[error("SNMP error: {0}")]
    Protocol(String),
    #[error("SNMP I/O error: {0}")]
    Io(String),
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
    community: &str,
) -> Result<usize, SnmpPollError> {
    let addr = format!("{}:{}", switch.ip_address, switch.snmp_port);

    let mut sess = tokio::time::timeout(
        REQUEST_TIMEOUT,
        AsyncSession::new_v2c(addr.clone(), community.as_bytes(), 1),
    )
    .await
    .map_err(|_| SnmpPollError::Timeout(addr.clone()))?
    .map_err(|e| SnmpPollError::Io(e.to_string()))?;

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

    // Bandwidth collection reuses this same session/poll but is entirely
    // best-effort: a switch that doesn't support IF-MIB's octet counters
    // (or a transient error walking them) shouldn't take down FDB-based
    // port matching above, which already succeeded. Errors are logged,
    // never propagated.
    collect_port_traffic(pool, &mut sess, switch, &addr, &if_to_descr).await;

    Ok(matched)
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

/// Decrypts `switch.community_encrypted` and polls it, recording the
/// outcome (success or error message) on the switch row either way.
/// Shared by the manual "Poll now" action (`SnmpPollOperation`) and the
/// unattended SNMP sweep (`spawn_panopticon_snmp_sweep`).
pub async fn poll_and_record(
    pool: &DbPool,
    switch: &abyssal_core::PanopticonSwitch,
    encryption_key: &EncryptionKey,
) -> Result<usize, SnmpPollError> {
    let community = encryption_key.decrypt(&switch.community_encrypted)?;
    let result = poll_switch(pool, switch, &community).await;
    let error_message = result.as_ref().err().map(ToString::to_string);
    if let Err(e) =
        repo::panopticon_switches::record_poll_result(pool, switch.id, error_message.as_deref())
            .await
    {
        tracing::error!(error = %e, switch = %switch.name, "failed to record poll result");
    }
    result
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
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SNMP_SWEEP_INTERVAL);
        loop {
            interval.tick().await;

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
