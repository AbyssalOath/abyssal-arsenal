//! Gravekeeper (Active Directory management): the configured domains a control
//! plane manages. One row per domain; a single-domain forest is just one row.
//! The service-account password is sealed with `ENCRYPTION_KEY` by the web
//! layer (`abyssal_web`), stored here as ciphertext, and never logged. See
//! `docs/roadmap/ad-management.md` and `migrations/0049_gravekeeper.sql`.
//!
//! Phase 1 reads the configured domains for the landing page and (M2) the
//! setup writes: adding a discovered domain, storing and validating a
//! delegated service account, and the disabled-OU / grace-period config.

use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::DbPool;

#[derive(Debug, Clone)]
pub struct DirectoryDomain {
    pub id: Uuid,
    /// The domain's DNS name (e.g. `corp.example.com`) -- its unique identity.
    pub dns_name: String,
    /// NetBIOS/short name (e.g. `CORP`), discovered from the forest.
    pub netbios_name: Option<String>,
    /// The forest root domain, for multi-domain forests.
    pub forest_root: Option<String>,
    /// The DC agent host every change for this domain is sent to.
    pub write_dc_host_id: Option<Uuid>,
    /// The delegated service account's UPN/username (the password is sealed
    /// separately and never returned by these reads).
    pub service_account_upn: Option<String>,
    /// Whether a sealed service-account credential is stored at all. The
    /// ciphertext itself is not surfaced; writes only happen for a domain that
    /// has one and whose last delegation check passed.
    pub has_service_account: bool,
    /// Where offboarded accounts go (a DN); `None` until setup sets it.
    pub disabled_ou: Option<String>,
    pub deletion_grace_days: i64,
    /// `none` | `exchange_onprem` | `exchange_hybrid` | `m365`.
    pub mail_mode: String,
    pub last_delegation_check_at: Option<DateTime<Utc>>,
    pub last_delegation_ok: Option<bool>,
    pub created_at: DateTime<Utc>,
}

impl DirectoryDomain {
    /// A domain Gravekeeper will run writes for: it has a service account and
    /// that account's last delegation check passed. Otherwise it is read-only.
    pub fn is_writable(&self) -> bool {
        self.has_service_account && self.last_delegation_ok == Some(true)
    }
}

#[derive(FromRow)]
struct Row {
    id: String,
    dns_name: String,
    netbios_name: Option<String>,
    forest_root: Option<String>,
    write_dc_host_id: Option<String>,
    service_account_upn: Option<String>,
    service_account_sealed: Option<String>,
    disabled_ou: Option<String>,
    deletion_grace_days: i64,
    mail_mode: String,
    last_delegation_check_at: Option<NaiveDateTime>,
    last_delegation_ok: Option<bool>,
    created_at: NaiveDateTime,
}

fn utc(t: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(t, Utc)
}

impl From<Row> for DirectoryDomain {
    fn from(r: Row) -> Self {
        DirectoryDomain {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            dns_name: r.dns_name,
            netbios_name: r.netbios_name,
            forest_root: r.forest_root,
            write_dc_host_id: r.write_dc_host_id.and_then(|s| Uuid::parse_str(&s).ok()),
            service_account_upn: r.service_account_upn,
            has_service_account: r.service_account_sealed.is_some(),
            disabled_ou: r.disabled_ou,
            deletion_grace_days: r.deletion_grace_days,
            mail_mode: r.mail_mode,
            last_delegation_check_at: r.last_delegation_check_at.map(utc),
            last_delegation_ok: r.last_delegation_ok,
            created_at: utc(r.created_at),
        }
    }
}

const COLUMNS: &str = "id, dns_name, netbios_name, forest_root, write_dc_host_id, \
                       service_account_upn, service_account_sealed, disabled_ou, \
                       deletion_grace_days, mail_mode, last_delegation_check_at, \
                       last_delegation_ok, created_at";

/// Every configured domain, ordered by DNS name.
pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<DirectoryDomain>> {
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM directory_domains ORDER BY dns_name"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn find_by_id(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<DirectoryDomain>> {
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM directory_domains WHERE id = ?"
    ))
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

pub async fn find_by_dns(pool: &DbPool, dns_name: &str) -> anyhow::Result<Option<DirectoryDomain>> {
    let row: Option<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM directory_domains WHERE dns_name = ?"
    ))
    .bind(dns_name)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

pub struct NewDirectoryDomain<'a> {
    pub dns_name: &'a str,
    pub netbios_name: Option<&'a str>,
    pub forest_root: Option<&'a str>,
    pub write_dc_host_id: Option<Uuid>,
    pub created_by: Option<Uuid>,
}

/// Adds a discovered domain. Idempotent on `dns_name` (re-adding an existing
/// domain refreshes its forest/NetBIOS/write-DC fields). Returns the domain's
/// id.
///
/// **Security:** a stored service-account credential is validated *against a
/// specific write DC*. If re-adding changes `write_dc_host_id`, the sealed
/// credential and the delegation result are cleared, so the credential is never
/// re-targeted at a different (possibly attacker-controlled) host without a
/// fresh delegation check on that host. Re-adding with the same write DC keeps
/// the credential.
pub async fn upsert(pool: &DbPool, new: &NewDirectoryDomain<'_>) -> anyhow::Result<Uuid> {
    if let Some(existing) = find_by_dns(pool, new.dns_name).await? {
        let write_dc_changed = existing.write_dc_host_id != new.write_dc_host_id;
        if write_dc_changed {
            sqlx::query(
                "UPDATE directory_domains SET netbios_name = ?, forest_root = ?, \
                 write_dc_host_id = ?, service_account_upn = NULL, \
                 service_account_sealed = NULL, last_delegation_ok = NULL, \
                 last_delegation_check_at = NULL, last_delegation_detail = NULL \
                 WHERE id = ?",
            )
            .bind(new.netbios_name)
            .bind(new.forest_root)
            .bind(new.write_dc_host_id.map(|u| u.to_string()))
            .bind(existing.id.to_string())
            .execute(pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE directory_domains SET netbios_name = ?, forest_root = ? WHERE id = ?",
            )
            .bind(new.netbios_name)
            .bind(new.forest_root)
            .bind(existing.id.to_string())
            .execute(pool)
            .await?;
        }
        return Ok(existing.id);
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO directory_domains \
         (id, dns_name, netbios_name, forest_root, write_dc_host_id, created_by) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(new.dns_name)
    .bind(new.netbios_name)
    .bind(new.forest_root)
    .bind(new.write_dc_host_id.map(|u| u.to_string()))
    .bind(new.created_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    Ok(id)
}

/// Stores a validated service account and its delegation result in one write:
/// the UPN, the sealed password, the check timestamp, that it passed, and the
/// detail JSON (manageable OUs, overprivilege findings). Only called after
/// `DirectoryTestDelegation` succeeds and the account is not overprivileged.
pub async fn set_validated_service_account(
    pool: &DbPool,
    id: Uuid,
    upn: &str,
    sealed: &str,
    detail_json: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE directory_domains SET service_account_upn = ?, service_account_sealed = ?, \
         last_delegation_check_at = CURRENT_TIMESTAMP(6), last_delegation_ok = 1, \
         last_delegation_detail = ? WHERE id = ?",
    )
    .bind(upn)
    .bind(sealed)
    .bind(detail_json)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Records a delegation check that did not pass (bad credentials, account not
/// found, or overprivileged) without storing any credential. Marks the domain
/// read-only (`last_delegation_ok = 0`) and keeps the detail for the UI.
pub async fn record_delegation_failure(
    pool: &DbPool,
    id: Uuid,
    detail_json: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE directory_domains SET last_delegation_check_at = CURRENT_TIMESTAMP(6), \
         last_delegation_ok = 0, last_delegation_detail = ? WHERE id = ?",
    )
    .bind(detail_json)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// The domain's last delegation-check detail JSON (manageable OUs, etc.), if any.
pub async fn delegation_detail(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<String>> {
    let detail: Option<Option<String>> =
        sqlx::query_scalar("SELECT last_delegation_detail FROM directory_domains WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(pool)
            .await?;
    Ok(detail.flatten())
}

/// Sets the disabled OU and deletion grace period for a domain.
pub async fn set_config(
    pool: &DbPool,
    id: Uuid,
    disabled_ou: &str,
    deletion_grace_days: u32,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE directory_domains SET disabled_ou = ?, deletion_grace_days = ? WHERE id = ?",
    )
    .bind(disabled_ou)
    .bind(deletion_grace_days)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Removes a configured domain (its sealed credential goes with it).
pub async fn delete(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM directory_domains WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

// --- Onboarding templates (Phase 2) ----------------------------------------

#[derive(Debug, Clone)]
pub struct DirectoryTemplate {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub name: String,
    pub target_ou: Option<String>,
    pub username_pattern: String,
    pub upn_suffix: Option<String>,
    pub email_pattern: Option<String>,
    /// Group identifiers (DNs) the new user is added to.
    pub groups: Vec<String>,
    /// Attribute defaults as (name, value), sorted by name.
    pub attributes: Vec<(String, String)>,
    pub mail_mode: String,
    pub manager_required: bool,
}

#[derive(FromRow)]
struct TemplateRow {
    id: String,
    domain_id: String,
    name: String,
    target_ou: Option<String>,
    username_pattern: String,
    upn_suffix: Option<String>,
    email_pattern: Option<String>,
    groups_json: Option<String>,
    attributes_json: Option<String>,
    mail_mode: String,
    manager_required: bool,
}

impl From<TemplateRow> for DirectoryTemplate {
    fn from(r: TemplateRow) -> Self {
        let groups: Vec<String> = r
            .groups_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        let mut attributes: Vec<(String, String)> = r
            .attributes_json
            .as_deref()
            .and_then(|s| {
                serde_json::from_str::<std::collections::BTreeMap<String, String>>(s).ok()
            })
            .map(|m| m.into_iter().collect())
            .unwrap_or_default();
        attributes.sort();
        DirectoryTemplate {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            domain_id: Uuid::parse_str(&r.domain_id).unwrap_or_default(),
            name: r.name,
            target_ou: r.target_ou,
            username_pattern: r.username_pattern,
            upn_suffix: r.upn_suffix,
            email_pattern: r.email_pattern,
            groups,
            attributes,
            mail_mode: r.mail_mode,
            manager_required: r.manager_required,
        }
    }
}

const TEMPLATE_COLUMNS: &str = "id, domain_id, name, target_ou, username_pattern, upn_suffix, \
                                email_pattern, groups_json, attributes_json, mail_mode, \
                                manager_required";

pub struct NewDirectoryTemplate<'a> {
    pub domain_id: Uuid,
    pub name: &'a str,
    pub target_ou: Option<&'a str>,
    pub username_pattern: &'a str,
    pub upn_suffix: Option<&'a str>,
    pub email_pattern: Option<&'a str>,
    /// Serialized JSON array of group identifiers.
    pub groups_json: &'a str,
    /// Serialized JSON object of attribute defaults.
    pub attributes_json: &'a str,
    pub mail_mode: &'a str,
    pub manager_required: bool,
    pub created_by: Option<Uuid>,
}

/// Templates for one domain, by name.
pub async fn list_templates(
    pool: &DbPool,
    domain_id: Uuid,
) -> anyhow::Result<Vec<DirectoryTemplate>> {
    let rows: Vec<TemplateRow> = sqlx::query_as(&format!(
        "SELECT {TEMPLATE_COLUMNS} FROM directory_templates WHERE domain_id = ? ORDER BY name"
    ))
    .bind(domain_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn find_template(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<DirectoryTemplate>> {
    let row: Option<TemplateRow> = sqlx::query_as(&format!(
        "SELECT {TEMPLATE_COLUMNS} FROM directory_templates WHERE id = ?"
    ))
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

pub async fn create_template(
    pool: &DbPool,
    new: &NewDirectoryTemplate<'_>,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO directory_templates \
         (id, domain_id, name, target_ou, username_pattern, upn_suffix, email_pattern, \
          groups_json, attributes_json, mail_mode, manager_required, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(new.domain_id.to_string())
    .bind(new.name)
    .bind(new.target_ou)
    .bind(new.username_pattern)
    .bind(new.upn_suffix)
    .bind(new.email_pattern)
    .bind(new.groups_json)
    .bind(new.attributes_json)
    .bind(new.mail_mode)
    .bind(new.manager_required)
    .bind(new.created_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn update_template(
    pool: &DbPool,
    id: Uuid,
    new: &NewDirectoryTemplate<'_>,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE directory_templates SET name = ?, target_ou = ?, username_pattern = ?, \
         upn_suffix = ?, email_pattern = ?, groups_json = ?, attributes_json = ?, \
         mail_mode = ?, manager_required = ? WHERE id = ?",
    )
    .bind(new.name)
    .bind(new.target_ou)
    .bind(new.username_pattern)
    .bind(new.upn_suffix)
    .bind(new.email_pattern)
    .bind(new.groups_json)
    .bind(new.attributes_json)
    .bind(new.mail_mode)
    .bind(new.manager_required)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_template(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM directory_templates WHERE id = ?")
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// A domain with a stored service-account credential, for the daily delegation
/// re-check sweep: enough to decrypt the password and dispatch the check to the
/// write DC. The sealed ciphertext is included here (unlike the `list`/`find`
/// reads) precisely because the sweep must decrypt and re-use it.
#[derive(Debug, Clone)]
pub struct DirectoryDomainCredential {
    pub id: Uuid,
    pub dns_name: String,
    pub service_account_upn: String,
    pub service_account_sealed: String,
    pub write_dc_host_id: Option<Uuid>,
}

#[derive(FromRow)]
struct CredRow {
    id: String,
    dns_name: String,
    service_account_upn: Option<String>,
    service_account_sealed: Option<String>,
    write_dc_host_id: Option<String>,
}

/// Every domain that has a stored service account (so the delegation re-check
/// sweep can revalidate it). Domains without one are read-only already and have
/// nothing to re-check.
pub async fn with_service_account(pool: &DbPool) -> anyhow::Result<Vec<DirectoryDomainCredential>> {
    let rows: Vec<CredRow> = sqlx::query_as(
        "SELECT id, dns_name, service_account_upn, service_account_sealed, write_dc_host_id \
         FROM directory_domains \
         WHERE service_account_sealed IS NOT NULL AND service_account_upn IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            Some(DirectoryDomainCredential {
                id: Uuid::parse_str(&r.id).ok()?,
                dns_name: r.dns_name,
                service_account_upn: r.service_account_upn?,
                service_account_sealed: r.service_account_sealed?,
                write_dc_host_id: r.write_dc_host_id.and_then(|s| Uuid::parse_str(&s).ok()),
            })
        })
        .collect())
}

/// The stored service account (UPN + sealed password) for a writable domain,
/// for a help-desk write that must run under its `-Credential`. `None` if the
/// domain has no stored account. The caller decrypts the sealed value with
/// `ENCRYPTION_KEY`; it is never logged.
pub async fn service_account(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<(String, String)>> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT service_account_upn, service_account_sealed FROM directory_domains WHERE id = ?",
    )
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(upn, sealed)| Some((upn?, sealed?))))
}

/// Records a passing delegation re-check (keeps the stored credential, refreshes
/// the timestamp, marks writable and updates the detail JSON).
pub async fn record_delegation_success(
    pool: &DbPool,
    id: Uuid,
    detail_json: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE directory_domains SET last_delegation_check_at = CURRENT_TIMESTAMP(6), \
         last_delegation_ok = 1, last_delegation_detail = ? WHERE id = ?",
    )
    .bind(detail_json)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}
