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
    /// Microsoft 365 licensing choices (from mail_settings_json): the usage
    /// location, the Entra licensing group, and/or the direct SKU id.
    pub m365_usage_location: String,
    pub m365_licensing_group: String,
    pub m365_license_sku: String,
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
    mail_settings_json: Option<String>,
    manager_required: bool,
}

#[derive(Default)]
struct MailSettings {
    usage_location: String,
    licensing_group: String,
    license_sku: String,
}

impl MailSettings {
    /// Parses the template's `mail_settings_json` object, tolerating a missing
    /// file or absent keys.
    fn parse(json: Option<&str>) -> Self {
        let v: serde_json::Value = json
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let field = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        MailSettings {
            usage_location: field("usage_location"),
            licensing_group: field("licensing_group"),
            license_sku: field("license_sku"),
        }
    }
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
        let mail = MailSettings::parse(r.mail_settings_json.as_deref());
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
            m365_usage_location: mail.usage_location,
            m365_licensing_group: mail.licensing_group,
            m365_license_sku: mail.license_sku,
            manager_required: r.manager_required,
        }
    }
}

const TEMPLATE_COLUMNS: &str = "id, domain_id, name, target_ou, username_pattern, upn_suffix, \
                                email_pattern, groups_json, attributes_json, mail_mode, \
                                mail_settings_json, manager_required";

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
    /// Serialized JSON of the M365 licensing settings (usage_location,
    /// licensing_group, license_sku), or `None` to leave unset.
    pub mail_settings_json: Option<&'a str>,
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
          groups_json, attributes_json, mail_mode, mail_settings_json, manager_required, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(new.mail_settings_json)
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
         mail_mode = ?, mail_settings_json = ?, manager_required = ? WHERE id = ?",
    )
    .bind(new.name)
    .bind(new.target_ou)
    .bind(new.username_pattern)
    .bind(new.upn_suffix)
    .bind(new.email_pattern)
    .bind(new.groups_json)
    .bind(new.attributes_json)
    .bind(new.mail_mode)
    .bind(new.mail_settings_json)
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

// --- Jobs (onboarding/offboarding, step by step) ---------------------------

#[derive(Debug, Clone)]
pub struct DirectoryJob {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub kind: String,
    pub title: String,
    pub target_sam: Option<String>,
    /// The created user's UPN (the mailbox identity), for a mail-step retry.
    pub target_upn: Option<String>,
    /// The template this job used, so a retry re-reads its mail settings.
    pub template_id: Option<Uuid>,
    /// Bulk jobs store their parsed rows here (JSON) for retry-failed-rows.
    pub payload_json: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DirectoryJobStep {
    pub id: Uuid,
    pub seq: i64,
    pub name: String,
    pub status: String,
    pub detail: Option<String>,
}

#[derive(FromRow)]
struct JobRow {
    id: String,
    domain_id: String,
    kind: String,
    title: String,
    target_sam: Option<String>,
    target_upn: Option<String>,
    template_id: Option<String>,
    payload_json: Option<String>,
    status: String,
    created_at: NaiveDateTime,
}

impl From<JobRow> for DirectoryJob {
    fn from(r: JobRow) -> Self {
        DirectoryJob {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            domain_id: Uuid::parse_str(&r.domain_id).unwrap_or_default(),
            kind: r.kind,
            title: r.title,
            target_sam: r.target_sam,
            target_upn: r.target_upn,
            template_id: r.template_id.and_then(|s| Uuid::parse_str(&s).ok()),
            payload_json: r.payload_json,
            status: r.status,
            created_at: utc(r.created_at),
        }
    }
}

const JOB_COLUMNS: &str = "id, domain_id, kind, title, target_sam, target_upn, template_id, \
                           payload_json, status, created_at";

/// Stores a bulk job's parsed rows (JSON) for later retry-failed-rows.
pub async fn set_job_payload(pool: &DbPool, id: Uuid, payload_json: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE directory_jobs SET payload_json = ? WHERE id = ?")
        .bind(payload_json)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Updates a single job step by its seq (for retrying one bulk row).
pub async fn update_job_step_by_seq(
    pool: &DbPool,
    job_id: Uuid,
    seq: i64,
    status: &str,
    detail: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE directory_job_steps SET status = ?, detail = ? WHERE job_id = ? AND seq = ?",
    )
    .bind(status)
    .bind(detail)
    .bind(job_id.to_string())
    .bind(seq)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(FromRow)]
struct JobStepRow {
    id: String,
    seq: i64,
    name: String,
    status: String,
    detail: Option<String>,
}

impl From<JobStepRow> for DirectoryJobStep {
    fn from(r: JobStepRow) -> Self {
        DirectoryJobStep {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            seq: r.seq,
            name: r.name,
            status: r.status,
            detail: r.detail,
        }
    }
}

/// Creates a job and returns its id. `template_id` lets a later step retry
/// re-read the template's settings.
pub async fn create_job(
    pool: &DbPool,
    domain_id: Uuid,
    kind: &str,
    title: &str,
    template_id: Option<Uuid>,
    created_by: Option<Uuid>,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO directory_jobs (id, domain_id, kind, title, template_id, created_by) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(domain_id.to_string())
    .bind(kind)
    .bind(title)
    .bind(template_id.map(|u| u.to_string()))
    .bind(created_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    Ok(id)
}

/// Appends a step to a job and returns its id.
pub async fn add_job_step(
    pool: &DbPool,
    job_id: Uuid,
    seq: i64,
    name: &str,
    status: &str,
    detail: Option<&str>,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO directory_job_steps (id, job_id, seq, name, status, detail) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(job_id.to_string())
    .bind(seq)
    .bind(name)
    .bind(status)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(id)
}

/// Sets a job's final status, target account name and UPN.
pub async fn finish_job(
    pool: &DbPool,
    id: Uuid,
    status: &str,
    target_sam: Option<&str>,
    target_upn: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE directory_jobs SET status = ?, target_sam = ?, target_upn = ? WHERE id = ?",
    )
    .bind(status)
    .bind(target_sam)
    .bind(target_upn)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Updates just a job's status (for a retry that changes the outcome).
pub async fn set_job_status(pool: &DbPool, id: Uuid, status: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE directory_jobs SET status = ? WHERE id = ?")
        .bind(status)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Updates the status/detail of a job's step identified by name (e.g. retrying
/// "Mailbox"). No-op if that step doesn't exist.
pub async fn update_job_step_by_name(
    pool: &DbPool,
    job_id: Uuid,
    name: &str,
    status: &str,
    detail: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE directory_job_steps SET status = ?, detail = ? WHERE job_id = ? AND name = ?",
    )
    .bind(status)
    .bind(detail)
    .bind(job_id.to_string())
    .bind(name)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn find_job(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<DirectoryJob>> {
    let row: Option<JobRow> = sqlx::query_as(&format!(
        "SELECT {JOB_COLUMNS} FROM directory_jobs WHERE id = ?"
    ))
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// A domain's jobs, newest first (capped).
pub async fn list_jobs(
    pool: &DbPool,
    domain_id: Uuid,
    limit: u32,
) -> anyhow::Result<Vec<DirectoryJob>> {
    let rows: Vec<JobRow> = sqlx::query_as(&format!(
        "SELECT {JOB_COLUMNS} FROM directory_jobs WHERE domain_id = ? ORDER BY created_at DESC LIMIT ?"
    ))
    .bind(domain_id.to_string())
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn job_steps(pool: &DbPool, job_id: Uuid) -> anyhow::Result<Vec<DirectoryJobStep>> {
    let rows: Vec<JobStepRow> = sqlx::query_as(
        "SELECT id, seq, name, status, detail FROM directory_job_steps \
         WHERE job_id = ? ORDER BY seq",
    )
    .bind(job_id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(Into::into).collect())
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

// --- Mail connections (Phase 2 mail) ---------------------------------------

#[derive(Debug, Clone)]
pub struct DirectoryMailConnection {
    pub domain_id: Uuid,
    pub mode: String,
    pub exchange_version: Option<String>,
    pub exchange_uri: Option<String>,
    pub exchange_account_upn: Option<String>,
    pub has_exchange_account: bool,
    pub exchange_agent_host_id: Option<Uuid>,
    pub remote_routing_domain: Option<String>,
    pub m365_tenant_id: Option<String>,
    pub m365_app_id: Option<String>,
    pub has_m365_cert: bool,
    pub m365_licensing_method: Option<String>,
    pub last_test_at: Option<DateTime<Utc>>,
    pub last_test_ok: Option<bool>,
    pub last_test_detail: Option<String>,
}

#[derive(FromRow)]
struct MailRow {
    domain_id: String,
    mode: String,
    exchange_version: Option<String>,
    exchange_uri: Option<String>,
    exchange_account_upn: Option<String>,
    exchange_account_sealed: Option<String>,
    exchange_agent_host_id: Option<String>,
    remote_routing_domain: Option<String>,
    m365_tenant_id: Option<String>,
    m365_app_id: Option<String>,
    m365_cert_sealed: Option<String>,
    m365_licensing_method: Option<String>,
    last_test_at: Option<NaiveDateTime>,
    last_test_ok: Option<bool>,
    last_test_detail: Option<String>,
}

impl From<MailRow> for DirectoryMailConnection {
    fn from(r: MailRow) -> Self {
        DirectoryMailConnection {
            domain_id: Uuid::parse_str(&r.domain_id).unwrap_or_default(),
            mode: r.mode,
            exchange_version: r.exchange_version,
            exchange_uri: r.exchange_uri,
            exchange_account_upn: r.exchange_account_upn,
            has_exchange_account: r.exchange_account_sealed.is_some(),
            exchange_agent_host_id: r
                .exchange_agent_host_id
                .and_then(|s| Uuid::parse_str(&s).ok()),
            remote_routing_domain: r.remote_routing_domain,
            m365_tenant_id: r.m365_tenant_id,
            m365_app_id: r.m365_app_id,
            has_m365_cert: r.m365_cert_sealed.is_some(),
            m365_licensing_method: r.m365_licensing_method,
            last_test_at: r.last_test_at.map(utc),
            last_test_ok: r.last_test_ok,
            last_test_detail: r.last_test_detail,
        }
    }
}

const MAIL_COLUMNS: &str = "domain_id, mode, exchange_version, exchange_uri, exchange_account_upn, \
                            exchange_account_sealed, exchange_agent_host_id, remote_routing_domain, \
                            m365_tenant_id, m365_app_id, m365_cert_sealed, m365_licensing_method, \
                            last_test_at, last_test_ok, last_test_detail";

pub async fn find_mail_connection(
    pool: &DbPool,
    domain_id: Uuid,
) -> anyhow::Result<Option<DirectoryMailConnection>> {
    let row: Option<MailRow> = sqlx::query_as(&format!(
        "SELECT {MAIL_COLUMNS} FROM directory_mail_connections WHERE domain_id = ?"
    ))
    .bind(domain_id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// The Exchange connection details plus the decryptable sealed account, for a
/// test or a mailbox provision. The sealed value is included (unlike the read
/// above) because the caller must decrypt it.
pub struct ExchangeCredentials {
    pub uri: String,
    pub account_upn: String,
    pub sealed: String,
    pub agent_host_id: Option<Uuid>,
    pub remote_routing_domain: Option<String>,
}

#[derive(FromRow)]
struct ExchangeCredRow {
    exchange_uri: Option<String>,
    exchange_account_upn: Option<String>,
    exchange_account_sealed: Option<String>,
    exchange_agent_host_id: Option<String>,
    remote_routing_domain: Option<String>,
}

/// `None` if there is no connection or the account isn't fully configured.
pub async fn exchange_credentials(
    pool: &DbPool,
    domain_id: Uuid,
) -> anyhow::Result<Option<ExchangeCredentials>> {
    let row: Option<ExchangeCredRow> = sqlx::query_as(
        "SELECT exchange_uri, exchange_account_upn, exchange_account_sealed, \
         exchange_agent_host_id, remote_routing_domain \
         FROM directory_mail_connections WHERE domain_id = ?",
    )
    .bind(domain_id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| {
        Some(ExchangeCredentials {
            uri: r.exchange_uri?,
            account_upn: r.exchange_account_upn?,
            sealed: r.exchange_account_sealed?,
            agent_host_id: r
                .exchange_agent_host_id
                .and_then(|s| Uuid::parse_str(&s).ok()),
            remote_routing_domain: r.remote_routing_domain,
        })
    }))
}

pub struct NewMailConnection<'a> {
    pub domain_id: Uuid,
    pub mode: &'a str,
    pub exchange_version: Option<&'a str>,
    pub exchange_uri: Option<&'a str>,
    pub exchange_account_upn: Option<&'a str>,
    /// The final sealed value to store (web resolves "keep existing" before this).
    pub exchange_account_sealed: Option<&'a str>,
    pub exchange_agent_host_id: Option<Uuid>,
    pub remote_routing_domain: Option<&'a str>,
    pub m365_tenant_id: Option<&'a str>,
    pub m365_app_id: Option<&'a str>,
    pub m365_cert_sealed: Option<&'a str>,
    pub m365_licensing_method: Option<&'a str>,
    pub created_by: Option<Uuid>,
}

/// Inserts or replaces a domain's mail connection (one per domain).
pub async fn upsert_mail_connection(
    pool: &DbPool,
    new: &NewMailConnection<'_>,
) -> anyhow::Result<()> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO directory_mail_connections \
         (id, domain_id, mode, exchange_version, exchange_uri, exchange_account_upn, \
          exchange_account_sealed, exchange_agent_host_id, remote_routing_domain, \
          m365_tenant_id, m365_app_id, m365_cert_sealed, m365_licensing_method, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE mode = VALUES(mode), exchange_version = VALUES(exchange_version), \
          exchange_uri = VALUES(exchange_uri), exchange_account_upn = VALUES(exchange_account_upn), \
          exchange_account_sealed = VALUES(exchange_account_sealed), \
          exchange_agent_host_id = VALUES(exchange_agent_host_id), \
          remote_routing_domain = VALUES(remote_routing_domain), \
          m365_tenant_id = VALUES(m365_tenant_id), m365_app_id = VALUES(m365_app_id), \
          m365_cert_sealed = VALUES(m365_cert_sealed), \
          m365_licensing_method = VALUES(m365_licensing_method)",
    )
    .bind(id.to_string())
    .bind(new.domain_id.to_string())
    .bind(new.mode)
    .bind(new.exchange_version)
    .bind(new.exchange_uri)
    .bind(new.exchange_account_upn)
    .bind(new.exchange_account_sealed)
    .bind(new.exchange_agent_host_id.map(|u| u.to_string()))
    .bind(new.remote_routing_domain)
    .bind(new.m365_tenant_id)
    .bind(new.m365_app_id)
    .bind(new.m365_cert_sealed)
    .bind(new.m365_licensing_method)
    .bind(new.created_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    Ok(())
}

/// Records a mail "Test connection" result.
/// The Microsoft 365 app config plus the decryptable sealed certificate, for a
/// Graph test or provision. `None` if not fully configured.
pub struct M365Credentials {
    pub tenant_id: String,
    pub app_id: String,
    pub cert_sealed: String,
    pub licensing_method: String,
}

#[derive(FromRow)]
struct M365CredRow {
    m365_tenant_id: Option<String>,
    m365_app_id: Option<String>,
    m365_cert_sealed: Option<String>,
    m365_licensing_method: Option<String>,
}

pub async fn m365_credentials(
    pool: &DbPool,
    domain_id: Uuid,
) -> anyhow::Result<Option<M365Credentials>> {
    let row: Option<M365CredRow> = sqlx::query_as(
        "SELECT m365_tenant_id, m365_app_id, m365_cert_sealed, m365_licensing_method \
         FROM directory_mail_connections WHERE domain_id = ?",
    )
    .bind(domain_id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| {
        Some(M365Credentials {
            tenant_id: r.m365_tenant_id?,
            app_id: r.m365_app_id?,
            cert_sealed: r.m365_cert_sealed?,
            licensing_method: r.m365_licensing_method.unwrap_or_else(|| "group".into()),
        })
    }))
}

pub async fn update_mail_test_result(
    pool: &DbPool,
    domain_id: Uuid,
    ok: bool,
    detail: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE directory_mail_connections SET last_test_at = CURRENT_TIMESTAMP(6), \
         last_test_ok = ?, last_test_detail = ? WHERE domain_id = ?",
    )
    .bind(ok)
    .bind(detail)
    .bind(domain_id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

// --- Offboard snapshots (Phase 3, for undo) --------------------------------

#[derive(Debug, Clone)]
pub struct OffboardSnapshot {
    pub id: Uuid,
    pub domain_id: Uuid,
    pub sam: Option<String>,
    pub upn: Option<String>,
    pub current_dn: String,
    pub original_ou: String,
    pub groups: Vec<String>,
    pub offboarded_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct SnapshotRow {
    id: String,
    domain_id: String,
    sam: Option<String>,
    upn: Option<String>,
    current_dn: String,
    original_ou: String,
    groups_json: Option<String>,
    offboarded_at: NaiveDateTime,
}

impl From<SnapshotRow> for OffboardSnapshot {
    fn from(r: SnapshotRow) -> Self {
        let groups: Vec<String> = r
            .groups_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        OffboardSnapshot {
            id: Uuid::parse_str(&r.id).unwrap_or_default(),
            domain_id: Uuid::parse_str(&r.domain_id).unwrap_or_default(),
            sam: r.sam,
            upn: r.upn,
            current_dn: r.current_dn,
            original_ou: r.original_ou,
            groups,
            offboarded_at: utc(r.offboarded_at),
        }
    }
}

const SNAPSHOT_COLUMNS: &str =
    "id, domain_id, sam, upn, current_dn, original_ou, groups_json, offboarded_at";

#[allow(clippy::too_many_arguments)]
pub async fn create_offboard_snapshot(
    pool: &DbPool,
    domain_id: Uuid,
    sam: Option<&str>,
    upn: Option<&str>,
    current_dn: &str,
    original_ou: &str,
    groups_json: &str,
    offboarded_by: Option<Uuid>,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO directory_offboard_snapshots \
         (id, domain_id, sam, upn, current_dn, original_ou, groups_json, offboarded_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(domain_id.to_string())
    .bind(sam)
    .bind(upn)
    .bind(current_dn)
    .bind(original_ou)
    .bind(groups_json)
    .bind(offboarded_by.map(|u| u.to_string()))
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn find_snapshot(pool: &DbPool, id: Uuid) -> anyhow::Result<Option<OffboardSnapshot>> {
    let row: Option<SnapshotRow> = sqlx::query_as(&format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM directory_offboard_snapshots WHERE id = ? AND undone_at IS NULL"
    ))
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// The active (not-yet-undone) snapshot for an account currently at `dn`, if any.
pub async fn active_snapshot_for_dn(
    pool: &DbPool,
    domain_id: Uuid,
    dn: &str,
) -> anyhow::Result<Option<OffboardSnapshot>> {
    let row: Option<SnapshotRow> = sqlx::query_as(&format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM directory_offboard_snapshots \
         WHERE domain_id = ? AND current_dn = ? AND undone_at IS NULL \
         ORDER BY offboarded_at DESC LIMIT 1"
    ))
    .bind(domain_id.to_string())
    .bind(dn)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

pub async fn mark_snapshot_undone(pool: &DbPool, id: Uuid) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE directory_offboard_snapshots SET undone_at = CURRENT_TIMESTAMP(6) WHERE id = ?",
    )
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}
