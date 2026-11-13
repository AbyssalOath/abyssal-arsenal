//! DHCP servers the capture has seen (0.2.9 Q4, rogue DHCP detection).

use abyssal_core::DhcpServer;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::FromRow;

use crate::DbPool;

fn utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::from_naive_utc_and_offset(naive, Utc)
}

#[derive(FromRow)]
struct ServerRow {
    server_ip: String,
    server_mac: Option<String>,
    first_seen_at: NaiveDateTime,
    last_seen_at: NaiveDateTime,
    replies: u32,
    chosen: u32,
    last_client_mac: Option<String>,
    alerted_at: Option<NaiveDateTime>,
}

impl From<ServerRow> for DhcpServer {
    fn from(r: ServerRow) -> Self {
        DhcpServer {
            server_ip: r.server_ip,
            server_mac: r.server_mac,
            first_seen_at: utc(r.first_seen_at),
            last_seen_at: utc(r.last_seen_at),
            replies: r.replies,
            chosen: r.chosen,
            last_client_mac: r.last_client_mac,
            alerted_at: r.alerted_at.map(utc),
        }
    }
}

/// How a server was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// A reply from it (OFFER/ACK/NAK).
    Reply,
    /// A client's REQUEST naming it (option 54).
    Chosen,
}

/// Records one sighting of a server and returns its row. `server_mac` only
/// for an unrelayed reply; an earlier one is kept when this has none.
pub async fn record(
    pool: &DbPool,
    server_ip: &str,
    server_mac: Option<&str>,
    client_mac: Option<&str>,
    seen: Seen,
) -> anyhow::Result<DhcpServer> {
    let (replies, chosen) = match seen {
        Seen::Reply => (1u32, 0u32),
        Seen::Chosen => (0, 1),
    };
    sqlx::query(
        "INSERT INTO panopticon_dhcp_servers \
         (server_ip, server_mac, replies, chosen, last_client_mac) VALUES (?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE server_mac = COALESCE(VALUES(server_mac), server_mac), \
           last_seen_at = CURRENT_TIMESTAMP(6), replies = replies + VALUES(replies), \
           chosen = chosen + VALUES(chosen), \
           last_client_mac = COALESCE(VALUES(last_client_mac), last_client_mac)",
    )
    .bind(server_ip)
    .bind(server_mac)
    .bind(replies)
    .bind(chosen)
    .bind(client_mac)
    .execute(pool)
    .await?;
    let row: ServerRow =
        sqlx::query_as("SELECT * FROM panopticon_dhcp_servers WHERE server_ip = ?")
            .bind(server_ip)
            .fetch_one(pool)
            .await?;
    Ok(row.into())
}

/// Marks a server as alerted on now.
pub async fn mark_alerted(pool: &DbPool, server_ip: &str) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE panopticon_dhcp_servers SET alerted_at = CURRENT_TIMESTAMP(6) WHERE server_ip = ?",
    )
    .bind(server_ip)
    .execute(pool)
    .await?;
    Ok(())
}

/// How many servers were alerted on since `since`.
pub async fn alerted_since(pool: &DbPool, since: DateTime<Utc>) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM panopticon_dhcp_servers WHERE alerted_at >= ?")
            .bind(since.naive_utc())
            .fetch_one(pool)
            .await?,
    )
}

/// Every server seen, most recently seen first.
pub async fn list(pool: &DbPool) -> anyhow::Result<Vec<DhcpServer>> {
    let rows: Vec<ServerRow> =
        sqlx::query_as("SELECT * FROM panopticon_dhcp_servers ORDER BY last_seen_at DESC")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Servers seen since `since`.
pub async fn seen_since(pool: &DbPool, since: DateTime<Utc>) -> anyhow::Result<Vec<DhcpServer>> {
    let rows: Vec<ServerRow> =
        sqlx::query_as("SELECT * FROM panopticon_dhcp_servers WHERE last_seen_at >= ?")
            .bind(since.naive_utc())
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Forgets a server (the page's Forget: one that's gone for good).
pub async fn delete(pool: &DbPool, server_ip: &str) -> anyhow::Result<bool> {
    let r = sqlx::query("DELETE FROM panopticon_dhcp_servers WHERE server_ip = ?")
        .bind(server_ip)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}
