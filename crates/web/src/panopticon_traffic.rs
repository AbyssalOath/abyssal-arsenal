//! Turns the raw counter samples `panopticon_snmp.rs` collects into actual
//! bandwidth graphs: rate computation from consecutive raw samples, the
//! hourly/daily rollup+prune background loop, range-aware tier selection
//! for the traffic page, and server-side inline SVG chart rendering (no
//! client-side JavaScript charting library -- this app is server-rendered
//! Askama throughout with no JS build pipeline, and a chart is no
//! exception).

use std::fmt::Write as _;

use abyssal_core::settings::{
    PANOPTICON_TRAFFIC_DAILY_RETENTION_DAYS, PANOPTICON_TRAFFIC_DAILY_RETENTION_DEFAULT_DAYS,
    PANOPTICON_TRAFFIC_HOURLY_RETENTION_DAYS, PANOPTICON_TRAFFIC_HOURLY_RETENTION_DEFAULT_DAYS,
    PANOPTICON_TRAFFIC_RAW_RETENTION_DAYS, PANOPTICON_TRAFFIC_RAW_RETENTION_DEFAULT_DAYS,
};
use abyssal_database::repo::panopticon_traffic::{RawSample, TrafficBucket};
use abyssal_database::{DbPool, repo};
use chrono::{DateTime, Duration, Timelike, Utc};
use uuid::Uuid;

/// However short an admin sets raw retention, the daily rollup needs a
/// full elapsed day of raw data still on hand when it runs (once daily,
/// right after midnight UTC) -- enforced here rather than trusted to
/// whatever gets saved from the settings form.
pub(crate) const MIN_RAW_RETENTION_DAYS: u32 = 2;

/// Converts consecutive raw counter samples into rate points (bits/sec,
/// the conventional unit for a bandwidth graph). A decrease between two
/// readings is either a counter wrap or a genuine reset: for a 32-bit
/// counter (`counter_bits == 32`) a decrease is treated as exactly one
/// wrap (adds back 2^32 before taking the delta) -- the standard MRTG/
/// Cacti convention, and correct as long as the counter wraps at most
/// once between polls. At 1 Gbps a 32-bit byte counter wraps roughly
/// every 34 seconds, far faster than any reasonable poll interval, so a
/// 32-bit-only switch's graph can silently under-count on a fast link --
/// an inherent limitation of 32-bit counters, not a bug fixable without
/// polling far more often. A 64-bit counter decrease is always treated as
/// a reset (interface flap, switch reboot) and simply skipped -- no rate
/// point for that interval -- since 2^64 bytes is never reached in
/// practice.
pub(crate) fn rates_from_raw(samples: &[RawSample]) -> Vec<TrafficBucket> {
    let mut points = Vec::with_capacity(samples.len().saturating_sub(1));
    for pair in samples.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        let elapsed = (b.polled_at - a.polled_at).num_milliseconds() as f64 / 1000.0;
        if elapsed <= 0.0 {
            continue;
        }
        let Some(in_delta) = counter_delta(a.in_octets, b.in_octets, b.counter_bits) else {
            continue;
        };
        let Some(out_delta) = counter_delta(a.out_octets, b.out_octets, b.counter_bits) else {
            continue;
        };
        let in_bps = (in_delta as f64 * 8.0) / elapsed;
        let out_bps = (out_delta as f64 * 8.0) / elapsed;
        points.push(TrafficBucket {
            at: b.polled_at,
            avg_in_bps: in_bps,
            avg_out_bps: out_bps,
            max_in_bps: in_bps,
            max_out_bps: out_bps,
        });
    }
    points
}

fn counter_delta(old: u64, new: u64, bits: u8) -> Option<u64> {
    if new >= old {
        Some(new - old)
    } else if bits == 32 {
        Some((u32::MAX as u64 - old) + new + 1)
    } else {
        None
    }
}

fn summarize(points: &[TrafficBucket]) -> Option<(f64, f64, f64, f64, u32)> {
    if points.is_empty() {
        return None;
    }
    let n = points.len() as f64;
    let avg_in = points.iter().map(|p| p.avg_in_bps).sum::<f64>() / n;
    let avg_out = points.iter().map(|p| p.avg_out_bps).sum::<f64>() / n;
    let max_in = points.iter().fold(0.0f64, |m, p| m.max(p.max_in_bps));
    let max_out = points.iter().fold(0.0f64, |m, p| m.max(p.max_out_bps));
    Some((avg_in, avg_out, max_in, max_out, points.len() as u32))
}

fn floor_to_hour(t: DateTime<Utc>) -> DateTime<Utc> {
    t.with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(t)
}

/// Computes and upserts the just-completed hour's rollup bucket (if
/// hourly retention is enabled) and, once a day, the just-completed day's
/// rollup bucket (if daily retention is enabled) for every known port of
/// every switch, then prunes each tier per its own retention setting.
/// Disabling a tier (retention set to 0) both stops computing new rows
/// for it and deletes every row it already has, so "0" really does mean
/// "not using this tier" rather than merely "stop growing it further."
async fn run_rollup_and_prune(pool: &DbPool) -> anyhow::Result<()> {
    let raw_days = repo::settings::get_u32(
        pool,
        PANOPTICON_TRAFFIC_RAW_RETENTION_DAYS,
        PANOPTICON_TRAFFIC_RAW_RETENTION_DEFAULT_DAYS,
    )
    .await?
    .max(MIN_RAW_RETENTION_DAYS);
    let hourly_days = repo::settings::get_u32(
        pool,
        PANOPTICON_TRAFFIC_HOURLY_RETENTION_DAYS,
        PANOPTICON_TRAFFIC_HOURLY_RETENTION_DEFAULT_DAYS,
    )
    .await?;
    let daily_days = repo::settings::get_u32(
        pool,
        PANOPTICON_TRAFFIC_DAILY_RETENTION_DAYS,
        PANOPTICON_TRAFFIC_DAILY_RETENTION_DEFAULT_DAYS,
    )
    .await?;

    let now = Utc::now();
    let this_hour = floor_to_hour(now);
    let prev_hour = this_hour - Duration::hours(1);

    let switches = repo::panopticon_switches::list(pool).await?;

    if hourly_days > 0 {
        for switch in &switches {
            for port in repo::panopticon_traffic::list_ports(pool, switch.id).await? {
                let samples = repo::panopticon_traffic::raw_samples_between(
                    pool,
                    switch.id,
                    port.if_index,
                    prev_hour,
                    this_hour,
                )
                .await?;
                let points = rates_from_raw(&samples);
                let Some((avg_in, avg_out, max_in, max_out, count)) = summarize(&points) else {
                    continue;
                };
                repo::panopticon_traffic::upsert_hourly_bucket(
                    pool,
                    switch.id,
                    port.if_index,
                    prev_hour,
                    avg_in,
                    avg_out,
                    max_in,
                    max_out,
                    count,
                )
                .await?;
            }
        }
    } else {
        repo::panopticon_traffic::delete_all_hourly(pool).await?;
    }

    // Once per day, right after the last hour of that day has closed.
    if daily_days > 0 && prev_hour.hour() == 23 {
        let day = prev_hour.date_naive();
        let day_start = DateTime::from_naive_utc_and_offset(day.and_hms_opt(0, 0, 0).unwrap(), Utc);
        let day_end = day_start + Duration::days(1);
        for switch in &switches {
            for port in repo::panopticon_traffic::list_ports(pool, switch.id).await? {
                let samples = repo::panopticon_traffic::raw_samples_between(
                    pool,
                    switch.id,
                    port.if_index,
                    day_start,
                    day_end,
                )
                .await?;
                let points = rates_from_raw(&samples);
                let Some((avg_in, avg_out, max_in, max_out, count)) = summarize(&points) else {
                    continue;
                };
                repo::panopticon_traffic::upsert_daily_bucket(
                    pool,
                    switch.id,
                    port.if_index,
                    day,
                    avg_in,
                    avg_out,
                    max_in,
                    max_out,
                    count,
                )
                .await?;
            }
        }
    } else if daily_days == 0 {
        repo::panopticon_traffic::delete_all_daily(pool).await?;
    }

    repo::panopticon_traffic::prune_raw_older_than(pool, now - Duration::days(i64::from(raw_days)))
        .await?;
    if hourly_days > 0 {
        repo::panopticon_traffic::prune_hourly_older_than(
            pool,
            now - Duration::days(i64::from(hourly_days)),
        )
        .await?;
    }
    if daily_days > 0 {
        repo::panopticon_traffic::prune_daily_older_than(
            pool,
            (now - Duration::days(i64::from(daily_days))).date_naive(),
        )
        .await?;
    }

    Ok(())
}

const ROLLUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Spawns the hourly rollup/prune loop -- the counterpart to
/// `panopticon_ops::spawn_panopticon_sweep` for bandwidth history rather
/// than device discovery, following the same system-initiated,
/// `Executor`-bypassing shape every background loop in this codebase
/// uses.
pub fn spawn_panopticon_traffic_rollup(pool: DbPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(ROLLUP_INTERVAL);
        loop {
            interval.tick().await;
            if let Err(e) = run_rollup_and_prune(&pool).await {
                tracing::error!(error = %e, "Panopticon traffic rollup failed");
            }
        }
    });
}

/// A duration preset the traffic page's UI offers -- deliberately not an
/// arbitrary date-range picker, to keep both the UI and the tier-selection
/// logic below simple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficRange {
    Hour1,
    Hours24,
    Days7,
    Days30,
    Year1,
}

impl TrafficRange {
    pub fn as_str(self) -> &'static str {
        match self {
            TrafficRange::Hour1 => "1h",
            TrafficRange::Hours24 => "24h",
            TrafficRange::Days7 => "7d",
            TrafficRange::Days30 => "30d",
            TrafficRange::Year1 => "1y",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TrafficRange::Hour1 => "Last hour",
            TrafficRange::Hours24 => "Last 24 hours",
            TrafficRange::Days7 => "Last 7 days",
            TrafficRange::Days30 => "Last 30 days",
            TrafficRange::Year1 => "Last year",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "1h" => Some(TrafficRange::Hour1),
            "24h" => Some(TrafficRange::Hours24),
            "7d" => Some(TrafficRange::Days7),
            "30d" => Some(TrafficRange::Days30),
            "1y" => Some(TrafficRange::Year1),
            _ => None,
        }
    }

    fn days(self) -> u32 {
        match self {
            TrafficRange::Hour1 => 0,
            TrafficRange::Hours24 => 1,
            TrafficRange::Days7 => 7,
            TrafficRange::Days30 => 30,
            TrafficRange::Year1 => 365,
        }
    }

    const ALL: &'static [TrafficRange] = &[
        TrafficRange::Hour1,
        TrafficRange::Hours24,
        TrafficRange::Days7,
        TrafficRange::Days30,
        TrafficRange::Year1,
    ];
}

/// Which presets are actually meaningful given the current retention
/// settings -- a preset longer than every tier that could serve it isn't
/// offered, rather than linking to a chart that would come back empty.
pub fn available_ranges(raw_days: u32, hourly_days: u32, daily_days: u32) -> Vec<TrafficRange> {
    let longest_tier = raw_days.max(hourly_days).max(daily_days);
    TrafficRange::ALL
        .iter()
        .copied()
        .filter(|r| r.days() <= longest_tier)
        .collect()
}

/// Picks the coarsest tier that still fully covers the requested range
/// (raw when it fits, else hourly, else daily) and returns its points,
/// oldest first. Falls back to whatever raw data exists if the requested
/// range outgrows every enabled tier, rather than returning nothing.
pub async fn points_for_range(
    pool: &DbPool,
    switch_id: Uuid,
    if_index: u32,
    range: TrafficRange,
    raw_days: u32,
    hourly_days: u32,
    daily_days: u32,
) -> anyhow::Result<Vec<TrafficBucket>> {
    let now = Utc::now();
    // `TrafficRange::days()` is 0 for the 1-hour preset (it's the only
    // sub-day one), so it needs its own hours-based lookback rather than
    // `Duration::days(0)`, which would make `since == now` and return
    // nothing.
    let since = if range == TrafficRange::Hour1 {
        now - Duration::hours(1)
    } else {
        now - Duration::days(i64::from(range.days()))
    };

    if range.days() <= raw_days {
        let samples =
            repo::panopticon_traffic::raw_samples_between(pool, switch_id, if_index, since, now)
                .await?;
        return Ok(rates_from_raw(&samples));
    }
    if hourly_days > 0 && range.days() <= hourly_days {
        return repo::panopticon_traffic::hourly_between(pool, switch_id, if_index, since, now)
            .await;
    }
    if daily_days > 0 && range.days() <= daily_days {
        return repo::panopticon_traffic::daily_between(
            pool,
            switch_id,
            if_index,
            since.date_naive(),
            now.date_naive() + Duration::days(1),
        )
        .await;
    }

    // Nothing configured covers this range -- return whatever raw data
    // is actually on hand instead of an empty chart.
    let samples =
        repo::panopticon_traffic::raw_samples_between(pool, switch_id, if_index, since, now)
            .await?;
    Ok(rates_from_raw(&samples))
}

/// Formats a bits/sec figure the way a network admin expects to read it
/// (bps/Kbps/Mbps/Gbps, 3 significant figures) rather than a raw float.
pub fn format_bps(bps: f64) -> String {
    const UNITS: &[(&str, f64)] = &[
        ("Gbps", 1_000_000_000.0),
        ("Mbps", 1_000_000.0),
        ("Kbps", 1_000.0),
    ];
    for (unit, scale) in UNITS {
        if bps >= *scale {
            return format!("{:.2} {unit}", bps / scale);
        }
    }
    format!("{bps:.0} bps")
}

const CHART_WIDTH: f64 = 640.0;
const CHART_HEIGHT: f64 = 160.0;
const CHART_PAD_LEFT: f64 = 60.0;
const CHART_PAD_BOTTOM: f64 = 20.0;
const CHART_PAD_TOP: f64 = 10.0;

/// Renders `points` as an inline SVG line chart (in traffic as one color,
/// out as another) -- server-side, no client JavaScript charting library,
/// consistent with this app being server-rendered Askama throughout with
/// no JS build pipeline. Returns `None` for fewer than 2 points (nothing
/// to draw a line between).
pub fn render_chart_svg(points: &[TrafficBucket]) -> Option<String> {
    if points.len() < 2 {
        return None;
    }

    let max_bps = points
        .iter()
        .fold(0.0f64, |m, p| m.max(p.avg_in_bps).max(p.avg_out_bps))
        .max(1.0); // avoid a divide-by-zero chart when traffic is all zero

    let plot_w = CHART_WIDTH - CHART_PAD_LEFT - 10.0;
    let plot_h = CHART_HEIGHT - CHART_PAD_TOP - CHART_PAD_BOTTOM;
    let t0 = points.first().unwrap().at.timestamp() as f64;
    let t1 = points.last().unwrap().at.timestamp() as f64;
    let t_span = (t1 - t0).max(1.0);

    let x_of = |t: f64| CHART_PAD_LEFT + (t - t0) / t_span * plot_w;
    let y_of = |bps: f64| CHART_PAD_TOP + plot_h - (bps / max_bps) * plot_h;

    let mut in_path = String::new();
    let mut out_path = String::new();
    for (i, p) in points.iter().enumerate() {
        let x = x_of(p.at.timestamp() as f64);
        let cmd = if i == 0 { "M" } else { "L" };
        let _ = write!(in_path, "{cmd}{:.1},{:.1} ", x, y_of(p.avg_in_bps));
        let _ = write!(out_path, "{cmd}{:.1},{:.1} ", x, y_of(p.avg_out_bps));
    }

    let mut svg = String::new();
    let _ = write!(
        svg,
        r#"<svg viewBox="0 0 {CHART_WIDTH} {CHART_HEIGHT}" width="100%" height="{CHART_HEIGHT}" role="img" aria-label="Bandwidth chart">"#
    );

    // Y-axis gridlines/labels at 0%, 50%, 100% of max.
    for frac in [0.0, 0.5, 1.0] {
        let y = CHART_PAD_TOP + plot_h * (1.0 - frac);
        let _ = write!(
            svg,
            r#"<line x1="{CHART_PAD_LEFT}" y1="{y:.1}" x2="{}" y2="{y:.1}" stroke="currentColor" stroke-opacity="0.15"/>"#,
            CHART_WIDTH - 10.0
        );
        let _ = write!(
            svg,
            r#"<text x="{}" y="{:.1}" font-size="10" fill="currentColor" fill-opacity="0.6" text-anchor="end">{}</text>"#,
            CHART_PAD_LEFT - 6.0,
            y + 3.0,
            format_bps(max_bps * frac)
        );
    }

    let _ = write!(
        svg,
        r##"<path d="{}" fill="none" stroke="#3b82f6" stroke-width="1.5"/>"##,
        in_path.trim_end()
    );
    let _ = write!(
        svg,
        r##"<path d="{}" fill="none" stroke="#f59e0b" stroke-width="1.5"/>"##,
        out_path.trim_end()
    );

    svg.push_str("</svg>");
    Some(svg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(at_secs: i64, in_octets: u64, out_octets: u64, bits: u8) -> RawSample {
        RawSample {
            polled_at: DateTime::from_timestamp(at_secs, 0).unwrap(),
            in_octets,
            out_octets,
            counter_bits: bits,
        }
    }

    #[test]
    fn computes_rate_between_two_samples() {
        let samples = vec![sample(0, 1_000, 2_000, 64), sample(10, 11_000, 4_000, 64)];
        let points = rates_from_raw(&samples);
        assert_eq!(points.len(), 1);
        // 10_000 octets / 10s * 8 bits = 8_000 bps in
        assert!((points[0].avg_in_bps - 8_000.0).abs() < 0.01);
        assert!((points[0].avg_out_bps - 1_600.0).abs() < 0.01);
    }

    #[test]
    fn treats_32bit_decrease_as_a_single_wrap() {
        let near_max = u32::MAX as u64 - 100;
        let samples = vec![
            sample(0, near_max, 0, 32),
            sample(10, 50, 0, 32), // wrapped past u32::MAX and back to 50
        ];
        let points = rates_from_raw(&samples);
        assert_eq!(points.len(), 1);
        // delta = (u32::MAX - near_max) + 50 + 1 = 100 + 50 + 1 = 151 octets
        assert!((points[0].avg_in_bps - (151.0 * 8.0 / 10.0)).abs() < 0.01);
    }

    #[test]
    fn treats_64bit_decrease_as_a_reset_and_skips_it() {
        let samples = vec![sample(0, 5_000, 0, 64), sample(10, 100, 0, 64)];
        assert!(rates_from_raw(&samples).is_empty());
    }

    #[test]
    fn available_ranges_excludes_presets_longer_than_every_tier() {
        let ranges = available_ranges(14, 0, 0);
        assert!(ranges.contains(&TrafficRange::Days7));
        assert!(!ranges.contains(&TrafficRange::Days30));
    }

    #[test]
    fn format_bps_scales_units() {
        assert_eq!(format_bps(500.0), "500 bps");
        assert_eq!(format_bps(1_500.0), "1.50 Kbps");
        assert_eq!(format_bps(2_500_000.0), "2.50 Mbps");
        assert_eq!(format_bps(1_200_000_000.0), "1.20 Gbps");
    }

    #[test]
    fn chart_svg_needs_at_least_two_points() {
        assert!(render_chart_svg(&[]).is_none());
        let one = vec![TrafficBucket {
            at: Utc::now(),
            avg_in_bps: 1.0,
            avg_out_bps: 1.0,
            max_in_bps: 1.0,
            max_out_bps: 1.0,
        }];
        assert!(render_chart_svg(&one).is_none());
    }
}
