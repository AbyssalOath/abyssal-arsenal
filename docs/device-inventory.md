# Device Inventory: subnet grouping and pagination

GitHub issue #10. This document covers how Panopticon's Device Inventory
groups devices by subnet, the query-string params that drive it, the
render-budget setting, how the shared pagination module decides
offset vs. keyset per view, and the schema/storage decisions behind all of
it. There is no JavaScript anywhere in this feature -- every interaction
(expanding a group, paging, filtering) is a plain link or GET/POST form,
using the same POST/redirect/GET pattern the rest of this app already
uses.

## Subnet grouping

Every device's `panopticon_devices.ip_address` is masked down to a network
at write time (`upsert`/`touch`/`note_sighting` in
`crates/database/src/repo/network_devices.rs`) and stored in a persisted
`network` column (`VARCHAR(43)`, indexed -- migration `0021`). This is
computed in Rust (`abyssal_core::network_of`, `crates/core/src/subnet.rs`),
not derived on every page read, so the Device Inventory page's group
headers are a single cheap `GROUP BY network` rather than fetching and
masking every device row per request.

The prefix is configurable per address family:

- `panopticon.subnet_prefix_v4` (default `24`)
- `panopticon.subnet_prefix_v6` (default `64`)

Changing either setting only affects devices written *after* the change --
existing rows keep their old `network` value until re-derived. Two ways
that happens:

- **Automatic backfill**: `repo::network_devices::backfill_network`, called
  once at every app startup. Idempotent -- only touches rows where
  `network IS NULL` (a fresh install's first devices, or any row this
  column didn't exist for yet).
- **Explicit re-derive**: the "Re-derive subnets" button on the Device
  Inventory page (`network.manage` permission;
  `routes::panopticon::subnets_rederive`, calling
  `repo::network_devices::rederive_all_networks`) recomputes `network` for
  *every* row using whatever prefix is configured right now. Use this
  after deliberately changing `panopticon.subnet_prefix_v4`/`_v6`.

A device whose `ip_address` fails to parse at all (shouldn't happen given
how rows are written, but never assumed impossible) gets `network = NULL`
and appears in a dedicated **"Unassigned / Unknown"** group instead of
being silently dropped from the inventory.

### Multi-IP devices

`panopticon_devices` has exactly one `ip_address` per row today -- there's
no multi-interface/multi-IP concept in the schema. The "a device with
multiple IPs appears in each relevant group, never twice within the same
group" requirement is therefore moot under the current data model; if a
future change adds multi-IP support, each IP would need its own `network`
value and the group-membership/count queries would need to `UNION` or
join across an IP-list table instead of reading a single column, which
this implementation doesn't attempt to pre-build.

### Least invasive IP storage decision

The spec suggested storing IPs in a typed `INET6` column for indexed
numeric range queries. This implementation deliberately does **not**
change `ip_address`'s storage type -- it stays a plain `VARCHAR(45)`.
MariaDB's `INET6_ATON()`/`INET6_NTOA()` functions work directly against a
plain string column (already used for numeric `ORDER BY` before this
feature existed) and support real numeric range containment via
`WHERE INET6_ATON(ip_address) BETWEEN INET6_ATON(?) AND INET6_ATON(?)` --
never a `LIKE '10.0.1.%'` prefix match, without any schema/type change,
CAST, or driver-mapping complexity. This is the "least invasive"
implementation of the range-query requirement.

## Query-string params (`/arsenals/panopticon`)

All parsed by `routes::panopticon::parse_inventory_query` (hand-parsed via
`form_urlencoded`, since axum's stock `Query<T>` extractor can't
deserialize repeated keys into a `Vec` or the `gp` pairs below) and
re-serialized by `InventoryQuery::href` -- the one place a link on this
page is built, so every link preserves every other active param.

| Param | Repeatable | Meaning |
| --- | --- | --- |
| `port` | no | Open-port filter, composed with grouping/pagination via a correlated `EXISTS` against `panopticon_device_ports`. |
| `subnet` | no | An ad-hoc CIDR filter (any valid `address/prefix`, not just one matching the configured grouping prefix) that replaces the grouped view entirely with one filtered, paginated table. Invalid input renders an error banner instead of a 500 or a silently-ignored filter. |
| `open` | **yes** | Which subnet groups render their device rows even when the render budget would otherwise leave them collapsed. Server-rendered back into `<details open>`, so state survives reloads and is shareable/bookmarkable. |
| `group_page` | no | Which page of the subnet *list itself* to show (`GROUPS_PER_PAGE = 25`), independent of any single group's own row pagination. |
| `gp` | **yes** | One subnet group's own row page, as a `<network>:<page>` pair (e.g. `gp=10.0.1.0%2F24:2`). A flat repeatable key with a compound value, not dynamic bracket keys (`gp[10.0.1.0/24]=2`) -- axum/serde_urlencoded can't deserialize either shape automatically either way, and a flat pair is simpler to hand-parse and validate. |
| `page` | no | The ad-hoc `subnet`-filtered view's own row page. Kept separate from `group_page` so the grouped view's pager and the filtered view's pager never share a key. |

Every numeric param is clamped or silently dropped on a malformed value
(never a 500): an out-of-range page clamps to the last valid page in the
same request (rather than an HTTP redirect -- functionally equivalent,
one fewer round trip), and an unparseable `port`/`group_page`/`gp` value
falls back to that param's default.

## Render budget

`panopticon.inventory_render_budget` (default `500`). If the total device
count matching the current `port` filter is at or under the budget, every
subnet group's body renders open by default (each still independently
paginated at `GROUP_ROWS_PER_PAGE = 50` rows/page) -- no `open=` params
needed. Past the budget, only groups explicitly named in `open=` render
their rows; every other group shows a single "Load devices" link that
reloads the page with that group added to `open`. Group *headers*
(subnet, device count, managed count) always render regardless -- one
aggregate `group_counts` query, never N+1.

## Offset vs. keyset pagination

`crates/web/src/pagination.rs` is the shared module both patterns build
on (`normalize`, `offset`, `total_pages`, `page_window`, `page_link`,
`Page<T>`, `CursorPage<T>`). Two views currently use it, chosen per the
following guidance:

- **Device Inventory** (per-group rows, the group list, and the ad-hoc
  filtered view) -- **offset/limit**. Each subnet group and the group
  list itself are naturally small, bounded collections that support
  jumping to an arbitrary page number, and the `COUNT(*)` behind each is
  already cheap (`count_for_group`/`total_count`, filtered by an indexed
  `network` column or a numeric IP range) rather than a full-table scan.
- **Audit Log** (`routes/audit.rs`, `repo::audit::list_keyset`) --
  **keyset (cursor)**, using a `(occurred_at, id)` composite cursor
  (`id` as the tiebreaker for rows sharing the same microsecond
  timestamp, which `datetime(6)` makes rare but not impossible). The
  audit log is append-heavy and unbounded in principle -- a `COUNT(*)`
  over the whole table on every page view, and an `OFFSET` that gets
  linearly slower the deeper a page is, are both avoided entirely. Only
  Newer/Older links, no numbered page strip (a keyset page doesn't know
  its position among a total it never computed).
  - `routes/audit.rs`'s CSV export also switched from a hardcoded
    `LIMIT 10,000` cap to `repo::audit::for_each_batch`, which streams the
    *entire* filtered result set in bounded keyset batches (500 rows at a
    time) so an export is never silently truncated regardless of how
    large the audit log grows.
  - The dashboard's small "recent activity" widget
    (`routes/dashboard.rs`) still uses the older offset-based
    `abyssal_audit::list`/`count` -- it always fetches a small, fixed
    page 0, so the `COUNT(*)`/`OFFSET` cost this feature otherwise avoids
    never applies there.

**Guidance for a future list view**: reach for keyset when the table is
append-heavy/unbounded and users only ever page linearly forward/backward
through it (logs, event history, scan results); reach for offset when
users need to jump to an arbitrary page number, the table is naturally
bounded, or filtering/sorting by an arbitrary column matters more than
raw scale.

## Accessibility

Each open group's device table sits in a `.table-scroll` container
(`max-height: min(60vh, 32rem)`, `overflow-y: auto`,
`overscroll-behavior: contain`, sticky `<thead>`) with `tabindex="0"`,
`role="region"`, and an `aria-label` naming the group (e.g. "Devices in
10.0.1.0/24"). The chevron icon rotates via CSS on `details[open]`,
guarded by `@media (prefers-reduced-motion: reduce)`. Every pagination
control is a plain link or `<nav aria-label="Pagination">` with
`aria-current="page"` on the active page and non-focusable disabled
states (`<span aria-disabled="true">`, not a disabled `<a>`).

## Manual test steps

1. Seed a handful of devices across several subnets (a discovery scan, or
   directly via SQL for a quick check) and load `/arsenals/panopticon` --
   confirm one group per distinct `/24`/`/64`, correct device/managed
   counts, and an "Unassigned / Unknown" group for any device whose IP
   didn't parse.
2. Set `panopticon.inventory_render_budget` low (e.g. `5`) via the
   `settings` table and reload -- every group should collapse to a "Load
   devices" link; following one should open only that group and keep
   every other group's own state (still collapsed, or already open)
   intact.
3. `?subnet=10.0.1.0/24` -- confirm the grouped view is replaced by one
   filtered table with a removable chip; `?subnet=garbage` -- confirm an
   error banner instead of a 500, with the invalid input still echoed
   back into the filter box.
4. Remove a subnet group (and the "Unassigned / Unknown" group
   separately) -- confirm only that group's devices are deleted and the
   audit log records `NETWORK_SUBNET_REMOVED` with the removed IPs in its
   metadata.
5. "Re-derive subnets" -- confirm the audit log records
   `NETWORK_SUBNETS_REDERIVED` with the updated row count.
6. On the Audit Log page, page all the way from the newest entry to the
   oldest via "Older", then all the way back via "Newer" -- confirm no
   duplicate or skipped rows, and that "Newer"/"Older" correctly disable
   at either end. Export CSV and confirm the row count matches
   `SELECT COUNT(*) FROM audit_log` for the active filter.
