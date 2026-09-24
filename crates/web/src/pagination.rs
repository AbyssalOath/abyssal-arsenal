//! Shared offset/limit and keyset (cursor) pagination -- GitHub issue #10.
//! One place to get "clamp the params, compute page counts, preserve
//! other query params on page links" right, rather than every list view
//! hand-rolling its own. See `docs/device-inventory.md` for the full
//! design (render budget, `open`/group-page params) and
//! `templates/_pagination.html` for the shared Askama partial this
//! drives.

pub const DEFAULT_PER_PAGE: u32 = 25;
pub const MAX_PER_PAGE: u32 = 200;

/// Clamps a requested `page`/`per_page` pair to something safe to run a
/// query with: `per_page` bounded to `[1, max_per_page]`, `page` bounded
/// to at least `1` (an out-of-range *high* page isn't rejected here --
/// see `Page::clamp_to_valid_range`, which needs the actual total first).
pub fn normalize(
    page: Option<u32>,
    per_page: Option<u32>,
    default_per_page: u32,
    max_per_page: u32,
) -> (u32, u32) {
    let per_page = per_page.unwrap_or(default_per_page).clamp(1, max_per_page);
    let page = page.unwrap_or(1).max(1);
    (page, per_page)
}

/// `(page - 1) * per_page`, saturating rather than panicking on a
/// pathological combination (shouldn't happen once `normalize` has run,
/// but this is cheap insurance against a future caller skipping it).
pub fn offset(page: u32, per_page: u32) -> i64 {
    i64::from(page.saturating_sub(1)).saturating_mul(i64::from(per_page))
}

pub fn total_pages(total: u64, per_page: u32) -> u32 {
    if total == 0 || per_page == 0 {
        1
    } else {
        (total.div_ceil(u64::from(per_page))) as u32
    }
}

/// One page of `T`, plus everything a pagination UI needs to render
/// itself -- the generic result type every offset-paginated repo
/// function/route in this app should return.
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
    pub total_pages: u32,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, page: u32, per_page: u32, total: u64) -> Self {
        Self {
            items,
            page,
            per_page,
            total,
            total_pages: total_pages(total, per_page),
        }
    }

    pub fn has_prev(&self) -> bool {
        self.page > 1
    }

    pub fn has_next(&self) -> bool {
        self.page < self.total_pages
    }

    /// 1-based index of the first item on this page, for "Showing X-Y of
    /// Z" -- `0` (not `1`) when there are no items at all, so the
    /// template can render "Showing 0 of 0" instead of a nonsensical
    /// "Showing 1-0".
    pub fn start_index(&self) -> u64 {
        if self.total == 0 {
            0
        } else {
            u64::from(self.page.saturating_sub(1)) * u64::from(self.per_page) + 1
        }
    }

    pub fn end_index(&self) -> u64 {
        (u64::from(self.page) * u64::from(self.per_page)).min(self.total)
    }

    /// Whether `page` is past the last real page for `total` -- the
    /// caller's cue to redirect to the last valid page (or an empty
    /// state) instead of running a query for a page that can't have any
    /// rows, per the "never a 500 on an out-of-range page" requirement.
    pub fn page_out_of_range(page: u32, per_page: u32, total: u64) -> bool {
        page > total_pages(total, per_page) && total > 0
    }
}

/// Page numbers to actually render as links, with `None` standing in for
/// an ellipsis -- always includes page 1, the last page, the current
/// page, and one neighbor on each side; collapses everything else. E.g.
/// for page 7 of 20: `[1, None, 6, 7, 8, None, 20]`.
pub fn page_window(current: u32, total_pages: u32) -> Vec<Option<u32>> {
    if total_pages <= 1 {
        return vec![Some(1)];
    }
    let mut pages: Vec<u32> = vec![1, total_pages];
    for p in current.saturating_sub(1)..=current.saturating_add(1) {
        if p >= 1 && p <= total_pages {
            pages.push(p);
        }
    }
    pages.sort_unstable();
    pages.dedup();

    let mut window = Vec::with_capacity(pages.len() * 2);
    let mut prev: Option<u32> = None;
    for p in pages {
        if let Some(prev_p) = prev
            && p > prev_p + 1
        {
            window.push(None);
        }
        window.push(Some(p));
        prev = Some(p);
    }
    window
}

/// Builds `base_path?...` with every pair in `params` re-encoded (in
/// their given order) plus `page` set to `page` -- the one place every
/// pagination link in the app builds its query string, so "preserve
/// every other filter/sort param, only change `page`" is guaranteed
/// rather than re-implemented per view. `params` should already exclude
/// any existing `page` entry (callers build it from the request's own
/// non-page params).
pub fn page_link(base_path: &str, params: &[(&str, &str)], page: u32) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        serializer.append_pair(k, v);
    }
    serializer.append_pair("page", &page.to_string());
    format!("{base_path}?{}", serializer.finish())
}

/// A keyset (cursor) page for append-heavy/huge tables (audit logs,
/// event history) -- "Newer"/"Older" links instead of numbered pages,
/// and no `COUNT(*)` over the whole table. `next_cursor`/`prev_cursor`
/// are opaque to the caller (in practice, usually a row's own id or
/// timestamp, base-encoded by whichever repo function produced this);
/// `None` means "there is no further page in that direction."
#[derive(Debug, Clone)]
pub struct CursorPage<T> {
    pub items: Vec<T>,
    pub newer_cursor: Option<String>,
    pub older_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_applies_defaults_when_nothing_is_requested() {
        assert_eq!(normalize(None, None, 25, 200), (1, 25));
    }

    #[test]
    fn normalize_clamps_per_page_to_the_max() {
        assert_eq!(normalize(Some(1), Some(9999), 25, 200), (1, 200));
    }

    #[test]
    fn normalize_clamps_per_page_to_at_least_one() {
        assert_eq!(normalize(Some(1), Some(0), 25, 200), (1, 1));
    }

    #[test]
    fn normalize_clamps_page_to_at_least_one() {
        assert_eq!(normalize(Some(0), None, 25, 200), (1, 25));
    }

    #[test]
    fn offset_is_zero_on_the_first_page() {
        assert_eq!(offset(1, 25), 0);
    }

    #[test]
    fn offset_advances_by_per_page_each_page() {
        assert_eq!(offset(3, 25), 50);
    }

    #[test]
    fn total_pages_rounds_up() {
        assert_eq!(total_pages(51, 25), 3);
        assert_eq!(total_pages(50, 25), 2);
        assert_eq!(total_pages(0, 25), 1);
    }

    #[test]
    fn page_out_of_range_is_true_past_the_last_page() {
        assert!(Page::<()>::page_out_of_range(3, 25, 50));
        assert!(!Page::<()>::page_out_of_range(2, 25, 50));
    }

    #[test]
    fn page_out_of_range_is_false_for_an_empty_table() {
        // Page 1 of an empty table is the correct "empty state" page, not
        // an out-of-range one.
        assert!(!Page::<()>::page_out_of_range(1, 25, 0));
    }

    #[test]
    fn start_and_end_index_are_correct_mid_list() {
        let page: Page<()> = Page::new(vec![], 3, 25, 120);
        assert_eq!(page.start_index(), 51);
        assert_eq!(page.end_index(), 75);
    }

    #[test]
    fn end_index_is_clamped_to_the_actual_total_on_the_last_page() {
        let page: Page<()> = Page::new(vec![], 5, 25, 110);
        assert_eq!(page.start_index(), 101);
        assert_eq!(page.end_index(), 110);
    }

    #[test]
    fn start_index_is_zero_when_the_table_is_empty() {
        let page: Page<()> = Page::new(vec![], 1, 25, 0);
        assert_eq!(page.start_index(), 0);
        assert_eq!(page.end_index(), 0);
    }

    #[test]
    fn small_page_counts_render_without_an_ellipsis() {
        assert_eq!(page_window(1, 3), vec![Some(1), Some(2), Some(3)]);
    }

    #[test]
    fn a_middle_page_of_a_long_list_collapses_with_ellipses_on_both_sides() {
        assert_eq!(
            page_window(10, 20),
            vec![Some(1), None, Some(9), Some(10), Some(11), None, Some(20)]
        );
    }

    #[test]
    fn near_the_start_only_the_trailing_ellipsis_appears() {
        assert_eq!(page_window(1, 20), vec![Some(1), Some(2), None, Some(20)]);
    }

    #[test]
    fn page_link_preserves_other_params_and_sets_page() {
        let link = page_link("/arsenals/panopticon", &[("port", "22")], 3);
        assert_eq!(link, "/arsenals/panopticon?port=22&page=3");
    }

    #[test]
    fn page_link_url_encodes_param_values() {
        let link = page_link("/x", &[("subnet", "10.0.1.0/24")], 1);
        assert_eq!(link, "/x?subnet=10.0.1.0%2F24&page=1");
    }
}
