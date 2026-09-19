# abyssal-workflows

Contextual Arsenal Workflow Navigation: lets an arsenal's result page offer
"go investigate this in another arsenal" buttons, driven entirely by data in
`registry.json`, with no arsenal-to-arsenal code dependency.

## Registry schema

`registry.json` is a JSON array of entries shaped like:

```json
{
  "source_arsenal": "cystoolbox",
  "source_action": "resource_usage_disk",
  "condition": { "field": "usage_percent", "operator": "greater_than_or_equal", "value": 90 },
  "target_arsenal": "catacomb",
  "target_action": "directory_usage_breakdown",
  "label": "Investigate {mount_point} with Catacomb",
  "context_fields": ["mount_point", "usage_percent"]
}
```

- `source_arsenal` / `source_action`: which structured result this entry
  reacts to. `source_action` is a stable name the source arsenal's web route
  chooses for the structured payload it emits (e.g. Cystoolbox's Resource
  Usage page emits one `resource_usage_disk` result per filesystem) -- it
  does not have to match a URL path. Most `source_action`s are evaluated
  against a *successful* result, but nothing about the evaluator requires
  that: Reliquary's `backup_write_failed` evaluates a failed operation's
  error text instead (see `crates/web/src/routes/reliquary.rs`,
  `backup_error_suggestions`, which wraps `common::suggested_actions_for`
  the same way every other source action does), matching a real, stable
  error string
  (`"Read-only file system"`) with the ordinary `contains` operator. The
  registry itself doesn't know or care which case it is -- both are just a
  field on a JSON object.
- `condition`: either one field comparison (a "leaf"), or an `all`/`any`
  group of nested conditions (AND/OR respectively):

  ```json
  { "field": "usage_percent", "operator": "greater_than_or_equal", "value": 90 }
  ```

  ```json
  {
    "all": [
      { "field": "usage_percent", "operator": "greater_than_or_equal", "value": 90 },
      { "any": [
        { "field": "mount_point", "operator": "equals", "value": "/tmp" },
        { "field": "mount_point", "operator": "equals", "value": "/var/tmp" }
      ]}
    ]
  }
  ```

  Groups can nest arbitrarily. An empty `all` is vacuously true and an empty
  `any` is vacuously false (the usual boolean fold over zero terms), but a
  registry entry shouldn't actually write one.

  Supported `operator` values: `equals`, `not_equals`, `greater_than_or_equal`,
  `less_than`, `contains`, `starts_with`, `ends_with`, `matches` (regex against
  a string field; `value` is the pattern), and `exists` (ignores `value`).
  `contains`/`starts_with`/`ends_with`/`matches` only match when the field's
  value is a string.
- `target_arsenal` / `target_action`: which arsenal/action the button points
  at. `target_action` is still informational rather than routing -- every
  suggestion always links to the target arsenal's own host landing page.
  What Phase 6 added is that landing page itself now reads the context back
  out of the query string: see "Context-aware destination pages" below.
- `label`: button text. `{field_name}` is substituted with that field's
  value from the matched structured result.
- `context_fields`: which fields of the structured result get copied into
  the target URL's query string when this entry matches.

Adding a new workflow relationship means adding an entry to `registry.json`
-- no changes to the evaluator in `src/evaluator.rs`.

Most structured payloads are parsed entirely on the control-plane side from
an agent operation's existing text output, so they take effect immediately.
Cryptkeeper's `certificate_detail` is the one exception so far: the agent
now also runs `openssl x509 -noout -enddate` and appends it under its own
`== Expiry ==` section (`crates/agent/src/cryptkeeper.rs`) so the expiry
date has a stable, machine-parseable line to read instead of grepping the
full `-text` dump. That means an already-deployed agent needs rebuilding
and redeploying before the `days_until_expiry` field -- and any suggestion
based on it -- actually appears; until then the parser just finds no
`== Expiry ==` section and produces nothing, same as any other missing
field.

## Context-aware destination pages

Every destination arsenal's `show_host` now accepts the incoming query
string (`axum::extract::Query<HashMap<String, String>>`) and does two
things with it, neither of which executes anything automatically -- the
user still has to click "run":

- **Always**: `crate::common::workflow_context_rows` picks out whichever of
  the registry's known `context_fields` (a fixed, labeled list in
  `crates/web/src/common.rs` -- `KNOWN_CONTEXT_FIELDS`) are present, and the
  page renders them in an `.info-banner` reading "Arrived here from a
  suggested next step, with: ...". An unrecognized query parameter is never
  shown. Adding a new context field to a registry entry means adding it to
  that list too, or it'll sit in the URL unrendered.
- **Where a real field exists**: a handful of destinations pre-fill the one
  form field that actually matches the incoming context, so the user's next
  click does what the suggestion promised instead of retyping it:
  Catacomb's Directory Usage Breakdown path (from `mount_point`),
  Necropsy's Disk Health device (from `source`/`device`), Ossuary's
  Partition Table device (from `device`, when present -- not every
  suggestion into Ossuary names one), Reanimation's Process Detail PID
  (from `pid`), and Reliquary's Create Backup source path (from
  `mount_point` -- arriving here because a filesystem is going read-only is
  exactly a "make sure this still has a backup" moment). Every other
  destination (Defleshing, Vivisection, Inquest, Postmortem, Incarnation,
  Resurrection) only has the banner, because nothing on those pages takes a
  field the passed context maps to (e.g. a PID or a byte count isn't
  anything Vivisection's no-argument profiling reads take).

## Observability: evaluation failures

`WorkflowRegistry::evaluate` returns an `EvaluationOutcome { matches,
failures }`, not just a list of matches. `failures` is for genuine registry
authoring bugs only (currently: an invalid regex pattern on a `matches`
condition) -- an ordinary missing or wrong-shaped field is never reported
here, because that's the normal, expected case for a structured result that
doesn't carry every field every condition might check (see "Safety
properties" below).

This crate stays pure and never performs I/O -- it only returns the
failures as data. `crate::common::suggested_actions_for` in `abyssal-web`
(the one function every source arsenal's read handler goes through) is what
turns a non-empty `failures` list into something admin-visible: it persists
each one to the audit trail as a `WORKFLOW_EVALUATION_FAILED` entry, with
the exact source/target arsenal-action pair, the field, and the error
message as `resource`/`metadata`, so an admin can find it on the Obituary
audit log (`/admin/audit?action=WORKFLOW_EVALUATION_FAILED`) instead of
only in server logs. The underlying `tracing::warn!` in
`evaluator::regex_matches` still fires too, unconditionally -- the audit
record is additional, not a replacement.

Evaluation also never short-circuits: every leaf in a compound `all`/`any`
tree is visited even after the group's boolean answer is already decided,
so a bad regex on a sibling branch is never hidden just because it stopped
mattering to the outcome.

## Admin registry view

`/admin/workflows` (gated by `modules.manage`, the same permission as the
Modules admin page) lists every entry currently compiled into the
registry -- source, a human-readable rendering of the condition
(`Condition::describe`, e.g. `all(usage_percent >= 90, any(mount_point ==
"/tmp", mount_point == "/var/tmp"))`), target, label, and which context
fields get passed. It's read-only: there's no form to edit an entry from
there, on purpose (see "Adding a new workflow relationship" below for why).
It exists purely so an admin debugging "why didn't that button show up" can
check what the registry actually says without reading `registry.json` or
redeploying to add a debug print.

## Adding a new workflow relationship

Registries evolve by editing `registry.json` and redeploying, not by
changing evaluator code. The checklist, in order:

1. **Make sure the source action has a structured payload.** If the
   arsenal's route handler doesn't already parse its text output into a
   `serde_json::Value` (see e.g. `cystoolbox::disk_usage_entries`), add
   that first -- purely additive, the existing rendered text output must
   stay unchanged. Pick a `source_action` name (doesn't need to match a URL
   path) and keep it stable once entries reference it.
2. **Add one or more entries to `registry.json`** naming the condition,
   target, label, and `context_fields`. Use the narrowest operator that
   expresses the real signal (prefer `equals`/`exists` over `matches`
   unless you actually need a regex).
3. **Wire the source handler through `crate::common::suggested_actions_for`**
   (or, for an error-path source like Reliquary's, evaluate the error
   string the same way) so matches render as buttons and any failures are
   audited.
4. **Add the new context field(s) to `KNOWN_CONTEXT_FIELDS`** in
   `crates/web/src/common.rs` if you introduced one the destination page
   should show in its "arrived here because..." banner -- otherwise it
   sits in the query string unrendered (see "Context-aware destination
   pages" below).
5. **Optionally, pre-fill a real destination form field** if the target
   page has one that genuinely matches a context field (see Catacomb,
   Necropsy, Ossuary, Reanimation, Reliquary for the pattern) -- most
   relationships won't have one, and that's fine; the context banner alone
   is still "context-aware."
6. **Check `/admin/workflows`** after redeploying to confirm the entry
   parses and reads the way you intended.
7. **Add unit tests** for the new parser (if any) and for the registry
   match/non-match/missing-field cases, following the existing tests in
   the source arsenal's route file and `crates/workflows/src/evaluator.rs`.

## Safety properties

- A missing or wrong-shaped field makes its condition evaluate to `false`;
  the evaluator never panics or returns an error. This applies even to
  `not_equals`: a missing field is "no match," not vacuously "not equal."
- An actual authoring failure in the registry itself -- currently, an
  invalid regex pattern on a `matches` condition -- is logged (via
  `tracing::warn!`) and recorded to the audit trail (see "Observability"
  above), but still resolves to "no match" rather than blocking the source
  action's own result from rendering.
- Evaluation is read-only. It only inspects the structured result and the
  registry -- it cannot trigger a system operation, and multiple matching
  entries all render rather than the evaluator picking a "best" one.
- Clicking a suggested action always navigates to the target arsenal's own
  page; that page still requires its own explicit user action (and its own
  permission checks) to actually do anything.
