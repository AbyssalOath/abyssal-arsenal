# Desktop (Tauri) -- not yet built

The Tauri desktop client is deferred. See [CHANGELOG.md](../CHANGELOG.md)
and [ARCHITECTURE.md](../ARCHITECTURE.md) for current project status. It
will authenticate against the same Axum backend and reuse the same
`/api/*` JSON endpoints the web UI's `/api/health` and `/api/me` routes
already establish -- no business logic duplicated here when it's built.
