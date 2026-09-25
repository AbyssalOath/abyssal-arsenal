-- Thanatos SIEM/EDR build-out, Phase 0: persist the platform a managed host
-- actually reports, rather than assuming every `Host` row is Linux (the
-- assumption baked into this app's doc comments up to this point). `os` is
-- whatever `std::env::consts::OS` gives the agent binary at compile time
-- ("linux", "windows", "macos", ...) -- a coarse platform family, not a
-- full distro/version string. `agent_version` is the agent binary's own
-- Cargo package version. Both are reported at every WebSocket connect (see
-- `X-Agent-Os`/`X-Agent-Version` headers, `crates/agent/src/transport.rs`)
-- and are NULL for a host that has never connected under agent builds new
-- enough to send them.
ALTER TABLE hosts
    ADD COLUMN os VARCHAR(32) NULL AFTER last_seen_ip,
    ADD COLUMN agent_version VARCHAR(32) NULL AFTER os;
