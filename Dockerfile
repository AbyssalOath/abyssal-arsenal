# ---- Build stage ----
FROM rust:1-slim-bookworm AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation separately from actual source. This is a
# 34-crate workspace, so the dummy-source trick needs a stub for every
# member crate, not just the binaries -- otherwise `cargo build` fails
# resolving the workspace before it ever gets to compiling real dependencies.
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/database/Cargo.toml crates/database/Cargo.toml
COPY crates/auth/Cargo.toml crates/auth/Cargo.toml
COPY crates/rbac/Cargo.toml crates/rbac/Cargo.toml
COPY crates/audit/Cargo.toml crates/audit/Cargo.toml
COPY crates/notifications/Cargo.toml crates/notifications/Cargo.toml
COPY crates/execution/Cargo.toml crates/execution/Cargo.toml
COPY crates/hosts/Cargo.toml crates/hosts/Cargo.toml
COPY crates/modules/Cargo.toml crates/modules/Cargo.toml
COPY crates/agent-protocol/Cargo.toml crates/agent-protocol/Cargo.toml
COPY crates/web/Cargo.toml crates/web/Cargo.toml
COPY crates/app/Cargo.toml crates/app/Cargo.toml
COPY crates/agent/Cargo.toml crates/agent/Cargo.toml
COPY crates/arsenals/cystoolbox/Cargo.toml crates/arsenals/cystoolbox/Cargo.toml
COPY crates/arsenals/cadavault/Cargo.toml crates/arsenals/cadavault/Cargo.toml
COPY crates/arsenals/necrolink/Cargo.toml crates/arsenals/necrolink/Cargo.toml
COPY crates/arsenals/postmortem/Cargo.toml crates/arsenals/postmortem/Cargo.toml
COPY crates/arsenals/reliquary/Cargo.toml crates/arsenals/reliquary/Cargo.toml
COPY crates/arsenals/mortiscope/Cargo.toml crates/arsenals/mortiscope/Cargo.toml
COPY crates/arsenals/incarnation/Cargo.toml crates/arsenals/incarnation/Cargo.toml
COPY crates/arsenals/resurrection/Cargo.toml crates/arsenals/resurrection/Cargo.toml
COPY crates/arsenals/necropsy/Cargo.toml crates/arsenals/necropsy/Cargo.toml
COPY crates/arsenals/necropolis/Cargo.toml crates/arsenals/necropolis/Cargo.toml
COPY crates/arsenals/obituary/Cargo.toml crates/arsenals/obituary/Cargo.toml
COPY crates/arsenals/reanimation/Cargo.toml crates/arsenals/reanimation/Cargo.toml
COPY crates/arsenals/ossuary/Cargo.toml crates/arsenals/ossuary/Cargo.toml
COPY crates/arsenals/catacomb/Cargo.toml crates/arsenals/catacomb/Cargo.toml
COPY crates/arsenals/parish/Cargo.toml crates/arsenals/parish/Cargo.toml
COPY crates/arsenals/apothecary/Cargo.toml crates/arsenals/apothecary/Cargo.toml
COPY crates/arsenals/grimoire/Cargo.toml crates/arsenals/grimoire/Cargo.toml
COPY crates/arsenals/cryptkeeper/Cargo.toml crates/arsenals/cryptkeeper/Cargo.toml
COPY crates/arsenals/defleshing/Cargo.toml crates/arsenals/defleshing/Cargo.toml
COPY crates/arsenals/vivisection/Cargo.toml crates/arsenals/vivisection/Cargo.toml
COPY crates/arsenals/inquest/Cargo.toml crates/arsenals/inquest/Cargo.toml

RUN for crate in core database auth rbac audit notifications execution hosts modules agent-protocol web \
        arsenals/cystoolbox arsenals/cadavault arsenals/necrolink arsenals/postmortem arsenals/reliquary \
        arsenals/mortiscope arsenals/incarnation arsenals/resurrection arsenals/necropsy arsenals/necropolis \
        arsenals/obituary arsenals/reanimation arsenals/ossuary arsenals/catacomb arsenals/parish \
        arsenals/apothecary arsenals/grimoire arsenals/cryptkeeper arsenals/defleshing arsenals/vivisection \
        arsenals/inquest; do \
        mkdir -p crates/$crate/src && echo "// stub" > crates/$crate/src/lib.rs; \
    done \
    && mkdir -p crates/app/src && echo "fn main() {}" > crates/app/src/main.rs \
    && mkdir -p crates/agent/src && echo "fn main() {}" > crates/agent/src/main.rs \
    && cargo build --release --workspace \
    && rm -rf crates/*/src crates/arsenals/*/src

COPY crates crates
COPY migrations migrations
# Force cargo to see the real source as newer than the dummy files it
# already compiled above, so a rebuild after a code change only recompiles
# what actually changed, not every dependency.
RUN find crates -name '*.rs' -exec touch {} + \
    && cargo build --release --bin abyssal-arsenal

# ---- Runtime stage ----
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /app --shell /usr/sbin/nologin abyssal

COPY --from=builder /build/target/release/abyssal-arsenal /app/abyssal-arsenal
COPY crates/web/static /app/static

# Migrations are embedded into the binary at compile time by
# sqlx::migrate!() (see crates/database/src/pool.rs) -- nothing to copy at
# runtime for them.
RUN chown -R abyssal:abyssal /app
USER abyssal

EXPOSE 8080
CMD ["/app/abyssal-arsenal"]
