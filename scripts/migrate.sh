#!/bin/bash
set -e
cd "$(dirname "$0")/.."

# Loads .env into this shell's environment (set -a exports every variable
# assigned while it's on) just for the duration of the sqlx-cli command, so
# you don't have to `export DATABASE_URL=...` by hand each time.
set -a
source .env
set +a

sqlx migrate "$@"
