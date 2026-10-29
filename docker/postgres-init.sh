#!/bin/sh
# Non-executable init scripts are sourced by the image entrypoint. Keep shell
# options inside a subshell so they cannot change the entrypoint's behavior.
(
set -eu
# Run by the official image only when initializing an empty data volume.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    --set=app_password="$VULNSCOPE_DB_PASSWORD" <<'SQL'
CREATE ROLE vulnscope LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'app_password';
ALTER DATABASE vulnscope OWNER TO vulnscope;
REVOKE CONNECT ON DATABASE vulnscope FROM PUBLIC;
SQL
)
