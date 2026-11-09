# Owner-authorized SQLite download

```console
day2 app sqlite download reports --output /private/reports.sqlite --request-id download-1
```

This uses the saved human app session and current `sqlite.download` ownership.
Local operator assertions cannot authenticate it. The platform captures one
consistent SQLite read transaction and creates a fresh database containing only
admitted business model tables and columns, including soft-deleted business
rows. It excludes framework sessions, OAuth/credential stores, provider secret
metadata, audit/replay history, framework schema and source freelist pages.
Rollups and internal runtime indexes are excluded. This is a debugging export;
it is not a restorable platform backup.

There is no SQL, path, table or database selector in the remote request. The
platform bounds rows to 100,000 and the resulting database to 16 MiB, validates
constraints and rechecks current authority before returning bytes. Admission and
preparation have metadata-only audit records; preparation is not proof that the
client received the response.

The client checks app scope, actor, authority, request ID, admitted artifact,
content type, no-store headers and SQLite file signature. It creates a new
mode-0600 file exclusively and never overwrites a file or symlink. No database
bytes enter JSON output. Filesystem parent directories remain trusted. An
interrupted download may leave a private partial file; inspect/remove it before
using a new destination and request ID. HTTP requests are never retried.

Snapshot catalogs, historical backup download, arbitrary remote queries, import
and restore remain separate operations. Local tests do not qualify hosted login.
