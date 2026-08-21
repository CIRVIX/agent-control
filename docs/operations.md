# Operations guide

Running a Cirvix control plane: what to watch, what to back up, how to upgrade,
and where it stops scaling.

## Monitoring

Scrape `/metrics`. It is public by default because a scraper on a private
network cannot easily carry a bearer token, and the payload contains counts
rather than tenant data. Set `CIRVIX_METRICS_TOKEN` to require one when the port
is exposed.

### Metrics

| Metric | Type | Labels |
|---|---|---|
| `cirvix_up` | gauge | — |
| `cirvix_http_requests_total` | counter | `route`, `method`, `status` |
| `cirvix_http_request_duration_seconds` | histogram | `route`, `method` |
| `cirvix_decisions_total` | counter | `verdict` |
| `cirvix_policy_evaluation_seconds` | histogram | — |
| `cirvix_alerts_delivered_total` | counter | `outcome` |
| `cirvix_endpoints` | gauge | `state` |
| `cirvix_agents` | gauge | — |
| `cirvix_organizations` | gauge | — |
| `cirvix_approvals_pending` | gauge | — |
| `cirvix_stream_subscribers` | gauge | — |
| `cirvix_audit_chain_verified` | gauge | — |

`route` is the route **pattern**, not the resolved path, so
`/v1/decisions/:decisionId` is one series rather than one per decision.

`cirvix_policy_evaluation_seconds` is the gateway's own measurement of the
decision, excluding the tool round trip.

### The three alerts that matter

```yaml
- alert: CirvixAuditChainTampered
  expr: cirvix_audit_chain_verified == 0
  for: 1m
  labels: { severity: critical }
  annotations:
    summary: "A Cirvix audit chain no longer verifies"
    description: "A record was altered or removed. Check /v1/audit/verify."

- alert: CirvixEndpointsStale
  expr: cirvix_endpoints{state="stale"} > 0
  for: 5m
  labels: { severity: high }
  annotations:
    summary: "Endpoints stopped reporting — agents may be running ungoverned"

- alert: CirvixApprovalBacklog
  expr: cirvix_approvals_pending > 5
  for: 15m
```

**Stale endpoints are the one to take seriously.** An endpoint going quiet means
an agent may be running with no enforcement, and it is the only condition
nothing else can detect — the endpoint cannot report that it stopped reporting.

**A tampered chain is a critical, not a page-in-the-morning.** Tamper-evidence
is only useful if someone is told; a chain that breaks and is never checked
provides exactly nothing.

The control plane also raises both of these as in-product alerts on its own
sweeps, delivered through your configured channels.

## Backup

One file, plus its WAL:

```bash
sqlite3 /var/lib/cirvix/cirvix.db ".backup '/backups/cirvix-$(date +%F).db'"
```

Use `.backup`, **not** `cp` — copying a live WAL database can capture a torn
state.

### Verify the restore

A restore that restores is not the same as a restore that verifies:

```bash
curl -s $CIRVIX_API/v1/audit/verify -H "authorization: Bearer cvx_..."
# {"ok":true,"records":43675}
```

If this returns `ok: false` on a restored database, the backup captured a torn
state or the file was modified. Restore an earlier one.

### What is not in the database

- **`CIRVIX_JWT_SECRET`** — losing it signs everyone out. Not fatal.
- **`CIRVIX_MASTER_KEY`** — losing it loses **every stored secret**,
  permanently. There is no escrow.

Back both up wherever you keep other root credentials, and **never in the same
place as the database**. A backup that contains the ciphertext and the key that
opens it is not a backup, it is a copy of the secrets.

## Upgrades

Migrations run automatically at boot: forward-only, each inside a transaction
with its version bump. A failed migration leaves the schema untouched and the
process exits rather than serving against a half-applied schema.

**Take a backup first. There is no down-migration.**

Current schema: version **8**.

| Version | Name |
|---|---|
| 1 | `initial_schema` |
| 2 | `secret_handles` |
| 3 | `alert_channels` |
| 4 | `secret_usages_allow_unknown_handle` |
| 5 | `sso_and_invitations` |
| 6 | `policy_governance` |
| 7 | `runs_and_replay` |
| 8 | `scim_provisioning` |

Check what is applied:

```bash
sqlite3 /var/lib/cirvix/cirvix.db 'SELECT MAX(version) FROM schema_migrations'
```

### Rolling an upgrade

1. Back up and verify the backup.
2. Deploy the new image. Migrations run at boot.
3. `curl /health` and confirm the version.
4. `curl /v1/audit/verify` and confirm the chain still verifies.

Endpoints keep enforcing throughout — they hold a cached rule set and spool
telemetry, so a control plane restart is not an enforcement outage.

## Scaling boundary

**Read this before you scale.**

The bundled store is SQLite, which is **single-writer**. The Helm chart refuses
`replicaCount > 1` for that reason: two pods against one volume corrupt it.

This is correct for a single-node deployment or a customer VPC, which is the
enterprise deployment model. For multi-instance horizontal scale, migrate to
Postgres — the schema is portable SQL and every query goes through
`src/db/index.mjs`.

**Enforcement is unaffected by this boundary.** Every gateway and every wrapped
agent decides locally. Adding agents adds telemetry ingest, not decision load.
The control plane is not on the hot path.

### What actually runs out first

| Pressure | Symptom | Response |
|---|---|---|
| Telemetry ingest | `POST /v1/decisions` latency climbs | Increase daemon `--interval`; batch more per flush |
| Audit growth | Disk, ~1 KB per decision | Provision disk; export and prune cold decisions |
| SSE connections | `cirvix_stream_subscribers` climbing | Each open console holds one. Bound with a proxy `worker_connections` |
| Write contention | SQLite `SQLITE_BUSY` in logs | You are at the boundary. Move to Postgres |

## Key rotation

| Key | Effect of rotating | Downtime |
|---|---|---|
| `CIRVIX_JWT_SECRET` | Every session invalidated; everyone signs in again | None, but visible |
| `CIRVIX_MASTER_KEY` | **Every stored secret becomes unreadable** | Maintenance window |
| An API key | That credential stops working immediately | None |
| A SCIM token | Provisioning stops until the provider is updated | None |

Rotating the master key means re-entering every secret. Plan it as a maintenance
window rather than a config change:

1. Export the list of secret names and destinations (`GET /v1/secrets` — values
   are never returned).
2. Stop the control plane.
3. Set the new key, start it.
4. Re-enter each value.

## Incident: an agent did something unexpected

The path through the tooling:

```bash
cirvix why dec_01JQ8F2K7M          # what was decided, and which run it belongs to
cirvix replay run_01JQ8F2K7M       # would today's rules have stopped it?
```

`why` names the run, which is the thread to pull — not just the one bead you
arrived holding. `replay` re-decides every step of that run under current
policy and **executes nothing**.

Then, if the answer is "no":

```bash
cirvix replay run_01JQ8F2K7M --policy candidate.json --diff
```

Iterate on `candidate.json` until the run comes out the way it should, then take
it through [governance](./administration.md#policy-governance). Exit code `1`
when anything changed makes this usable as a CI gate.

## Incident: the audit chain broke

1. `GET /v1/audit/verify` — note `brokenAt` and `records`.
2. Everything **before** `brokenAt` is still intact and still trustworthy. The
   chain localises the damage; it does not invalidate the whole log.
3. Compare against the most recent verified backup to establish what changed.
4. Treat host access as compromised until shown otherwise — a broken chain means
   something wrote to the database outside the API.

The chain does not prevent destruction. Someone with disk access can delete the
file. What it guarantees is that doing so is *visible*.

## Retention

There is no automatic pruning. Decisions, runs, audit records, and alert
deliveries accumulate.

Export before pruning, or the evidence goes with it:

```bash
curl -s "$CIRVIX_API/v1/export?format=cef&since=2026-01-01" \
  -H "authorization: Bearer $TOKEN" > decisions.cef
```

Formats include CEF (ArcSight, ingested by every SIEM without a custom parser).

Pruning audit records **breaks the chain by design** — that is the point of a
hash chain. If you must prune, archive the removed range and record the
checkpoint hash at the cut, so the remaining chain can be anchored to it.

## Runbook summary

| Symptom | First check |
|---|---|
| Console cannot reach the API | `NEXT_PUBLIC_CIRVIX_API` matches the built origin |
| Console reconnects forever | Proxy buffering / read timeout on SSE |
| Endpoint stale, daemon running | Outbound 443 egress; daemon logs for `sync failed` |
| `/v1/secrets` returns 503 | `CIRVIX_MASTER_KEY` not set |
| Everyone signed out at once | JWT secret rotated, or refresh reuse detected |
| Migration failed | Schema unchanged; capture the error and `MAX(version)` |

Full detail: [Troubleshooting](./troubleshooting.md).
