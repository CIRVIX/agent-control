# `cirvix/scan`

Find the AI agent runtimes, MCP servers, and reachable credentials in a
repository that nothing is governing — on every pull request.

```yaml
- uses: cirvix/scan@v1
```

That is the whole minimum. It scans the checkout, writes a job summary,
annotates blocking findings on the diff, uploads SARIF to code scanning, and
fails the job on anything high.

## First run on an existing repository

Do not gate a merge on the first scan. Look at the baseline:

```yaml
- uses: cirvix/scan@v1
  with:
    fail-on: never
```

Then tighten once you know what is there.

## A realistic workflow

```yaml
name: Agent governance

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      # Required to put findings in the Security tab and on the diff.
      security-events: write
      # Only needed for comment-on-pr.
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: cirvix/scan@v1
        with:
          fail-on: high
          comment-on-pr: true
```

Without `security-events: write` the upload step is skipped rather than
failing the job — the scan is still useful, the findings just stay in the
summary.

## Inputs

| Input | Default | |
|---|---|---|
| `fail-on` | `high` | `high`, `medium`, `low`, or `never` |
| `working-directory` | `.` | Directory to scan |
| `sarif-file` | `cirvix-scan.sarif` | Empty string to skip SARIF |
| `upload-sarif` | `true` | Send findings to code scanning |
| `comment-on-pr` | `false` | One comment, edited in place on each push |
| `version` | `latest` | Version of `@cirvix/agent-control` to run |

## Outputs

`high`, `medium`, `low`, `passed`, and `findings` (the full JSON), so a
workflow can branch without re-running the scan:

```yaml
- uses: cirvix/scan@v1
  id: cirvix
  with:
    fail-on: never
- if: steps.cirvix.outputs.high != '0'
  run: echo "::notice::${{ steps.cirvix.outputs.high }} high findings"
```

## What it does not do

- **It does not send your code anywhere.** The scan reads local configuration
  files and reports what it finds. Nothing is uploaded except the SARIF you
  asked GitHub to store.
- **It does not execute anything.** No agent runs, no tool is called.
- **It reports reachability, not wrongdoing.** "This runtime can read
  `.env.production`" is not a claim that it did. That distinction is in the
  summary text on purpose, because a security report that overstates gets
  discounted entirely the first time somebody checks one.

## Why a composite action

There is no committed `dist/` bundle. A JavaScript action ships one, it has to
be rebuilt on every change, and in practice it is the thing that goes stale.
The CLI has zero runtime dependencies, so `npx @cirvix/agent-control` is a
smaller and more honest supply chain than a vendored bundle nobody re-reads.

Pin `version` if you would rather not track `latest`.
