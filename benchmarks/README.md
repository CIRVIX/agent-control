# Benchmarks

The complementary system benchmark measures process startup, steady-state
decision latency, decisions per second, RSS memory, and separate audit append
overhead:

```bash
node benchmarks/system.mjs --json
```

Do not combine its audit and non-audit numbers into one latency claim; the
audit path is durable filesystem I/O and depends on the disk.

```bash
node benchmarks/decision.mjs
```

| Flag | What it does |
|---|---|
| `--full` | adds the 1,000,000-decision run (~80s) |
| `--record` | writes the result into `results.json`, keyed by platform |
| `--matrix` | prints the coverage table and exits |
| `--audit` | includes the audit-chain append (fsync-bound) |
| `--json` | machine-readable |
| `--n <count>` | one extra run at an arbitrary size |

## Coverage

```bash
node benchmarks/decision.mjs --matrix
```

Rows that have not been run print **not measured**. They are absent rather than
estimated, because an estimated latency row is indistinguishable from a measured
one once it is in a table — and the first person to reproduce it finds out which
kind it was.

To fill one in, run on that machine:

```bash
node benchmarks/decision.mjs --record --full
```

For the container row:

```bash
docker build -f benchmarks/Dockerfile -t cirvix-bench .
docker run --rm -v "$PWD/benchmarks:/app/benchmarks" cirvix-bench
```

The bind mount matters — without it the row is written inside the container and
discarded on exit.

**A WSL2-hosted container is not a Linux host measurement.** The
`docker-linux-x86_64` row currently in `results.json` was recorded under Docker
Desktop on WSL2 — a real Linux kernel and a real container on x86_64, so it is
an honest *container* row, and it is not the same thing as a native Linux
server. The kernel string is stored in the row's `environment.platform`
(`…microsoft-standard-WSL2…`) so the distinction survives being quoted. The
`linux-x86_64` row stays empty until something measures a Linux host.

`.github/workflows/benchmark-matrix.yml` fills the remaining rows on real
runners. It is `workflow_dispatch` plus a monthly schedule, because a benchmark
that runs on every commit becomes a benchmark nobody reads.

**Emulated ARM is not an ARM measurement.** `--platform linux/arm64` under QEMU
runs, and its numbers describe QEMU. Record the ARM rows on real silicon only;
there is no "emulated" column because a number qualified in a footnote gets
quoted without the footnote.

## What is measured

Wall-clock time inside `Pipeline.submit()` — parse, normalize, secret scan, risk
classification, policy evaluation, approval check, argument substitution.
Everything Cirvix adds to a tool call.

## What is not measured, and why

**The upstream tool round trip.** A local filesystem read is single-digit
milliseconds; a hosted MCP call is hundreds. Including either would bury the
engine's contribution in the transport and produce a flattering number that
describes the network.

**The audit append**, unless you pass `--audit`. It is an fsync-bound filesystem
write whose cost is a property of the disk, not the engine. Report it
separately; folding it in makes a comparison across machines meaningless.

**GC pauses are included.** They are real latency a real caller experiences.
Excluding them is the standard way a P99 becomes fiction.

## Methodology

- Warmup of `min(2000, max(200, n/10))` iterations, excluded from the sample and
  reported in the output. A JIT-compiled runtime has a fast first number and a
  different steady state; measuring the first one is measuring the interpreter.
- Sample array preallocated as a `Float64Array` — growing an array mid-run is
  itself measurable.
- Percentiles by nearest-rank on the full sorted sample. No interpolation, no
  sampling, no trimming.
- The workload is a weighted mix, not the cheapest call repeated: 30% file
  reads, 15% `git status`, 10% writes, 8% shell, 6% HTTP with a body to scan, 5%
  credential denials, and so on. Benchmarking `git.status` alone measures the
  fast path and reports it as the product's latency.

## Targets

| Milestone | Target | Status |
|---|---|---|
| First | P99 < 10ms | met |
| Second | P99 < 5ms | met |

Met **on the one platform measured so far** — see `--matrix`. These are design
targets measured on the machine listed in the output, not a published SLA and
not a comparison against other products.

## Cross-platform

The harness runs anywhere Node 20+ does. Results are kept per platform and never
averaged: Linux x86, Linux ARM, macOS ARM, Docker, and Windows have materially
different numbers, and a mean across them is true of nowhere.

## On competitor comparisons

There is no competitor latency table here, and there should not be one until
every row in it has been reproduced on the same machine on the same day with the
same workload and the methodology published alongside. A comparison table you
cannot reproduce is the fastest way for a technical buyer to discard everything
else you have said.

## Reporting a number

Always with the platform line the tool prints:

```
node       v24.14.1
platform   win32 10.0.26200 x64
cpu        Intel(R) Core(TM) Ultra 5 225U × 14
memory     15 GB
rules      34
```

A latency figure with no machine attached is not a measurement.
