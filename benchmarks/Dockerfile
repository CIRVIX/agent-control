# Benchmark harness in a container.
#
#   docker build -f benchmarks/Dockerfile -t cirvix-bench .
#   docker run --rm -v "$PWD/benchmarks:/app/benchmarks" cirvix-bench
#
# The bind mount is what makes the run useful: without it the recorded row is
# written inside the container and discarded on exit, and the matrix stays empty
# no matter how many times somebody runs this.
#
# Cross-architecture rows come from the same image under emulation or on native
# hardware — `--platform linux/arm64` gives you the ARM row, slowly. A result
# measured under QEMU is NOT the same as one measured on real ARM silicon, so
# record those only on real hardware; the matrix has no column for "emulated"
# because a number qualified in a footnote gets quoted without the footnote.

FROM node:24-slim

WORKDIR /app

# Only what the benchmark actually imports. The engine is dependency-free, so
# there is nothing to install — copying package manifests and running an install
# would add a layer that does nothing.
COPY packages/agent-control/src ./packages/agent-control/src
COPY benchmarks ./benchmarks

# Marks the row as containerized even where /.dockerenv is absent, so a Docker
# result can never be recorded as though it were bare metal.
ENV CIRVIX_BENCH_ENV=docker

ENTRYPOINT ["node", "benchmarks/decision.mjs"]
CMD ["--record", "--full"]
