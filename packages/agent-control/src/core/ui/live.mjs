/**
 * LiveStream — `cirvix logs --watch` live security stream.
 *
 * Line-based updates, no full redraw, readable.
 */

import { dim, bold } from "../format.mjs";
import { renderDecision } from "./decisions.mjs";

export class LiveStream {
  constructor({ stream = process.stdout, title = "CIRVIX LIVE · protection active" } = {}) {
    this.stream = stream;
    this.title = title;
    this.started = false;
  }

  header() {
    if (this.started) return;
    this.started = true;
    try {
      this.stream.write(`\n  ${bold(this.title)}\n`);
      this.stream.write(`  ${dim("─".repeat(60))}\n\n`);
    } catch {}
  }

  push(event) {
    this.header();
    const line = renderDecision(event);
    // For live, compact is preferred even for DENY to keep stream readable,
    // but DENY still gets expanded with context on next line.
    try {
      // event already has ts; render with clock if present.
      const clock = event.ts ? String(event.ts).slice(11, 19) : new Date().toISOString().slice(11, 19);
      // If decision renderer already includes multiline, just prefix clock.
      if (line.includes("\n")) {
        const parts = line.split("\n");
        this.stream.write(`  ${dim(clock)} ${parts[0].trimStart()}\n`);
        for (let i = 1; i < parts.length; i++) this.stream.write(parts[i] + "\n");
      } else {
        this.stream.write(`  ${dim(clock)} ${line.trimStart()}\n`);
      }
    } catch {}
  }

  footer(stats) {
    if (!stats) return;
    try {
      this.stream.write(`\n  ${dim(`${stats.records ?? 0} decisions · P99 ${stats.latency?.p99 ?? 0}ms`)}\n\n`);
    } catch {}
  }
}
