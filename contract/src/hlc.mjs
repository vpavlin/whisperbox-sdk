// hlc.mjs — hybrid logical clock + total order. Plain-ESM mirror of
// loam-sync src/event.ts (same spec, byte-identical JSON wire shape). Keep in
// lockstep with both that file and basecamp/logos_sync/event.hpp (three-way
// parity; see loam-sync docs/PARITY.md).

/** HLC = {wall: ms, ctr: causal tiebreak, dev: author device id}. */

/** Total order: wall → ctr → dev. Identical on every replica. */
export function compareHlc(a, b) {
  if (a.wall !== b.wall) return a.wall < b.wall ? -1 : 1;
  if (a.ctr !== b.ctr) return a.ctr < b.ctr ? -1 : 1;
  if (a.dev !== b.dev) return a.dev < b.dev ? -1 : 1;
  return 0;
}

/** Stamps local events and advances past ingested ones. Prime it from your whole
 *  log on load, and call receive() for every event you ingest (loam-sync ADR 0002). */
export class Clock {
  constructor(dev) {
    this.dev = dev;
    this.wall = 0;
    this.ctr = 0;
  }
  send(nowMs) {
    if (nowMs > this.wall) {
      this.wall = nowMs;
      this.ctr = 0;
    } else {
      this.ctr += 1;
    }
    return { wall: this.wall, ctr: this.ctr, dev: this.dev };
  }
  receive(h) {
    if (h.wall > this.wall) {
      this.wall = h.wall;
      this.ctr = h.ctr;
    } else if (h.wall === this.wall) {
      this.ctr = Math.max(this.ctr, h.ctr);
    }
  }
}
