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
// An HLC counter only counts events stamped in one millisecond; a peer's huge ctr used to be adopted
// and carried into every later local stamp (open-review FR-2). Same bound as the C++ engine.
export const MAX_HLC_CTR = 2 ** 30;

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
    } else if (this.ctr >= MAX_HLC_CTR) {
      this.wall += 1;   // carry into the next millisecond
      this.ctr = 0;
    } else {
      this.ctr += 1;
    }
    return { wall: this.wall, ctr: this.ctr, dev: this.dev };
  }
  receive(h) {
    if (!h || !Number.isInteger(h.ctr) || h.ctr < 0 || h.ctr > MAX_HLC_CTR) return;
    if (h.wall > this.wall) {
      this.wall = h.wall;
      this.ctr = h.ctr;
    } else if (h.wall === this.wall) {
      this.ctr = Math.max(this.ctr, h.ctr);
    }
  }
}
