// SPDX-License-Identifier: AGPL-3.0-or-later
// How fast one Telegram account may go now: learned from Telegram's flood waits, kept between runs.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { appDir } from "./home.ts";

const CALM_MS = 10 * 60_000; // this long without a flood wait halves the slow-down
const MAX_FACTOR = 64;

/** How much slower than normal one Telegram account goes now (1 = normal). Each flood wait doubles it;
 *  each calm 10 minutes halve it again, down to 1, so it always comes back to the set speed. Saved per
 *  account (`pace.json`), so a restart does not forget it. */
export class Pace {
  private static all = new Map<string, Pace>();
  factor = 1;
  /** Since when the current factor holds (calm time counts from here). */
  since = Date.now();
  /** No calls before this (end of Telegram's last flood wait). */
  until = 0;

  private constructor(private file: string | null) {
    try { Object.assign(this, JSON.parse(readFileSync(file!, "utf8"))); } catch { /* none yet */ }
  }

  static of(profile: string): Pace {
    let p = Pace.all.get(profile);
    if (!p) Pace.all.set(profile, (p = new Pace(join(appDir(profile), "pace.json"))));
    return p;
  }

  /** For tests and the sandbox: not saved. */
  static memory(): Pace { return new Pace(null); }

  now(): number {
    const calm = Math.floor((Date.now() - this.since) / CALM_MS);
    if (calm > 0 && this.factor > 1) {
      this.factor = Math.max(1, this.factor / 2 ** calm);
      this.since += calm * CALM_MS;
      this.save();
    }
    return this.factor;
  }

  flood(seconds: number): void {
    this.factor = Math.min(MAX_FACTOR, this.now() * 2);
    this.since = Date.now();
    this.until = Math.max(this.until, Date.now() + seconds * 1000);
    this.save();
  }

  private save(): void {
    if (!this.file) return;
    try { writeFileSync(this.file, JSON.stringify({ factor: this.factor, since: this.since, until: this.until })); } catch { /* best effort */ }
  }
}
