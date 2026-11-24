// SPDX-License-Identifier: AGPL-3.0-or-later
// Dead connections. mtcute reconnects forever, so a call over a dead network or proxy would wait
// forever. A call fails once the client has been unable to connect for OFFLINE_MS in a row. Slow but
// working transfers (a big chunk over mobile data) are never cut: only "connecting"/"offline" time counts.
import { OfflineError } from "../transport.ts";

export const OFFLINE_MS = 60_000;
const downSince = new WeakMap<object, number | null>();
type Watched = { onConnectionState: { add(f: (s: string) => void): void } };

export function watchConnection(tg: Watched): void {
  downSince.set(tg, null);
  tg.onConnectionState.add((s) => {
    const down = s === "connecting" || s === "offline";
    downSince.set(tg, down ? (downSince.get(tg) ?? Date.now()) : null);
  });
}

/** `p`, or a TransportError once `tg` has been unable to reach Telegram for `ms` in a row. */
export function whileReachable<T>(tg: object, p: Promise<T>, ms = OFFLINE_MS): Promise<T> {
  let t: ReturnType<typeof setInterval> | undefined;
  const dead = new Promise<never>((_, no) => {
    t = setInterval(() => {
      const since = downSince.get(tg);
      if (since != null && Date.now() - since >= ms) {
        no(new OfflineError(`no connection to Telegram for ${Math.round(ms / 1000)}s (network or proxy down?); ` +
          "nothing was lost: run the same command again when the connection is back"));
      }
    }, Math.min(1000, ms));
  });
  return Promise.race([p, dead]).finally(() => clearInterval(t));
}
