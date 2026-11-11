// SPDX-License-Identifier: AGPL-3.0-or-later
// The group, as the engine sees it: an ordered list of (id, kind, bytes). Telegram, the sandbox
// folder and the in-memory fake below all implement this.

export interface Message { id: number; kind: string }

export interface Transport {
  send(kind: string, data: Uint8Array): Promise<number>;
  iterAfter(afterId: number): AsyncIterable<Message>;
  fetch(id: number): Promise<Uint8Array>;
  close(): Promise<void>;
}

export class TransportError extends Error {}

/** Shared in-memory group for tests; each client gets its own `transport()`. */
export class FakeChannel {
  messages = new Map<number, [string, Uint8Array]>();
  nextId = 1;
  sent = 0;

  transport(): Transport {
    return {
      send: async (kind, data) => {
        const id = this.nextId++;
        this.messages.set(id, [kind, data.slice()]);
        this.sent++;
        return id;
      },
      iterAfter: (afterId) => {
        const ids = [...this.messages.keys()].filter((i) => i > afterId).sort((a, b) => a - b);
        const msgs = this.messages;
        return (async function* () {
          for (const id of ids) yield { id, kind: msgs.get(id)![0] };
        })();
      },
      fetch: async (id) => {
        const m = this.messages.get(id);
        if (!m) throw new TransportError(`message ${id} missing`);
        return m[1].slice();
      },
      close: async () => {},
    };
  }
}
