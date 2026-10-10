// Storage adapters for the protocol client.
//  - secrets (the identity private key): expo-secure-store, Android Keystore-backed.
//  - store (event log, watched forms, pins, my receipts): one JSON file per key in the
//    app's private documents directory. Writes are atomic (write tmp, then move).
import * as SecureStore from "expo-secure-store";
import * as FS from "expo-file-system/legacy";

export type KV = { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<void> };

const path = (k: string) => (FS.documentDirectory || "") + k.replace(/[^a-z0-9-]/gi, "_") + ".json";

// Writes per key are serialized and coalesced: while one write is in flight, newer values
// replace the pending one, so a burst of saves (catch-up) costs ~2 writes and the LAST value
// always lands. No debounce timer - a timer can lose writes when the app is killed.
const pending = new Map<string, string>();
const busy = new Set<string>();
async function flush(k: string) {
  if (busy.has(k)) return;
  busy.add(k);
  try {
    while (pending.has(k)) {
      const v = pending.get(k)!; pending.delete(k);
      const p = path(k), tmp = p + ".tmp";
      try {
        await FS.writeAsStringAsync(tmp, v);
        await FS.moveAsync({ from: tmp, to: p });
      } catch {
        try { await FS.writeAsStringAsync(p, v); } catch { /* next write retries */ }
      }
    }
  } finally { busy.delete(k); }
}

export const fileStore: KV = {
  async get(k) {
    if (pending.has(k)) return pending.get(k)!;
    try {
      const p = path(k);
      const info = await FS.getInfoAsync(p);
      return info.exists ? await FS.readAsStringAsync(p) : null;
    } catch { return null; }
  },
  async set(k, v) { pending.set(k, v); await flush(k); },
};

export const secretStore: KV = {
  get: (k) => SecureStore.getItemAsync(k),
  set: (k, v) => SecureStore.setItemAsync(k, v, { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY }),
};
