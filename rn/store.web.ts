// Web build (UI testing in a browser only): localStorage-backed storage. The Android app
// uses store.ts (expo-file-system + Keystore-backed SecureStore).
export type KV = { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<void> };
const ls = (): Storage | null => { try { return globalThis.localStorage; } catch { return null; } };
export const fileStore: KV = {
  async get(k) { try { return ls()?.getItem("wb:" + k) ?? null; } catch { return null; } },
  async set(k, v) { try { ls()?.setItem("wb:" + k, v); } catch { /* */ } },
};
export const secretStore = fileStore;
