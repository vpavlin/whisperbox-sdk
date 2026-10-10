// React Native adapter: one WhisperboxClient (the shared protocol in ../client) wired to an
// INJECTED loam-transport. The host app passes its own loam-transport module, so an app that
// also runs other engines (Scala, Kith) keeps a single transport; each engine adds its own
// receiver and topics with start() (loam-transport >= 9963f22).
//
//   import * as transport from "./src/lib/loam-transport";      // the host's copy
//   import { setAppId, createWhisperbox } from "./src/whisperbox/rn";
//   setAppId("frequencies");                                    // register with Loam as yourself
//   const wb = createWhisperbox({ transport });
//   await wb.boot();
//   wb.client.createForm({ title, questions });  wb.client.formSummary(formId);
import * as SecureStore from "expo-secure-store";
import { fileStore, secretStore, type KV } from "./store";
// @ts-ignore - plain ESM shared with the desktop reference + tests
import { WhisperboxClient, TOPIC, parseLink } from "../client/src/client.mjs";

export { TOPIC, parseLink, fileStore, secretStore };
export type { KV };

/** The app id WhisperBox registers with Loam. Hosts set their own before boot(). */
let appId = "xyz.vpavlin.whisperbox";
export function setAppId(id: string) { appId = id; }
export function getAppId() { return appId; }

/** What the adapter needs from loam-transport (its public API). */
export type Transport = {
  preferServiceBackend(shared: boolean, appId: string): void;
  start(o: { deviceId: string; topics: string[]; onReceive: (topic: string, candidates: Uint8Array[]) => boolean; onStatus?: (s: string) => void }): Promise<unknown>;
  storeSync(cb: (topic: string, candidates: Uint8Array[]) => boolean): Promise<unknown>;
  publishSealed(topic: string, bytes: Uint8Array): Promise<unknown>;
  usingServiceBackend?(): boolean;
};

export type Options = {
  transport: Transport;
  store?: KV;        // event log + local state (default: files in the app's documents dir)
  secrets?: KV;      // identity key (default: SecureStore, Keystore-backed)
  log?: (msg: string) => void;   // breadcrumbs (WhisperBox: its crash log)
};

export function createWhisperbox(o: Options) {
  const { transport } = o;
  const log = o.log || (() => {});
  const client: any = new WhisperboxClient({
    store: o.store || fileStore,
    secrets: o.secrets || secretStore,
    send: async (bytes: Uint8Array) => { await transport.publishSealed(TOPIC, bytes); },
  });
  const net = { status: "Starting…", started: false, error: "", shared: true };
  let booted: Promise<void> | null = null;

  /** setAppId (before) → preferServiceBackend → start. Boot order matters
   *  (loam-integrate-app §2): the backend choice comes before anything touches the transport. */
  function boot(): Promise<void> {
    if (booted) return booted;
    booted = (async () => {
      log("client.init");
      await client.init();
      log("client ready dev=" + client.deviceId + " log=" + client.log.length);
      try { net.shared = (await SecureStore.getItemAsync("wb-shared-node")) !== "0"; } catch { net.shared = true; }
      transport.preferServiceBackend(net.shared, appId);
      log("transport.start shared=" + net.shared + " app=" + appId);
      let rx = 0;
      try {
        await transport.start({
          deviceId: client.deviceId,
          topics: [TOPIC],
          onReceive: (topic: string, candidates: Uint8Array[]) => {
            if (topic !== TOPIC) return false;
            rx++; if (rx <= 3 || rx % 25 === 0) log("rx #" + rx + " new=" + client.diag.rxNew + " err=" + (client.diag.rxErr || 0));
            return client.ingest(candidates);
          },
          onStatus: (s: string) => { net.status = s; log("status: " + s); client.emit(); },
        });
        net.started = true; net.status = "Connected";
        log("started " + (transport.usingServiceBackend?.() ? "shared node" : "own node"));
        // Protocol errors must not be reported as "start failed" (the transport IS up).
        try { client.onConnected(); } catch (e: any) { log("onConnected error " + (e?.message || e)); }
        log("store sync");
        transport.storeSync((t: string, c: Uint8Array[]) => { try { return t === TOPIC && client.ingest(c); } catch { return false; } })
          .then(() => log("store sync done log=" + client.log.length)).catch((e: any) => log("store sync failed " + (e?.message || e)));
      } catch (e: any) {
        net.error = String(e?.message || e); net.status = "Offline"; log("start failed: " + net.error); client.emit();
      }
      let ticks = 0;
      setInterval(() => {
        try { client.tick(); } catch (e: any) { log("tick error " + (e?.message || e)); }
        if (++ticks === 5 || ticks === 30) log("alive " + ticks + "s log=" + client.log.length + " rx=" + client.diag.rxRaw);
      }, 1000);
    })();
    return booted;
  }

  /** Applies on next launch (the backend choice is locked at start). */
  async function setSharedNode(on: boolean) {
    await SecureStore.setItemAsync("wb-shared-node", on ? "1" : "0");
    net.shared = on;
  }

  function pullHistory() {
    if (!net.started) return Promise.resolve();
    client.resync();
    return transport.storeSync((t: string, c: Uint8Array[]) => t === TOPIC && client.ingest(c)).then(() => client.emit());
  }

  return { client, net, boot, setSharedNode, pullHistory };
}
