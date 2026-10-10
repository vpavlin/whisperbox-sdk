# whisperbox-sdk

WhisperBox encrypted forms as a library: create a form, share it as a `whisperbox://` link or
QR code, collect answers sealed to the form's key, read them. This is the protocol the
[WhisperBox](https://github.com/vpavlin/whisperbox-logos) Android app runs, byte-for-byte the
same as its desktop core (the app repo tests the two against each other). Sync rides
[Loam](https://github.com/vpavlin/loam-transport) (Logos Messaging) on the WhisperBox topic, so
forms made with the SDK are ordinary WhisperBox forms: anyone answers with the WhisperBox app.

Built on the Logos tech stack; not affiliated with or endorsed by Logos.

| Path | What |
|---|---|
| `contract/` | crypto (secp256k1, ECIES, HKDF), events, HLC, merge, answer validation + quiz scoring |
| `engine/` | the pure fold (`computeState`, `creatorView`) and its golden fixtures |
| `client/` | `WhisperboxClient`: local log, sealing, catch-up, receipts, replies, `formSummary` |
| `templates/` | organiser form templates: `booking`, `crew`, `guestlist`, `feedback` |
| `rn/` | React Native adapter: `setAppId`, `createWhisperbox({transport})`, default stores |
| `loam-sync-pkg/` | submodule: loam-sync's RBSR catch-up (`dist/catchup.js`) |

## Mount it (React Native / Expo)

```sh
git submodule add https://github.com/vpavlin/whisperbox-sdk mobile/src/whisperbox
git submodule update --init --recursive
```

- Install the peers in your app: `@noble/curves@2.3.0 @noble/hashes@2.4.0 @noble/ciphers@2.4.0
  buffer@^6.0.3` and, for the RN adapter's default stores, `expo-file-system@~57` and
  `expo-secure-store@~57`.
- Metro: add `mjs` to `resolver.sourceExts` (the protocol is plain ESM). If you mount it
  outside your project root, add it to `watchFolders` and point `resolver.nodeModulesPaths` at
  your `node_modules`.
- The SDK has **no loam-transport of its own**: pass yours. With loam-transport 9963f22 or later,
  several engines share one transport; each calls `start()` with its own topics and receiver.

```ts
import * as transport from "./src/lib/loam-transport";            // your copy
import { setAppId, createWhisperbox } from "./src/whisperbox/rn";
import { template } from "./src/whisperbox/templates/templates.mjs";

setAppId("frequencies");                 // register with Loam as your app, before boot()
const wb = createWhisperbox({ transport });
await wb.boot();                          // preferServiceBackend(true, appId) -> start(...)

const { formId } = wb.client.createForm(template("guestlist", { title: "Guest list - Fri 14 Nov" }));
const { uri } = wb.client.shareUri(formId);   // whisperbox://form?id=...&by=0x...
wb.client.formSummary(formId);                // {title, status, receipts, responses (creator only), ...}
wb.client.subscribe(() => render(wb.client.snapshot()));
```

Answers can be read only by the form's creator or a co-owner: a sealed answer doesn't say which
form it answers, so nobody else can even count them.

## Desktop (Basecamp)

Nothing to mount: declare `whisperbox_core` in your module's `dependencies` and call it
(`createForm`, `shareUri`, `shareQr`, `formSummary`, `getDecryptedResponses`, `snapshot` +
the `stateChanged` event, ...). See the WhisperBox repo's `docs/SPEC.md`.

## Changing it

Two commits, SDK first: change and push here, then bump the submodule in
[whisperbox-logos](https://github.com/vpavlin/whisperbox-logos) and run its `scripts/test.sh`,
which checks this code against the C++ core (parity, golden vectors, interop). A change is done
only when that passes. Keep `loam-sync-pkg` at the revision the app's `third_party/loam-sync`
pins. Consumers bump their pointer to get a fix.

`npm install && npm test` runs the protocol's own tests here.

Consumers: [whisperbox-logos](https://github.com/vpavlin/whisperbox-logos) (`packages/`),
[frequencies](https://github.com/vpavlin/frequencies).

## Licence

MIT OR Apache-2.0.
