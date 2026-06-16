# iroh-bun

A thin [napi-rs](https://napi.rs) wrapper around [iroh](https://github.com/n0-computer/iroh)
that exposes QUIC peer-to-peer endpoints, connections and bidirectional byte streams to
**Node and Bun**. It is a *leaf* binding: framing, routing and app logic live in TypeScript
on top, so this crate never has to change as the app evolves.

## Use it from Bun

```ts
import { createEndpoint } from "iroh-bun";

// secretKey is the 32-byte ed25519 seed. Feed it your own seed and
// the endpoint id below === your ed25519 public key (hex).
const ep = await createEndpoint({
  secretKey: seed32,                           // Uint8Array(32) | omit for ephemeral
  alpns: [Buffer.from("my-app/0")],            // protocols we accept
});

await ep.online();
console.log("my id:", ep.id());                // 64-char hex == ed25519 pubkey

// dial a peer by id; discovery finds the path, no signaling server needed
const conn = await ep.connect(peerIdHex, Buffer.from("my-app/0"));
const s = await conn.openBi();
await s.write(Buffer.from("hello"));
await s.finish();

// accept loop (other side)
let inc;
while ((inc = await ep.accept())) {
  console.log("from:", inc.remoteId());        // authenticated peer id
  const s = await inc.acceptBi();
  const chunk = await s.read(65536);           // Buffer | null at EOF
}
```

## API (generated `index.d.ts`)

```ts
export interface EndpointOptions { secretKey?: Uint8Array; alpns: Uint8Array[] }
export function createEndpoint(opts: EndpointOptions): Promise<IrohEndpoint>;

export class IrohEndpoint {
  id(): string;                                          // own id, hex
  online(): Promise<void>;
  connect(endpointId: string, alpn: Uint8Array): Promise<IrohConnection>;
  accept(): Promise<IrohConnection | null>;              // null when closed
  close(): Promise<void>;
}
export class IrohConnection {
  remoteId(): string;                                    // authenticated peer id, hex
  openBi(): Promise<IrohStream>;
  acceptBi(): Promise<IrohStream>;
  close(): void;
}
export class IrohStream {
  write(data: Uint8Array): Promise<void>;
  read(maxLen: number): Promise<Buffer | null>;          // null at clean EOF
  finish(): Promise<void>;
}
```

## Distributing prebuilt binaries (so others just `bun add`)

`@napi-rs/cli` produces one `.node` per platform and a set of `optionalDependencies`
(`iroh-bun-darwin-arm64`, `iroh-bun-linux-x64-gnu`, …). The `.github/workflows/CI.yml`
matrix cross-builds them and `napi prepublish` pushes the platform packages plus
this root package to npm. Consumers then `bun add iroh-bun` and the loader pulls
the matching prebuilt — no Rust.

The binaries are roughly 11.5MB large.

## `bun build --compile` (single native binary)

`bun build --compile` can embed napi `.node` addons, but only ones that are
**directly required** (not resolved dynamically). The napi-rs loader does dynamic
per-platform resolution, so for a clean standalone executable, `require()` the
specific platform `.node` directly (or re-export it) in your entry so Bun bundles
it. Because this is your own addon you control that loader path.

## Build

Requires a Rust toolchain (only on the *build* machine — not for consumers).

```bash
cd iroh-bun
npm install                    # gets @napi-rs/cli
npm run build                  # -> iroh-bun.<triple>.node + index.js + index.d.ts
```

`napi build` also generates `index.js` (a loader that picks the right prebuilt
binary for the host platform) and `index.d.ts` (the typed surface below).