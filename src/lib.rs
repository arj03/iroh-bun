//! iroh-bun — a thin napi-rs wrapper around iroh 1.0.
//!
//! This is deliberately a *leaf* binding: it exposes iroh's QUIC primitives
//! (endpoint, connection, bidirectional byte streams) to JavaScript and nothing
//! more. All framing, routing and application logic stays in TypeScript on top
//! (see `net-iroh.ts`), so this crate never needs to change as the app evolves.
//!
//! Why a wrapper at all: core iroh ships no prebuilt client library — only the
//! `iroh-relay` / `iroh-dns-server` infra binaries — and the community napi
//! binding lags the core crate. Compiling this ~one file against `iroh = "1.0"`
//! is the only way to get exactly-1.0 in-process for Node/Bun. The build happens
//! once in CI; consumers install a prebuilt `.node` and never touch Rust.
//!
//! ## Identity
//! iroh's node identity is a 32-byte ed25519 seed. Pass your own 32-byte seed as
//! `secretKey` and iroh's EndpointId becomes byte-for-byte the corresponding
//! ed25519 public key. Because iroh authenticates every QUIC connection to its
//! EndpointId via TLS, `connection.remoteId()` is the *cryptographically proven*
//! peer id — so no application-level handshake is needed over this transport.
//!
//! API verified against the iroh 1.0.0 `echo` / `echo-no-router` examples and
//! docs.rs (1.0 renamed Node→Endpoint: `remote_id() -> EndpointId`, `EndpointAddr`).

use std::sync::Arc;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;

use iroh::{
    endpoint::{presets, Connection, RecvStream, SendStream},
    Endpoint, EndpointAddr, EndpointId, SecretKey,
};

/// Map any Display error into a JS exception.
fn nerr<E: std::fmt::Display>(e: E) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

/// Parse a lowercase-hex (64 char) endpoint id into iroh's `EndpointId`.
///
/// We go through raw bytes on purpose so the wire id is exactly `toHex(pubkey)`
/// — independent of whatever canonical string form iroh's `Display`/`FromStr`
/// happen to use.
fn parse_endpoint_id(s: &str) -> Result<EndpointId> {
    let bytes = hex::decode(s).map_err(|_| napi::Error::from_reason("endpoint id must be hex"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| napi::Error::from_reason("endpoint id must be 32 bytes"))?;
    EndpointId::from_bytes(&arr).map_err(|_| napi::Error::from_reason("invalid endpoint id"))
}

/// Options for creating an endpoint. Field names are camelCased in JS
/// (`secretKey`, `alpns`).
#[napi(object)]
pub struct EndpointOptions {
    /// 32-byte ed25519 seed. Omit to let iroh generate an ephemeral identity.
    pub secret_key: Option<Uint8Array>,
    /// ALPN protocol ids this endpoint will *accept*. The connecting side passes
    /// its ALPN to `connect`; both must match or the connection is rejected.
    pub alpns: Vec<Uint8Array>,
}

/// Create + bind an endpoint using the n0 preset (n0 DNS discovery + default
/// relays), so a bare endpoint id is dialable without any signaling server.
#[napi]
pub async fn create_endpoint(opts: EndpointOptions) -> Result<IrohEndpoint> {
    let mut builder = Endpoint::builder(presets::N0);
    if let Some(sk) = opts.secret_key {
        let bytes: [u8; 32] = sk
            .as_ref()
            .try_into()
            .map_err(|_| napi::Error::from_reason("secretKey must be exactly 32 bytes"))?;
        builder = builder.secret_key(SecretKey::from_bytes(&bytes));
    }
    let alpns: Vec<Vec<u8>> = opts.alpns.iter().map(|a| a.as_ref().to_vec()).collect();
    builder = builder.alpns(alpns);
    let endpoint = builder.bind().await.map_err(nerr)?;
    Ok(IrohEndpoint { inner: endpoint })
}

/// A bound iroh endpoint. `Endpoint` is cheap to clone (Arc-backed), so every
/// async method clones the handle up front and the returned future owns it — no
/// borrow of `self` is held across an await.
#[napi]
pub struct IrohEndpoint {
    inner: Endpoint,
}

#[napi]
impl IrohEndpoint {
    /// Our own endpoint id as 64-char lowercase hex (== the ed25519 public key
    /// when constructed from a 32-byte seed).
    #[napi]
    pub fn id(&self) -> String {
        hex::encode(self.inner.id().as_bytes())
    }

    /// Resolve once the endpoint has a reachable address (relay home registered /
    /// discovery published). Mirrors `endpoint.online().await` in the examples.
    #[napi]
    pub async fn online(&self) {
        let ep = self.inner.clone();
        ep.online().await;
    }

    /// Dial a peer by endpoint id (hex) over the given ALPN. Discovery resolves
    /// the actual paths, so no address is needed.
    #[napi]
    pub async fn connect(&self, endpoint_id: String, alpn: Uint8Array) -> Result<IrohConnection> {
        let ep = self.inner.clone();
        let id = parse_endpoint_id(&endpoint_id)?;
        let conn = ep
            .connect(EndpointAddr::from(id), alpn.as_ref())
            .await
            .map_err(nerr)?;
        Ok(IrohConnection { inner: conn })
    }

    /// Pull the next inbound connection. Resolves to `null` once the endpoint is
    /// closed, so JS can drive `while ((c = await ep.accept()))`.
    #[napi]
    pub async fn accept(&self) -> Result<Option<IrohConnection>> {
        let ep = self.inner.clone();
        match ep.accept().await {
            Some(incoming) => {
                let conn = incoming.await.map_err(nerr)?;
                Ok(Some(IrohConnection { inner: conn }))
            }
            None => Ok(None),
        }
    }

    /// Gracefully close the endpoint and all its connections.
    #[napi]
    pub async fn close(&self) {
        let ep = self.inner.clone();
        ep.close().await;
    }
}

/// A live QUIC connection to one peer. `Connection` is also Arc-backed/Clone.
#[napi]
pub struct IrohConnection {
    inner: Connection,
}

#[napi]
impl IrohConnection {
    /// The peer's *authenticated* endpoint id as hex — proven by the QUIC/TLS
    /// handshake, safe to use directly as the peer id.
    #[napi]
    pub fn remote_id(&self) -> String {
        hex::encode(self.inner.remote_id().as_bytes())
    }

    /// Open a new bidirectional stream (the dialing side).
    #[napi]
    pub async fn open_bi(&self) -> Result<IrohStream> {
        let conn = self.inner.clone();
        let (send, recv) = conn.open_bi().await.map_err(nerr)?;
        Ok(IrohStream::new(send, recv))
    }

    /// Accept the next bidirectional stream the peer opened (the accepting side).
    #[napi]
    pub async fn accept_bi(&self) -> Result<IrohStream> {
        let conn = self.inner.clone();
        let (send, recv) = conn.accept_bi().await.map_err(nerr)?;
        Ok(IrohStream::new(send, recv))
    }

    /// Queue a connection close (error code 0). Non-async, like iroh's own
    /// `Connection::close`; the endpoint flushes it on its next tick / `close()`.
    #[napi]
    pub fn close(&self) {
        self.inner.close(0u32.into(), b"closed by host");
    }
}

/// One bidirectional stream = an ordered, reliable byte pipe (not message-framed;
/// the TS layer length-prefixes frames, exactly as the TCP transport does).
#[napi]
pub struct IrohStream {
    send: Arc<Mutex<SendStream>>,
    recv: Arc<Mutex<RecvStream>>,
}

impl IrohStream {
    fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send: Arc::new(Mutex::new(send)),
            recv: Arc::new(Mutex::new(recv)),
        }
    }
}

#[napi]
impl IrohStream {
    /// Write all the bytes to the stream (ordered, reliable).
    #[napi]
    pub async fn write(&self, data: Uint8Array) -> Result<()> {
        let send = self.send.clone();
        let mut guard = send.lock().await;
        guard.write_all(data.as_ref()).await.map_err(nerr)?;
        Ok(())
    }

    /// Read up to `maxLen` bytes. Resolves to `null` at clean end-of-stream
    /// (peer called `finish`). May return fewer bytes than requested.
    #[napi]
    pub async fn read(&self, max_len: u32) -> Result<Option<Buffer>> {
        let recv = self.recv.clone();
        let mut guard = recv.lock().await;
        let mut buf = vec![0u8; max_len as usize];
        match guard.read(&mut buf).await.map_err(nerr)? {
            Some(n) => {
                buf.truncate(n);
                Ok(Some(buf.into()))
            }
            None => Ok(None),
        }
    }

    /// Signal end-of-data on the send side, terminating the peer's read stream.
    #[napi]
    pub async fn finish(&self) -> Result<()> {
        let send = self.send.clone();
        let mut guard = send.lock().await;
        guard.finish().map_err(nerr)?;
        Ok(())
    }
}
