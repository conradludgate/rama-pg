# rama-pg

A Rust **library for building Postgres wire-protocol proxies** on top of
[rama](https://ramaproxy.org). You assemble a proxy from composable pieces — a
TLS acceptor, an SNI router, a pluggable authenticator, and a forwarding mode —
and rama-pg handles the awkward Postgres-specific edges (TLS negotiated *after* a
plaintext `SSLRequest`; no Host header to route on; a hand-rolled zero-copy wire
codec). It is also an experiment in stretching rama's HTTP/TLS/L4 `Service` model
onto a non-HTTP protocol.

> ⚠️ **Experimental — not for production.** rama-pg is an educational
> exploration, useful for understanding the Postgres wire protocol and rama's
> service model — not for fronting a real database. It authenticates clients but
> takes deliberate shortcuts (no SASLprep, a trust-only `pg_authid` admin
> connection, no channel binding, no `CancelRequest` routing) and builds against
> an unreleased git revision of rama. Don't put it in front of data you care
> about.

The docs document the **library**: a [Diátaxis](https://diataxis.fr)
**tutorial** to build a proxy with it, **how-to guides** for its extension seams,
**reference** for the API surface, and **explanation** for the design. The
`rama-pg-example` and `pgbouncer` crates are *showcases* of the library — see
[Example showcases](#example-showcases).

---

## Tutorial: build a proxy with the library

This builds a minimal pass-through proxy *in code* and runs a `psql` session
through it. You need Rust (stable) and a Postgres reachable at `127.0.0.1:5432`.

rama-pg targets an unreleased rama, so it isn't on crates.io — depend on it by
path or git (the same `rama` git revision is pulled in transitively):

```toml
[dependencies]
rama-pg = { path = "../rama-pg" } # or: { git = "<your fork/clone>" }
tokio = { version = "1", features = ["full"] }
```

A whole proxy is one `PgProxy` value served on a `TcpListener`:

```rust
use std::sync::Arc;

use rama::error::BoxError;
use rama::net::tls::server::SelfSignedData;
use rama::rt::Executor;
use rama::tcp::server::TcpListener;
use rama::tls::rustls::server::TlsAcceptorDataBuilder;
use rama_pg::auth::{Auth, PassThrough};
use rama_pg::cancel::RegistryCancellation;
use rama_pg::proxy::PgProxy;
use rama_pg::route::{Backend, Router};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // The proxy presents a self-signed cert (clients use sslmode=require).
    let tls = TlsAcceptorDataBuilder::try_new_self_signed(SelfSignedData::default())?.build();

    // Route every connection to one backend (exact SNI routes are optional).
    let router = Arc::new(Router::new().with_default(Backend::new("127.0.0.1:5432")));

    // Pass-through auth: the *backend* authenticates the client.
    let auth = Arc::new(Auth::PassThrough(PassThrough));

    // Mediate query cancellation with the default in-memory registry.
    let cancellation = Arc::new(RegistryCancellation::new());

    // No pool and no query handler → direct 1:1 forwarding.
    let proxy = Arc::new(PgProxy::new(tls, router, auth, None, None, cancellation));

    TcpListener::bind_address("127.0.0.1:6432", Executor::new())
        .await?
        .serve(proxy)
        .await;
    Ok(())
}
```

Run it, then connect with `psql` from another terminal. The proxy presents a
self-signed certificate, so use `sslmode=require` (encrypt without verifying):

```sh
psql "host=127.0.0.1 port=6432 user=$USER dbname=postgres sslmode=require" \
  -c "select 'hello through rama-pg'"
```

What happened: psql sent a plaintext `SSLRequest`; the proxy answered `S` and
upgraded the *same* socket to TLS; it read your `StartupMessage`, dialed your
Postgres, and relayed the rest byte-for-byte — your Postgres did the actual
authentication. The how-to guides swap in auth termination, pooling, and an
in-proxy query mode by changing the values you pass to `PgProxy`.

> Don't want to write code yet? The `rama-pg-example` crate is exactly this
> program, configured by environment variables:
> `RAMA_PG_BACKEND=127.0.0.1:5432 cargo run -p rama-pg-example`.

---

## How-to guides

Each guide changes one input to the `PgProxy` from the tutorial. They cover the
library's extension seams; types are detailed in [Reference](#reference).

### Terminate cleartext password auth

Swap the authenticator. The proxy challenges the client for a cleartext password
(safe over the required TLS), checks it with a `PasswordValidator`, then connects
to a trust backend:

```rust
use std::collections::HashMap;
use rama_pg::auth::{Auth, CleartextPassword, StaticPasswordValidator};

let mut creds = HashMap::new();
creds.insert("alice".to_owned(), "secret".to_owned());
let auth = Arc::new(Auth::Cleartext(CleartextPassword::new(
    StaticPasswordValidator::new(creds),
)));
```

### Check credentials your own way (async)

`PasswordValidator` is async, so the cleartext password can be anything you can
verify with I/O — e.g. a JWT validated against a JWKS endpoint:

```rust
use rama::error::BoxError;
use rama_pg::auth::{AuthContext, PasswordValidator};

struct JwtValidator { /* JWKS client, issuer, … */ }

impl PasswordValidator for JwtValidator {
    async fn validate(&self, ctx: &AuthContext<'_>, password: &[u8]) -> Result<bool, BoxError> {
        // `password` is the cleartext secret the client sent (here, a JWT);
        // fetch keys / verify claims however you like, keyed on ctx.startup / ctx.sni.
        let _user = ctx.startup.user().unwrap_or_default();
        Ok(verify_jwt(password).await?)
    }
}
// Auth::Cleartext(CleartextPassword::new(JwtValidator { .. }))
```

### Terminate SCRAM-SHA-256

The proxy runs the SCRAM exchange as the *server* using a verifier (never a
plaintext password), then reauthenticates to a SCRAM backend by reusing the
`ClientKey` it recovered from the client's proof:

```rust
use rama_pg::auth::Auth;
use rama_pg::scram::{ScramSecret, ScramSha256, StaticSecretStore};

// Verifiers held in memory (copy from `SELECT rolpassword FROM pg_authid`)…
let store = StaticSecretStore::new()
    .with_secret("alice", ScramSecret::parse("SCRAM-SHA-256$4096:<salt>$<stored>:<server>")?);
let auth = Arc::new(Auth::Scram(ScramSha256::new(store)));
```

### Supply SCRAM verifiers from your own source

`ScramSecretStore` is the async seam for *where verifiers come from*. rama-pg
ships `StaticSecretStore` (above) and `PgAuthidStore`, which fetches from
`pg_authid` on demand over a superuser admin connection:

```rust
use rama_pg::scram::PgAuthidStore;

// host:port, superuser, admin database — read verifiers live from pg_authid.
let store = PgAuthidStore::new("127.0.0.1:5434", "postgres", "postgres");
// Auth::Scram(ScramSha256::new(store))
```

Implement the trait yourself (`async fn get_secret(&self, lookup: SecretLookup)
-> Result<Option<ScramSecret>, BoxError>`) to source verifiers from anywhere —
a control plane, a secrets manager, etc. — keyed on user / database / SNI.

### Pool connections (and load-balance replicas)

Pass a `BackendPool` to enable transaction pooling. List several equivalent
replicas to round-robin transactions across them (a multi-statement transaction
stays pinned to one); pick when a backend is returned with `PoolMode`:

```rust
use rama_pg::pool::{BackendPool, PoolMode};

let pool = BackendPool::new(
    vec!["127.0.0.1:5434".to_owned(), "127.0.0.1:5435".to_owned()],
    8,                      // max pooled connections (across replicas)
    PoolMode::Transaction,  // Session / Transaction / Statement
);
// Pooling terminates auth, so pair it with cleartext or scram (not pass-through):
let proxy = Arc::new(PgProxy::new(tls, router, auth, Some(pool), None, cancellation));
```

A backend is returned to the pool only at a verified idle boundary, and reset
with `DISCARD ALL` first (transaction/statement modes), so session state can't
leak between clients.

### Answer queries in-proxy with no backend

Implement `QueryHandler` for a "virtual Postgres" — the proxy answers queries
itself, with access to per-connection transaction state:

```rust
use std::future::Future;
use std::pin::Pin;
use rama_pg::query::{QueryContext, QueryHandler, QueryResponse};

struct Echo;

impl QueryHandler for Echo {
    fn handle<'a>(
        &'a self,
        ctx: QueryContext<'a>,
        sql: &'a str,
    ) -> Pin<Box<dyn Future<Output = QueryResponse> + Send + 'a>> {
        Box::pin(async move {
            QueryResponse::Rows {
                columns: vec!["echo".to_owned(), "user".to_owned()],
                rows: vec![vec![Some(sql.to_owned()), Some(ctx.user.to_owned())]],
                tag: "SELECT 1".to_owned(),
            }
        })
    }
}
// PgProxy::new(tls, router, auth, None, Some(Arc::new(Echo)), cancellation);
```

### Mediate query cancellation

Cancellation is wired through the `Cancellation` provider passed to `PgProxy`.
`RegistryCancellation` (used above) mints an opaque cancel key per session and
routes a client's `CancelRequest` to the backend it is currently using — for both
direct *and* pooled connections, with nothing else to do. A forwarder reports the
current backend through the `CancelHandle` that `begin` returns: `set` on
lease-acquire (once for a direct 1:1 backend, per-transaction when pooling),
`clear` when idle. Implement the trait to use a different (e.g. distributed) store:

```rust
use bytes::Bytes;
use rama::error::BoxError;
use rama_pg::cancel::{CancelHandle, Cancellation};

type Fut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

struct MyCancellation { /* a shared/distributed map of key -> CancelSlot */ }

impl Cancellation for MyCancellation {
    fn begin(&self) -> Fut<'_, Result<(Option<Bytes>, CancelHandle), BoxError>> {
        Box::pin(async move {
            // Mint a key, make a CancelSlot, store a clone under the key, and
            // return CancelHandle::new(slot, move || /* deregister the key */).
            // (Or (None, CancelHandle::disabled()) to pass the backend's through.)
            todo!()
        })
    }

    fn cancel(&self, key: Bytes) -> Fut<'_, Result<(), BoxError>> {
        Box::pin(async move {
            // Look `key` up, read its slot's current UpstreamSession (if any),
            // and deliver a CancelRequest to that backend.
            todo!()
        })
    }
}
```

Cancellation keys are opaque byte strings (a `BackendKeyData` payload reused as a
`CancelRequest` body), so protocol 3.0's 8-byte key and 3.2's longer key both
work unchanged. `NoCancellation` disables mediation.

### Add your own forwarding mode

The forwarding "mode" (direct / pooled / custom) is just a `rama::Service` over
an authenticated `PgClient`. Write your own and pass it to
`PgProxy::with_forwarder` — the composability seam for anything beyond the
built-in three:

```rust
use rama::Service;
use rama::error::BoxError;
use rama_pg::proxy::{PgClient, PgProxy};
use tokio::io::{AsyncRead, AsyncWrite};

struct MyForwarder;

impl<IO> Service<PgClient<IO>> for MyForwarder
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, client: PgClient<IO>) -> Result<(), BoxError> {
        // client.stream  — the TLS client stream
        // client.startup — parsed StartupMessage (user, database, …)
        // client.sni / client.auth — routing key + auth outcome
        Ok(())
    }
}

// let proxy = PgProxy::with_forwarder(tls, auth, MyForwarder, cancellation);
```

---

## Reference

### Core API (`rama_pg::proxy`)

- **`PgProxy`** — the top-level `rama::Service<TcpStream>`. `PgProxy::new(tls,
  router, auth, pool, handler, cancellation)` picks a built-in forwarder (custom
  if `handler` is `Some`, else pooled if `pool` is `Some`, else direct).
  `PgProxy::with_forwarder(tls, auth, forwarder, cancellation)` takes any
  forwarding `Service`.
- **`PgClient<IO>`** — an authenticated client handed to a forwarder: the TLS
  `stream`, the raw `startup_frame`, the parsed `startup`, the `sni`, and the
  `auth` outcome.
- **`Forwarder`** — alias for the boxed forwarding `Service` over the proxy's
  concrete client stream.

### Auth (`rama_pg::auth`)

- **`Authenticator`** — the trait a mechanism implements (`authenticate(&self,
  client, ctx)`), returning a `ClientAuth`.
- **`Auth`** — a ready-made enum dispatching to `PassThrough`, `Cleartext`, or
  `Scram`, generic over the validator and secret store.
- **`ClientAuth` / `BackendAuth`** — the outcome: pass-through (relay), or
  terminated with a `Trust` or `Scram(keys)` backend handshake.
- **`PasswordValidator`** — async credential check for `CleartextPassword`;
  `StaticPasswordValidator` is the in-memory impl.

### SCRAM (`rama_pg::scram`)

- **`ScramSha256<S>`** — the SCRAM server authenticator over a `ScramSecretStore`.
- **`ScramSecretStore`** — async verifier source; `StaticSecretStore` (in-memory)
  and `PgAuthidStore` (`pg_authid` over an admin connection) are provided.
- **`ScramSecret` / `ScramKeys`** — a parsed verifier and the recovered key
  material reused upstream.

### Pooling (`rama_pg::pool`)

- **`BackendPool`** — `new(replicas, max_size, mode)` builds a pool (on rama's
  client pool) that round-robins transactions across replicas. A backend returns
  only at a verified `ReadyForQuery` idle, reset with `DISCARD ALL` first.
- **`PoolMode`** — when a backend is returned:
  - *session* — one backend per client connection, held for the whole session.
  - *transaction* — a backend per transaction, returned at idle (default).
  - *statement* — a backend per statement; a backend left mid-transaction is
    discarded (multi-statement transactions break).
- **`Lease`** — a checked-out backend (`AsyncRead`/`AsyncWrite` + `reset` /
  `checkin` / `discard`).

### Cancellation (`rama_pg::cancel`)

- **`Cancellation`** — the pluggable seam: `begin` (assign the client's cancel key
  + return a `CancelHandle`) and `cancel` (route an incoming `CancelRequest`).
- **`CancelHandle`** — the forwarder reports the client's current backend through
  it: `set`/`clear`, and it deregisters the key on drop. `CancelSlot` is the
  shared cell behind it; `UpstreamSession` is a backend address + its key.
- **`RegistryCancellation`** — default in-memory store: opaque random keys,
  delivering an upstream `CancelRequest` to the client's current backend. Works
  for both direct and pooled connections.
- **`NoCancellation`** — disables mediation (client sees the backend's own key).

### Custom queries (`rama_pg::query`)

- **`QueryHandler`** — answer simple `Query`s in-proxy; **`QueryContext`** carries
  the user and per-connection **`SessionState`** (transaction status);
  **`QueryResponse`** is `Rows` / `Command` / `Error`.

### Routing (`rama_pg::route`)

- **`Router`** / **`Backend`** — map a TLS SNI hostname to a backend `host:port`,
  with an optional catch-all default (`with_default` / `with_route`).

### Protocol (`rama_pg::protocol`)

- **`startup`** — `SSLRequest` / `StartupMessage` / `CancelRequest` parsing, plus
  protocol-version helpers (`negotiated_version`, `pq_options`,
  `MAX_PROTOCOL_VERSION`).
- **`codec`** — tagged frames, `read_message` (+ the capped pre-auth variant),
  and the cancel-safe `FramedReader`.
- **`message`** — server-message builders.

### Auth mechanisms

- **pass-through** — relay the auth exchange; the *backend* authenticates. Works
  with any backend mechanism, including SCRAM.
- **cleartext** — the proxy asks for a cleartext password and checks it with a
  `PasswordValidator` (a static map, or e.g. a JWKS-fetching JWT validator), then
  connects to a trust backend.
- **scram** — the proxy runs SCRAM-SHA-256 as the server using a verifier from a
  `ScramSecretStore`, then reauthenticates to a SCRAM backend reusing the
  recovered `ClientKey`.

### Crate layout

A Cargo workspace: the `rama-pg` library at the root, plus two showcase binaries.

- `src/proxy/` — the L4 service. `mod.rs` is the front matter (`PgProxy`,
  `PgSession`, `PgClient`); the forwarding modes are one `Service` impl per file
  (`direct.rs` / `pooled.rs` / `custom.rs`).
- `src/auth.rs` — the `Authenticator` trait, the `ClientAuth`/`BackendAuth`
  outcomes, pass-through, and cleartext termination over a `PasswordValidator`.
- `src/scram/` — SCRAM-SHA-256: `crypto` (primitives + key recovery), `secret`
  (verifier + async `ScramSecretStore`), the server authenticator (`mod.rs`),
  `client` (upstream reauth), and `authid` (`PgAuthidStore`).
- `src/pool.rs` — pooling + replica sharding on rama's client pool, keyed on
  `(user, database, replica)`.
- `src/query.rs` — the `QueryHandler` trait, `QueryResponse`, and per-connection
  `SessionState` for custom mode.
- `src/cancel.rs` — the `Cancellation` trait + `RegistryCancellation` /
  `NoCancellation` for query cancellation.
- `src/route.rs` — the SNI router.
- `src/protocol/` — wire types: `startup`, `codec`, `message`.
- `rama-pg-example/` & `pgbouncer/` — the showcases (see below).

---

## Example showcases

These two crates **demonstrate** the library; they are not part of its API.

### `rama-pg-example`

The tutorial program, configurable by environment variables so one binary can
show every mode. `psql` connects with `sslmode=require`; for SNI routing use a
host *name* plus `hostaddr` (libpq omits SNI for IP literals):
`host=db.example.com hostaddr=127.0.0.1`.

| Variable                | Meaning                                                       | Default          |
|-------------------------|---------------------------------------------------------------|------------------|
| `RAMA_PG_LISTEN`        | listen address                                                | `127.0.0.1:6432` |
| `RAMA_PG_BACKEND`       | catch-all backend `host:port`                                 | —                |
| `RAMA_PG_ROUTES`        | exact SNI routes, `sni=host:port` separated by `;`            | —                |
| `RAMA_PG_AUTH`          | `passthrough`, `cleartext`, or `scram`                        | `passthrough`    |
| `RAMA_PG_USERS`         | `user:password` pairs separated by `;` (cleartext mode)       | —                |
| `RAMA_PG_SCRAM_SECRETS` | `user=SCRAM-SHA-256$…` verifiers, `;`-separated (scram mode)   | —                |
| `RAMA_PG_POOL_SIZE`     | max pooled backend connections; enables pooling when set      | — (direct)       |
| `RAMA_PG_REPLICAS`      | `host:port` replicas, `,`-separated, to round-robin (pooling) | `RAMA_PG_BACKEND`|
| `RAMA_PG_POOL_MODE`     | `session`, `transaction`, or `statement` (pooling)            | `transaction`    |
| `RAMA_PG_CUSTOM`        | if set, answer queries in-proxy with no backend               | —                |

```sh
RAMA_PG_AUTH=cleartext RAMA_PG_USERS="alice:secret" \
  RAMA_PG_BACKEND=127.0.0.1:5434 cargo run -p rama-pg-example
```

### `pgbouncer`

A small pgbouncer-alike composed from the library: SCRAM auth with verifiers
fetched from `pg_authid` on demand, configurable pooling, and an admin console on
the `pgbouncer` database. Configured by an INI file:

| Section / key                               | Meaning                                              |
|---------------------------------------------|------------------------------------------------------|
| `[databases]` `* = host=… port=…`           | catch-all backend connstring (also the `pg_authid` source) |
| `[pgbouncer]` `listen_addr` / `listen_port` | listen address                                       |
| `[pgbouncer]` `pool_mode`                   | `session` / `transaction` / `statement`              |
| `[pgbouncer]` `default_pool_size`           | max pooled connections                               |
| `[pgbouncer]` `auth_user` / `auth_dbname`   | superuser + database for `pg_authid` lookups         |

```sh
cargo run -p pgbouncer -- pgbouncer/pgbouncer.ini

# the admin console (connect with dbname=pgbouncer):
psql "host=h hostaddr=127.0.0.1 port=6432 user=alice dbname=pgbouncer sslmode=require" \
  -c "SHOW POOLS"
```

The admin console answers `SHOW POOLS`, `SHOW CLIENTS`, `SHOW STATS`,
`SHOW LISTS`, and `SHOW VERSION`.

---

## Explanation

### Why this exists

rama is built for HTTP/TLS/L4. Postgres is a good stress test of whether its
`Service`/`Layer` model generalises, because the protocol fights the usual
assumptions: TLS is negotiated *after* a plaintext `SSLRequest` on the same
socket (not "TLS from byte 0"), and there is no Host header — the routing keys
are split across the TLS SNI (handshake time) and the `StartupMessage`
(post-TLS). The interesting question throughout was "can this stay idiomatic
rama?", and mostly it can.

### How a connection flows

The whole thing is one L4 `Service<TcpStream>` (`PgProxy`):

1. **TLS entry** — peek the first byte: a TLS `ClientHello` (`0x16`) means a
   *direct-TLS* client (`sslnegotiation=direct`, PG 17+) and goes straight to the
   acceptor (the acceptor advertises the `postgresql` ALPN that direct TLS
   mandates). Otherwise it's the classic flow: read the plaintext `SSLRequest`
   (`80877103`), reply `S`; decline `GSSENCRequest` so the client falls back to
   TLS; reject a plaintext startup. A plaintext `CancelRequest` (the traditional
   libpq cancel path) is handed to the `Cancellation` provider here; the over-TLS
   cancel (libpq 17+) is handled after the handshake.
2. **Mid-stream TLS upgrade** — hand the *same* socket to rama's
   `TlsAcceptorService`, which reads the ClientHello from the current cursor. The
   SNI lands in the stream's extensions.
3. **Startup + negotiation + auth** — `PgSession` reads the `StartupMessage`;
   when it terminates auth it negotiates the protocol version (sending
   `NegotiateProtocolVersion` to downgrade a client that asked for a newer minor
   than the proxy's max, 3.2, or used unknown `_pq_` options) *before* running
   the pluggable `Authenticator`. Pass-through lets the backend negotiate
   (relayed). The result is bundled into a `PgClient`.
4. **Forward** — `PgClient` is handed to a *forwarding leaf*, itself a
   `rama::Service<PgClient<…>>`: `DirectForwarder` (1:1 relay), `PooledForwarder`
   (pooling + sharding), or `CustomForwarder` (answer in-proxy). The leaf is
   selected with `rama::service::BoxService`, so a new mode is "write a
   `Service`", not a new branch — see `PgProxy::with_forwarder`.

The wire codec is hand-rolled and zero-copy: only startup/auth (and
`ReadyForQuery` for pooling) are parsed; everything else is forwarded as opaque
frames.

### Leaning into rama

Where rama already had the right abstraction, the library uses it rather than
reinventing it:

- **TLS** is `TlsAcceptorService` composed around the session.
- **Pooling** is rama's own client pool — `PooledConnector` + `LruDropPool` + a
  `ReqToConnID` key — wrapping a PG `Connector`. The `(user, database, replica)`
  key gives per-role pools and replica sharding for free; a leased connection is
  returned only at a verified idle boundary, reset with `DISCARD ALL` first
  (otherwise discarded), so a desynced or dirty backend can't leak the previous
  client's data.
- **Modes** are `Service`s selected via `BoxService`; auth and routing are the
  pluggable seams (`Authenticator`, `PasswordValidator`, `ScramSecretStore`,
  `Router`).

### Not yet implemented & limitations

- **mTLS (client certificates) is blocked on rama 0.3.** The rustls acceptor
  discards the client cert (`NegotiatedTlsParameters { peer_certificate_chain:
  None, .. }`) and the builder only offers `with_no_client_auth()`, so the proxy
  never sees a cert. A clean fix is small and upstream; deferred pending that.
- **Auth** — `OAUTHBEARER` is not implemented (JWT-over-cleartext needs no new
  mechanism, just a `PasswordValidator`). SASLprep and SCRAM-SHA-256-PLUS channel
  binding are not done. The `cleartext` mechanism terminates only to a trust
  backend.
- **Pooling** — non-trust backends and a primary/replica read-write split are
  future work. Transaction/statement modes reset reused backends with
  `DISCARD ALL`; session-mode connections are still discarded on close rather
  than reused (the relay is opaque, so there's no idle boundary to reset at).
- **`CancelRequest` routing** is implemented for **direct and pooled modes** via
  the pluggable `Cancellation` provider: the proxy mints an opaque cancel key,
  captures the backend's, and routes a client's `CancelRequest` upstream — to the
  backend it is currently using (tracked per-transaction when pooling), over
  either the plaintext or the over-TLS cancel path. Protocol versions are
  negotiated (3.0 and 3.2): a synthesized-mode client on 3.2 gets a longer,
  harder-to-guess cancel key; direct modes issue the classic 4-byte key.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
