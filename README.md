# rama-pg

A Postgres wire-protocol proxy built on [rama](https://ramaproxy.org) — an
experiment in stretching rama's HTTP/TLS/L4 `Service`/`Layer` model onto a
non-HTTP protocol with awkward edges (TLS negotiated *after* a plaintext
`SSLRequest`; no Host header to route on).

> ⚠️ **Experimental — not for production.** rama-pg is an educational
> exploration, useful for understanding the Postgres wire protocol and rama's
> service model — not for fronting a real database. It authenticates clients but
> takes deliberate shortcuts (no SASLprep, a trust-only `pg_authid` admin
> connection, no channel binding, no `CancelRequest` routing) and builds against
> an unreleased git revision of rama. Don't put it in front of data you care
> about.

The docs below follow [Diátaxis](https://diataxis.fr): a **tutorial** to get
going, **how-to guides** for specific tasks, **reference** for the dry details,
and **explanation** for the why.

---

## Tutorial: proxy your first connection

This takes you from nothing to a `psql` session flowing through rama-pg. You need
Rust (stable) and a Postgres you can reach at `127.0.0.1:5432`.

**1. Start the proxy** in pass-through mode, pointing at your Postgres:

```sh
RAMA_PG_BACKEND=127.0.0.1:5432 cargo run -p rama-pg-example
```

It logs `rama-pg listening` on `127.0.0.1:6432`.

**2. Connect through it** with `psql` from another terminal. Postgres requires
TLS at this point and the proxy presents a self-signed certificate, so use
`sslmode=require` (encrypt without verifying) and your normal Postgres
credentials:

```sh
psql "host=127.0.0.1 port=6432 user=$USER dbname=postgres sslmode=require" \
  -c "select 'hello through rama-pg'"
```

**3. You should see the query's result.** What just happened: psql sent a
plaintext `SSLRequest`; the proxy answered `S` and upgraded the *same* socket to
TLS; it read your `StartupMessage`, dialed your Postgres, and relayed the rest
byte-for-byte — your Postgres did the actual authentication.

That's the direct pass-through path. The how-to guides add auth termination,
pooling, and an in-proxy query mode on top.

---

## How-to guides

All commands run the `rama-pg-example` binary, configured by environment
variables (see [Reference](#reference)). `psql` connects with
`sslmode=require`; to exercise SNI routing, use a host *name* plus `hostaddr`
(libpq omits SNI for IP literals): `host=db.example.com hostaddr=127.0.0.1`.

### Terminate password auth at the proxy

The proxy challenges the client for a cleartext password (safe over the required
TLS) and checks it itself, then connects to a trust backend:

```sh
RAMA_PG_AUTH=cleartext RAMA_PG_USERS="alice:secret" \
  RAMA_PG_BACKEND=127.0.0.1:5434 cargo run -p rama-pg-example
```

### Terminate SCRAM auth at the proxy

Run the full SCRAM-SHA-256 exchange as the server, using a verifier (not a
plaintext password). The proxy then reauthenticates to a SCRAM backend by
reusing the `ClientKey` it recovered from the client:

```sh
RAMA_PG_AUTH=scram \
  RAMA_PG_SCRAM_SECRETS="alice=SCRAM-SHA-256\$4096:<salt>\$<stored>:<server>" \
  RAMA_PG_BACKEND=127.0.0.1:5433 cargo run -p rama-pg-example
```

Copy the verifier from `SELECT rolpassword FROM pg_authid WHERE rolname='alice'`.
To fetch it automatically instead, see the
[pgbouncer example](#run-the-pgbouncer-like-example).

### Pool connections

Enable transaction pooling by giving a pool size; pick a mode with
`RAMA_PG_POOL_MODE` (`session` / `transaction` / `statement`):

```sh
RAMA_PG_POOL_SIZE=8 RAMA_PG_POOL_MODE=transaction \
  RAMA_PG_AUTH=cleartext RAMA_PG_USERS="alice:secret" \
  RAMA_PG_BACKEND=127.0.0.1:5434 cargo run -p rama-pg-example
```

Pooling terminates auth, so use `cleartext` or `scram` (not `passthrough`).

### Load-balance reads across replicas

List several equivalent replicas; each transaction round-robins across them (a
multi-statement transaction stays pinned to one):

```sh
RAMA_PG_POOL_SIZE=8 RAMA_PG_AUTH=cleartext RAMA_PG_USERS="alice:secret" \
  RAMA_PG_REPLICAS="127.0.0.1:5434,127.0.0.1:5435" cargo run -p rama-pg-example
```

### Serve queries in-proxy with no backend

A "virtual Postgres" — the proxy answers queries itself (the example ships a demo
handler that echoes the query, user, and transaction status):

```sh
RAMA_PG_CUSTOM=1 RAMA_PG_AUTH=cleartext RAMA_PG_USERS="alice:secret" \
  cargo run -p rama-pg-example
```

### Run the pgbouncer-like example

The `pgbouncer` crate composes the library into a small pgbouncer-alike: SCRAM
auth with verifiers fetched from `pg_authid` on demand, configurable pooling, and
an admin console on the `pgbouncer` database. It is configured by an INI file:

```sh
cargo run -p pgbouncer -- pgbouncer/pgbouncer.ini

# a real database — SCRAM auth (verifier from pg_authid), then pooled:
psql "host=h hostaddr=127.0.0.1 port=6432 user=alice dbname=shop sslmode=require"

# the admin console:
psql "host=h hostaddr=127.0.0.1 port=6432 user=alice dbname=pgbouncer sslmode=require" \
  -c "SHOW POOLS"
```

### Add your own forwarding mode

A forwarding "mode" is just a `rama::Service` over an authenticated `PgClient`.
Implement one and pass it to `PgProxy::with_forwarder`:

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
        // client.stream — the TLS client stream
        // client.startup — parsed StartupMessage (user, database, …)
        // client.sni / client.auth — routing key + auth outcome
        Ok(())
    }
}

// let proxy = PgProxy::with_forwarder(tls, auth, MyForwarder);
```

---

## Reference

### `rama-pg-example` environment variables

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

TLS uses a self-signed certificate, so clients must use `sslmode=require` (which
encrypts without verifying the certificate).

### `pgbouncer.ini`

| Section / key                 | Meaning                                              |
|-------------------------------|------------------------------------------------------|
| `[databases]` `* = host=… port=…` | catch-all backend connstring (also the `pg_authid` source) |
| `[pgbouncer]` `listen_addr` / `listen_port` | listen address                          |
| `[pgbouncer]` `pool_mode`     | `session` / `transaction` / `statement`              |
| `[pgbouncer]` `default_pool_size` | max pooled connections                           |
| `[pgbouncer]` `auth_user` / `auth_dbname` | superuser + database for `pg_authid` lookups |

The admin console (connect with `dbname=pgbouncer`) answers `SHOW POOLS`,
`SHOW CLIENTS`, `SHOW STATS`, `SHOW LISTS`, and `SHOW VERSION`.

### Pooling modes

- **session** — one backend per client connection, held for the whole session.
- **transaction** — a backend per transaction, returned at `ReadyForQuery` idle.
- **statement** — a backend per statement; multi-statement transactions break
  (the backend is discarded if left mid-transaction).

### Auth mechanisms

- **passthrough** — relay the auth exchange; the *backend* authenticates the
  client. Works with any backend mechanism, including SCRAM.
- **cleartext** — the proxy asks for a cleartext password and checks it with a
  pluggable async `PasswordValidator` (a static map, or e.g. a JWKS-fetching JWT
  validator), then connects to a trust backend.
- **scram** — the proxy runs SCRAM-SHA-256 as the server, using a verifier from a
  pluggable async `ScramSecretStore` (`StaticSecretStore` or `PgAuthidStore`),
  then reauthenticates to a SCRAM backend reusing the recovered `ClientKey`.

### Crate layout

A Cargo workspace: the `rama-pg` library at the root, plus two example binaries.

- `src/protocol/` — wire types: `startup` (SSLRequest / StartupMessage /
  CancelRequest), `codec` (tagged frames, `read_message`, the cancel-safe
  `FramedReader`), `message` (server-message builders).
- `src/route.rs` — the SNI router.
- `src/auth.rs` — the `Authenticator` trait, the `ClientAuth`/`BackendAuth`
  outcomes, pass-through, and cleartext termination over a `PasswordValidator`.
- `src/scram/` — SCRAM-SHA-256: `crypto` (primitives + key recovery), `secret`
  (verifier + async `ScramSecretStore`), the server authenticator (`mod.rs`),
  `client` (upstream reauth), and `authid` (`PgAuthidStore`).
- `src/pool.rs` — pooling + replica sharding on rama's client pool: a PG
  `Connector` through `PooledConnector` / `LruDropPool`, keyed on
  `(user, database, replica)`.
- `src/query.rs` — the `QueryHandler` trait, `QueryResponse`, and the
  per-connection mutable `SessionState` (transaction status) for custom mode.
- `src/proxy/` — the L4 service. `mod.rs` is the front matter (`PgProxy`,
  `PgSession`, `PgClient`); the forwarding modes are one `Service` impl per file
  (`direct.rs` / `pooled.rs` / `custom.rs`).
- `rama-pg-example/` — the runnable proxy binary (env-driven).
- `pgbouncer/` — the pgbouncer-like example (INI-driven).

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

1. **Pre-TLS `SSLRequest` shim** — read the plaintext `SSLRequest` (`80877103`),
   reply `S`; decline `GSSENCRequest` so the client falls back to TLS; require
   TLS (reject plaintext startup).
2. **Mid-stream TLS upgrade** — hand the *same* socket to rama's
   `TlsAcceptorService`, which reads the ClientHello from the current cursor. The
   SNI lands in the stream's extensions.
3. **Startup + auth** — `PgSession` reads the `StartupMessage`, runs the
   pluggable `Authenticator`, and bundles everything into a `PgClient` (stream +
   startup + SNI + auth outcome).
4. **Forward** — `PgClient` is handed to a *forwarding leaf*, itself a
   `rama::Service<PgClient<…>>`: `DirectForwarder` (1:1 relay), `PooledForwarder`
   (pooling + sharding), or `CustomForwarder` (answer in-proxy). The leaf is
   selected with `rama::service::BoxService`, so a new mode is "write a
   `Service`", not a new branch — see `PgProxy::with_forwarder`.

The wire codec is hand-rolled and zero-copy: only startup/auth (and
`ReadyForQuery` for pooling) are parsed; everything else is forwarded as opaque
frames.

### Leaning into rama

Where rama already had the right abstraction, the proxy uses it rather than
reinventing it:

- **TLS** is `TlsAcceptorService` composed around the session.
- **Pooling** is rama's own client pool — `PooledConnector` + `LruDropPool` + a
  `ReqToConnID` key — wrapping a PG `Connector`. The `(user, database, replica)`
  key gives per-role pools and replica sharding for free; a leased connection is
  returned to the pool only at a verified idle boundary (otherwise discarded, so
  a desynced backend can't leak the previous client's data).
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
- **Pooling** — non-trust backends, a `DISCARD ALL` server-reset on reuse, and a
  primary/replica read-write split are future work. Session-pool connections are
  currently discarded on close rather than reused (no reset hook yet).
- **`CancelRequest` routing** — arrives on a separate connection carrying a PID +
  secret; needs a cancel-key map (not implemented).
- **Direct-TLS** (ALPN, client skips `SSLRequest`) is not handled.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
