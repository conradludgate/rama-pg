# rama-pg

A Postgres wire-protocol proxy built on [rama](https://ramaproxy.org) (tracking
git `0.3.0-rc1`).

It exists to test whether rama's `Service`/`Layer` model — built for HTTP/TLS/L4
— extends cleanly to a non-HTTP L7 protocol with awkward edges: Postgres
negotiates TLS *after* a plaintext `SSLRequest`, and has no Host header to route
on (the routing keys are spread across the TLS SNI and the post-TLS
`StartupMessage`).

## What works

The whole connection is one L4 `Service<State, TcpStream>` (`PgProxy`):

1. **Pre-TLS `SSLRequest` shim** — reads the plaintext `SSLRequest`
   (`80877103`) and replies `S`; declines `GSSENCRequest` (`80877104`) so the
   client falls back to TLS; rejects plaintext startup (TLS is required).
2. **Mid-stream TLS upgrade** — hands the *same* socket to rama's
   `TlsAcceptorService`, which reads the ClientHello from the current cursor.
   The SNI is captured into the context for routing.
3. **Hand-rolled, zero-copy codec** — startup-phase parsing plus a tagged-message
   reader that retains whole frames so they can be forwarded opaquely.
4. **SNI routing** — a static SNI → backend map (no control-plane lookup).
5. **Pluggable auth** — an `Authenticator` trait, with two mechanisms today:
   - `PassThrough` — relay the auth exchange so the *backend* authenticates the
     client. Works with any backend mechanism, including SCRAM-SHA-256.
   - `CleartextPassword` — the proxy *terminates* auth itself, checking the
     supplied secret with a pluggable, async `PasswordValidator` (a static map,
     or e.g. a JWKS-fetching JWT validator since a JWT rides the cleartext
     password), then dials a trust backend and splices its startup result
     (`AuthenticationOk` … `ReadyForQuery`) back to the client.
   - `ScramSha256` — the proxy runs the full SCRAM-SHA-256 (RFC 5802/7677) SASL
     exchange as the server, using a verifier from a pluggable, async
     `ScramSecretStore` (keyed on user/database/SNI) — *not* a plaintext
     password. Because it presents Postgres' own salt, the `ClientKey` it
     recovers from the client's proof is valid upstream, so it then
     **reauthenticates to a SCRAM backend** reusing that key (terminate-then-
     reauth). Crypto is checked against the RFC 7677 vector; channel binding
     (`-PLUS`) is not offered.
6. **Direct 1:1 proxy** — forward the `StartupMessage` verbatim, then
   `tokio::io::copy_bidirectional`.
7. **Transaction pooling + replica sharding** (optional) — multiplex clients over
   a shared pool of backend connections, built on **rama's own client pool**
   (`PooledConnector` + `LruDropPool` + a `ReqToConnID` keyed on
   `(user, database, replica)`). A connection is leased per transaction and
   returned at `ReadyForQuery` status `I` by dropping the `LeasedConnection` (a
   backend left mid-transaction is discarded, so no state leaks). The proxy
   terminates auth, synthesizes the client's startup from the pool's captured
   `ParameterStatus`, and relays via a cancel-safe `FramedReader`. With several
   replica addresses, transactions are round-robined across them (read
   load-balancing — a multi-statement transaction stays pinned to one replica).
   Three pgbouncer-style modes (`PoolMode`): session, transaction, statement.
8. **Custom in-proxy queries** (optional) — a "virtual Postgres" with no backend
   at all: a pluggable async `QueryHandler` answers simple-protocol queries, the
   proxy synthesizes the startup and encodes `RowDescription`/`DataRow`/
   `CommandComplete`, and a per-connection mutable `SessionState` tracks the
   transaction status (`I`/`T`/`E`) — visible to the handler — so `BEGIN`/
   `COMMIT`/`ROLLBACK` work.

## Run

`rama-pg` is a library; the runnable proxy is the `rama-pg-example` crate.

```sh
# pass-through: the backend authenticates the client (works with SCRAM, md5, …)
RAMA_PG_LISTEN=127.0.0.1:6432 RAMA_PG_BACKEND=127.0.0.1:5432 \
  cargo run -p rama-pg-example

# proxy-terminated cleartext auth in front of a trust backend
RAMA_PG_AUTH=cleartext RAMA_PG_USERS="alice:secret" \
  RAMA_PG_BACKEND=127.0.0.1:5434 cargo run -p rama-pg-example

# proxy-terminated SCRAM, reauthenticating to a SCRAM backend with the
# verifier copied from Postgres `pg_authid.rolpassword` (no plaintext)
RAMA_PG_AUTH=scram \
  RAMA_PG_SCRAM_SECRETS="alice=SCRAM-SHA-256\$4096:<salt>\$<stored>:<server>" \
  RAMA_PG_BACKEND=127.0.0.1:5433 cargo run -p rama-pg-example

# transaction pooling: many clients multiplexed over 8 backend connections
RAMA_PG_POOL_SIZE=8 RAMA_PG_AUTH=cleartext RAMA_PG_USERS="alice:secret" \
  RAMA_PG_BACKEND=127.0.0.1:5434 cargo run -p rama-pg-example

# pooling + replica sharding: round-robin transactions across two replicas
RAMA_PG_POOL_SIZE=8 RAMA_PG_AUTH=cleartext RAMA_PG_USERS="alice:secret" \
  RAMA_PG_REPLICAS="127.0.0.1:5434,127.0.0.1:5435" cargo run -p rama-pg-example

# custom in-proxy queries: a virtual Postgres with no backend
RAMA_PG_CUSTOM=1 RAMA_PG_AUTH=cleartext RAMA_PG_USERS="alice:secret" \
  cargo run -p rama-pg-example
```

### pgbouncer-like example

The `pgbouncer` crate composes the above into a small pgbouncer-alike: SCRAM
auth with verifiers fetched from `pg_authid` on demand, pooling (session /
transaction / statement), and an admin console on the `pgbouncer` database
answering `SHOW POOLS` / `CLIENTS` / `STATS` / `LISTS` / `VERSION`. It is
configured by a **pgbouncer-style INI file** (`[databases]` backend connstring +
`[pgbouncer]` settings) — see `pgbouncer/pgbouncer.ini`.

```sh
cargo run -p pgbouncer -- pgbouncer/pgbouncer.ini
# real database — SCRAM auth (verifier from pg_authid), then pooled:
psql "host=h hostaddr=127.0.0.1 port=6432 user=alice dbname=shop sslmode=require"
# admin console:
psql "host=h hostaddr=127.0.0.1 port=6432 user=alice dbname=pgbouncer sslmode=require" -c "SHOW POOLS"
```

Connect through it (SNI comes from the host name; `hostaddr` keeps the dial on
localhost):

```sh
psql "host=db.example.com hostaddr=127.0.0.1 port=6432 \
      user=alice dbname=shop sslmode=require"
```

### Configuration (environment)

| Variable          | Meaning                                             | Default            |
|-------------------|-----------------------------------------------------|--------------------|
| `RAMA_PG_LISTEN`  | listen address                                      | `127.0.0.1:6432`   |
| `RAMA_PG_BACKEND` | catch-all backend `host:port`                       | —                  |
| `RAMA_PG_ROUTES`  | exact SNI routes, `sni=host:port` separated by `;`  | —                  |
| `RAMA_PG_AUTH`    | `passthrough`, `cleartext`, or `scram`              | `passthrough`      |
| `RAMA_PG_USERS`   | `user:password` pairs separated by `;` (cleartext)  | —                  |
| `RAMA_PG_SCRAM_SECRETS` | `user=SCRAM-SHA-256$…` verifiers, `;`-separated (scram) | —          |
| `RAMA_PG_POOL_SIZE` | max pooled backend connections; enables transaction pooling | — (direct) |
| `RAMA_PG_REPLICAS` | `host:port` replicas, `,`-separated, to round-robin across (pooling) | `RAMA_PG_BACKEND` |
| `RAMA_PG_POOL_MODE` | `session`, `transaction`, or `statement` (pooling) | `transaction` |
| `RAMA_PG_CUSTOM` | if set, answer queries in-proxy with no backend (virtual server) | — |

TLS currently uses a self-signed certificate, so connect with `sslmode=require`
(which encrypts without verifying the certificate).

## Not yet implemented

- **mTLS (client certificates) is blocked on rama 0.3.** The rustls acceptor
  discards the client cert (`NegotiatedTlsParameters { peer_certificate_chain:
  None, .. }`) and `TlsAcceptorDataBuilder` only exposes `with_no_client_auth()`,
  so the proxy never sees a cert to map to an identity. A clean fix is small and
  upstream (the acceptor already holds the rustls connection — it just needs to
  read `peer_certificates()`); the alternative is a raw-rustls escape hatch that
  leaks TLS internals into the session. Deferred pending an upstream discussion.
- More auth mechanisms: `OAUTHBEARER`. (JWT-over-cleartext needs no built-in
  mechanism — supply a `PasswordValidator` that verifies the token against
  JWKS.) The `cleartext` mechanism still terminates to a trust backend (only
  SCRAM does upstream reauth); SASLprep password normalisation is future work.
  A `PgAuthidStore` ships (fetches verifiers from `pg_authid` on demand); other
  `ScramSecretStore` / `PasswordValidator` implementations (control plane, JWKS
  fetching) are left to the user behind the async traits.
- Pooling beyond v1: non-trust backends (the pool's connector can't satisfy a
  credential challenge yet), server reset/`DISCARD ALL` reuse instead of
  discarding a dirty connection, and correctness under cross-transaction
  pipelining. Per-`(user, database)` pooling and round-robin replica sharding
  already work via the pool key; a primary/replica read-write split (routing
  writes to a primary, reads to replicas via query classification) is future.
- `CancelRequest` routing — it arrives on a *separate* connection carrying a
  PID + secret and must reach the same backend, so it needs a cancel-key map.
- Direct-TLS (ALPN, client skips `SSLRequest`) and SCRAM-SHA-256-PLUS channel
  binding.

## Layout

A Cargo workspace: the `rama-pg` library at the root, plus two example binaries.

- `src/protocol/` — wire types: `startup` (SSLRequest / StartupMessage /
  CancelRequest), `codec` (tagged frames, `read_message`, and the cancel-safe
  `FramedReader`), `message` (server-message builders).
- `src/route.rs` — the SNI router.
- `src/pool.rs` — transaction pooling + replica sharding on rama's client pool:
  a PG `Connector` through `PooledConnector` / `LruDropPool`, keyed on
  `(user, database, replica)`, round-robining transactions across replicas.
- `src/query.rs` — the `QueryHandler` trait, `QueryResponse`, and the
  per-connection mutable `SessionState` (transaction status) for custom mode.
- `src/auth.rs` — the `Authenticator` trait, the `ClientAuth`/`BackendAuth`
  outcomes, the pass-through mechanism, and cleartext termination over a
  pluggable async `PasswordValidator`.
- `src/scram/` — SCRAM-SHA-256: `crypto` (primitives + key recovery), `secret`
  (the verifier + async `ScramSecretStore`), the server-side authenticator
  (`mod.rs`), `client` (upstream reauth), and `authid` (`PgAuthidStore`).
- `src/proxy/` — the L4 service: SSL shim → TLS → startup → auth, then a
  forwarding **leaf `rama::Service`** over a `PgClient`. `mod.rs` holds the
  front matter (`PgProxy`, `PgSession`, `PgClient`); the three modes are one
  `Service` impl per file — `direct.rs` / `pooled.rs` / `custom.rs` — selected
  via `BoxService`. `PgProxy::with_forwarder` takes any `Service<PgClient<…>>`,
  so a new mode is "write a `Service`", not a new branch.
- `rama-pg-example/` — the runnable proxy binary (env-driven configuration).
- `pgbouncer/` — a pgbouncer-like example composing it all via
  `PgProxy::with_forwarder`: a database-routing forwarder (admin console vs.
  pool), `pg_authid` SCRAM auth, pooling modes, and `SHOW` commands. Configured
  by a `pgbouncer.ini` (a small hand-rolled INI parser in `config.rs`).
