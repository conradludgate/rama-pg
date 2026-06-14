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
   - `CleartextPassword` — the proxy *terminates* auth itself against a static
     credential map, then dials the backend and splices its startup result
     (`AuthenticationOk` … `ReadyForQuery`) back to the client.
6. **Direct 1:1 proxy** — forward the `StartupMessage` verbatim, then
   `tokio::io::copy_bidirectional`.

## Run

```sh
# pass-through: the backend authenticates the client (works with SCRAM, md5, …)
RAMA_PG_LISTEN=127.0.0.1:6432 RAMA_PG_BACKEND=127.0.0.1:5432 cargo run

# proxy-terminated cleartext auth in front of a trust backend
RAMA_PG_AUTH=cleartext RAMA_PG_USERS="alice:secret" \
  RAMA_PG_BACKEND=127.0.0.1:5434 cargo run
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
| `RAMA_PG_AUTH`    | `passthrough` or `cleartext`                        | `passthrough`      |
| `RAMA_PG_USERS`   | `user:password` pairs separated by `;` (cleartext)  | —                  |

TLS currently uses a self-signed certificate, so connect with `sslmode=require`
(which encrypts without verifying the certificate).

## Not yet implemented

- More auth mechanisms: SCRAM-SHA-256 termination (terminate-then-reauth),
  JWT-as-cleartext-password validation, mTLS, `OAUTHBEARER`.
- Session / transaction pooling (return the backend to a pool at transaction
  boundaries by tracking the `ReadyForQuery` status `I`/`T`/`E`) and read-only
  sharding (primary/replica split).
- `CancelRequest` routing — it arrives on a *separate* connection carrying a
  PID + secret and must reach the same backend, so it needs a cancel-key map.
- Direct-TLS (ALPN, client skips `SSLRequest`) and SCRAM-SHA-256-PLUS channel
  binding.

## Layout

- `src/protocol/` — wire types: `startup` (SSLRequest / StartupMessage /
  CancelRequest), `codec` (tagged frames + the `read_message` reader),
  `message` (server-message builders).
- `src/route.rs` — the SNI router.
- `src/auth.rs` — the `Authenticator` trait and mechanisms.
- `src/proxy.rs` — the L4 service: SSL shim → TLS → startup → auth → forward.
