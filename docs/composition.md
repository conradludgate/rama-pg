# Composable PostgreSQL services

Rama-pg provides reusable PostgreSQL protocol services. The `pgbouncer` workspace
member assembles those services into one proxy application; its configuration,
admin commands and policy defaults belong to that application.

## Composition boundaries

The connection pipeline is:

```text
transport / TLS policy
    -> PostgreSQL startup and authentication (PgSession)
    -> authenticated PgClient<IO>
    -> caller-supplied Rama Service and Layers
```

`PgProxy` supplies the standard TCP entry point, including PostgreSQL's
SSLRequest upgrade and direct-TLS entry. It delegates startup/authentication to
the same `PgSession` callers can place behind their own transport layers.
`PgSession` reads SNI from Rama's transport extensions when available. Applications
that compose it directly must establish their own transport security policy.

The forwarder is a concrete `Service<PgClient<IO>>`, with an error convertible to
`BoxError`. Ordinary Rama layers can surround it. Runtime boxing remains an
option at a deliberate boundary; it is not a requirement for custom forwarders.
The built-in constructor still boxes its runtime choice of direct, pooled or
custom mode. `PgProxy::with_forwarder` retains the supplied service type, so
explicit annotations using the old default boxed `PgProxy<A>` type may need to
name the new forwarder parameter or allow type inference.

Examples this boundary enables include application-aware routing using startup
user/database parameters, per-tenant admission layers, custom authentication,
and virtual PostgreSQL endpoints. They do not need PgBouncer's configuration
model or its pooling modes.

## Protocol I/O

The archived local implementation emphasized limits before allocation, bounded
borrowed parsing and streaming opaque bodies. The remote library supplies the
existing TLS/authentication, cancellation and forwarding services. The first
integration combines those strengths without importing the local placeholder
pooling/session types or its demo SQL engine.

For decoded messages, `read_message_capped` and `FramedReader::with_max_len`
validate headers before reading bodies, and grow storage with received data.
Lengths include the four-byte length field and exclude the tag. The default
reader limit is unchanged; applications select tighter budgets where needed.
This is a per-message bound, not a total connection/time/session limit.

For opaque payloads, `read_header` exposes a validated `MessageHeader`.
`copy_body_to` streams exactly that body through caller-owned scratch storage.
No body-sized allocation is needed, and the next message is left in the stream.
Use a sink as the writer when discarding an unsupported body. Deciding which
messages to inspect remains separate from transporting bytes.

`FramedReader` retains partial headers/bodies across cancelled read futures. It
does not read beyond the returned frame, so handing off the transport at
ReadyForQuery cannot discard a prefetched asynchronous notice/notification.
Header/body streaming operations are sequential, not cancel-safe: if interrupted
or errored, terminate the connection rather than restarting message parsing.
Existing direct forwarding continues to use opaque bidirectional copying after
startup, rather than decoding every message.

## Next integration steps

These are follow-ups, not claims that the first integration implements them:

1. **Rama-native backend establishment.** Direct forwarding now accepts routing
   and establishment services. Routes own/return PgClient; custom connectors
   accept any owned target and return BackendConnection with its stream and a
   cloneable cancellation service. The TCP default uses Rama's non-HTTP connect
   primitive and pins cancellation to the connected peer. Custom policies can
   layer DNS/TLS/deadlines and carry tenant-specific target metadata. Next apply
   this establishment boundary to pooled backends without folding pool lifecycle
   or PgBouncer configuration into the transport service.
2. **Layered resource policy.** Thread application-selected frame budgets through
   built-in forwarders/authentication. Use Rama layers for concurrency and time
   budgets; account separately for session and pool state. Preserve opaque
   streaming for large CopyData payloads instead of forcing buffering.
3. **Pooling boundaries.** Keep reuse/reset/transaction-state handling separate
   from routing and transport. PgBouncer's session/transaction/statement policies
   are implementations of this boundary, not the only possible proxy model.
4. **Compatibility tests.** The original imported PgBouncer corpus remains
   unchanged in the local archive. Adopt its fixtures against the library and
   showcase deliberately; do not carry over blanket non-strict expected-failure
   marking as evidence of compatibility. Add scripted backend and real PostgreSQL
   tests for TLS, cancellation, pool resets, pipelining and asynchronous messages.
5. **Rama baseline.** Select an updated Rama revision in its own change after
   checking the connector/TLS/service APIs against the maintained Rama work.

The two implementations have unrelated Git roots. The local history, portal
fix and generated test artifacts are preserved separately; reconciliation means
porting useful behavior with tests, rather than merging unrelated histories.
