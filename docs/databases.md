# Databases

Status: **design, not built**. The broker already speaks to SQL Server and RavenDB for agents and
scripts. This page designs the next step: an ordinary application (EF Core, ADO.NET, the RavenDB
client) using a database without the long-lived credential ever being in the app, its
configuration or its folder.

## What exists

- **SQL Server, statements over HTTP.** A vault service with upstream `mssql://host/database` and
  `read`/`write` grants. `POST /sql/{instance}/{grant}` runs one statement and returns rows as
  JSON. The broker connects as a **temporary login** `tir_<lease>_<grant>`, created on first use by
  `tir.BeginLease` (signed procedures, `src/Tiresias.Broker/sql/01-tiresias-setup.sql`) and
  dropped at lease end. A `read` grant only runs what `SqlReadClassifier` proves is one SELECT.
  The provisioner connection string is the vault secret. `tir exec` hands out `{SLUG}_SQL_URL`.
- **RavenDB, HTTP proxied.** `* /raven/{instance}/**`: the broker presents the instance's client
  certificate (a PFX in the vault, loaded ephemeral, disposed at lease end) and rewrites topology
  responses so the client never learns a node URL (`RavenTopology`). WebSocket requests (Changes
  API) get `501`, and the TCP protocol (subscriptions) is not reachable at all.

Neither serves an application that uses the normal drivers.

## Decisions

- **Apps first, agents second.** Phase 1 is the app path. Agent-side work (desktop UI for SQL and
  Raven services, schema discovery on `/sql`) follows.
- **SQL Server: hand out a short-lived login, not a wire proxy.** The app gets a connection string
  whose login is a `tir.BeginLease` temporary login, dropped at lease end. It works with every
  driver and every feature (MARS, bulk copy, connection pooling) because SQL
  Server sees an ordinary login. A TDS proxy that swaps credentials would keep even the temporary
  password out of the app, but means terminating TLS and rewriting LOGIN7 packets for every driver
  version; the risk is in the proxy, not the credential. Entra access tokens only fit Azure SQL.
- **RavenDB: extend the proxy, keep the certificate in the broker.** The app talks plain HTTP to
  the local forwarder; the broker holds the certificate. Minting per-lease client certificates
  would need a cluster admin certificate in the broker, a far bigger key to lose.

## SQL Server for applications

The trade-off, stated once: **the app holds a credential**, but one that

- exists only in the app's memory and the lease's broker process, never on disk;
- is scoped to one database and one fixed role (`tir_read` or `tir_write`: no DDL);
- dies with the lease (workday cap, at most 10 hours, enforced by the procedure), on lock, or on
  revocation, and its sessions are killed then (`tir.DropLogins`).

A stolen `secrets.json` or a leaked environment gives nothing; a memory dump of a running app gives
a login that expires that day.

### Shape

1. The vault service is the existing one (`mssql://`), with a new grant flag **`login`**: this
   grant may be handed out as a login, not only used by the broker. Without it nothing changes;
   handing a login out bypasses the per-statement read classifier, so it is opt-in per grant.
2. New broker endpoint `POST /sql/{instance}/{grant}/login` → `{ connectionString, expiresAt }`.
   Same authorization, elevation and audit as `/sql`, audited as `Method: "LOGIN"`. The broker
   keeps the login for the lease as it does today; one lease, one login per grant.
3. The app asks for it through what it already uses:
   - **Configuration:** a `secrets.json` value `tiresias:sql/{instance}/{grant}` (for example
     `ConnectionStrings:Default`). `AddProtectedUserSecrets` resolves it through the agent, which
     asks the broker (solo or remote) after the usual consent. No code change.
   - **`tir run` / `tir exec`:** `{SLUG}_CONNECTION_STRING`, next to the existing `_SQL_URL`.
4. **Renewal.** At 80 % of the lease the provider fetches a new login and raises a configuration
   reload. The old login stays valid until its own lease ends, so the windows overlap. An app that
   reads the connection string per `DbContext` (the default `AddDbContext` lambda) picks it up;
   one that captured it at startup keeps working until the old lease ends, then fails, and the log
   says why. Pooled connections on the old login are killed at its end; SqlClient clears the pool
   and EF's retrying execution strategy reconnects.

### Open questions

- **Migrations.** `tir_write` has no DDL. Either migrations stay an admin step outside Tiresias,
  or a third role `tir_owner` (`db_ddladmin`) exists behind elevation. Leaning: admin step, said
  plainly in the guide.
- **Remote broker reachability.** The app connects to SQL Server directly; the broker only needs
  the provisioner path. Nothing new on the network, but the guide must say so.

## RavenDB for applications

### Shape

1. The app's configuration points at the forwarder:
   `http://127.0.0.1:{port}/raven/{instance}/{placeholder}` with no certificate. The `tirph_`
   placeholder rides in the **path**, because the RavenDB client sends no custom header on its
   WebSocket and TCP connections. A placeholder works only through this machine's forwarder and is
   revocable, so its showing up in a client log costs little. The broker strips it before
   forwarding, and topology rewrites keep it in every node URL.
2. **HTTP**: as today.
3. **Changes API (WebSocket)**: the forwarder accepts the upgrade and opens a WebSocket to the
   broker's same route; the broker opens one upstream with the certificate and pumps frames both
   ways. Replaces the `501`.
4. **Subscriptions and other TCP operations**: the client asks `GET /info/tcp` and connects where
   the answer says. The broker rewrites that answer like topology: `Url` becomes
   `tcp://127.0.0.1:{relay}` on the forwarder and `Certificate` becomes `null`, so the client
   speaks plain TCP to loopback. The forwarder tunnels each TCP connection to the broker over a
   WebSocket (`/raven/{instance}/{placeholder}/tcp`), keeping the device-signed channel; the broker
   opens TLS to the node with the client certificate and relays bytes.
5. **Policy**: HTTP keeps its method/path rules. A WebSocket or TCP tunnel is opaque after the
   handshake, so each is its own grant (`changes`, `tcp`), off by default, audited at open and
   close with bytes moved.

### Open questions

- **TCP header checks.** The TCP negotiation carries the database name, operation and version; in
  secured mode the client may also check the server id against the topology. Needs a spike
  against a real cluster before committing to step 4.
- **Failover** stays lost, as with HTTP today: one forwarder address stands for every node.
- **Latency.** Every call crosses the broker. In solo mode that is loopback; through a remote
  broker it is a network hop per request, fine for development, wrong for a production app.

## Not in scope

- Production deployments. A server app in Azure uses managed identity or the platform's secret
  store; Tiresias is for the machines people work on.
- Other databases. PostgreSQL would follow the SQL Server shape (`CREATE ROLE ... VALID UNTIL`),
  once someone needs it.

## Phases

1. **SQL login hand-out:** the `login` grant flag, `/login`, provider and `tir run` support,
   renewal. Guide: *SQL Server with per-lease logins*.
2. **RavenDB placeholder path and Changes:** path-carried placeholder, WebSocket relay.
3. **RavenDB TCP relay**, after the spike. Guide: *RavenDB through the broker*.
4. **Agent side:** SQL and RavenDB services in the desktop app's Services window and `tir`,
   schema discovery on `/sql`.
