# Out-of-band alerts

Status: **phases 1 to 6 built**, and from phase 7 signed webhooks and the heartbeat: webhook, ntfy and LcdHub end to end, every event in the table wired, failing sinks reported. Tracks issue #101. This page designs how Tiresias tells you about a
serious event when you aren't looking at the app: a push to your phone through
[ntfy](https://ntfy.sh), a line on a [LcdHub](https://github.com/stevehansen/LcdHub) screen beside
the machine, or a JSON POST to a webhook of your choice.

## The problem

A tripped decoy, a blocked program asking again, or a trust chain that failed verification shows
up today as a tray notification and a finding on Home. That only works while you sit at the
machine. You miss it when you are away, when the session is locked, or when Tiresias runs on a VM or
a remote box you rarely look at. Those are the moments an attacker picks.

## Decisions

- **One seam, three sinks.** ntfy, LcdHub and a generic webhook are sinks behind one pure planner.
  The planner decides what each sink gets. A sink only formats and delivers.
- **Every sink is public by default.** A public sink gets the event type, its severity, a count, the
  time and a machine label you chose. It never gets a secret name or value, a path, a program, a
  service, a user name or a host name. A sink you mark **trusted** also gets names and paths.
  **No sink ever gets a value**, a placeholder token, key material or a command line.
- **Anything that widens what leaves the machine needs Windows Hello.** Adding a sink, changing its
  address or headers, or marking it trusted is an edit to a sealed file. Narrowing (mute, raise a
  threshold, remove a sink) needs nothing.
- **Sink addresses and credentials live sealed, like the sealed environment.** The ntfy topic and
  token, the webhook URL and its headers are in `alerts.json`, sealed for Windows Hello and the
  recovery key as `environment.json` is. An ntfy topic on ntfy.sh, or a webhook URL with a key in
  its query, is as much a credential as the `Authorization` header.
- **Alerts keep working while the session is locked.** That is when they matter. The app opens
  `alerts.json` at unlock and keeps the sink definitions in memory until it exits. This is the one
  thing a lock does not forget (see *While locked*).
- **The payload is a wire format.** `tiresias.alert/v1`, versioned, in `Tiresias.Protocol`.
- **Alerts add to the app; they replace nothing.** The tray notification, the finding on Home and
  the activity record stay as they are.

## Events

Each alert has a fixed **event** (a dotted name), a **severity** (`info`, `warning`, `high`,
`critical`) and a **subject**: what the event is about, used only to dedupe and, on a trusted sink,
to explain. The title a sink shows comes from this table, never from the event's own text.

| Event | Severity | Title | Source today |
|---|---|---|---|
| `decoy.used` | critical | Decoy credential used | `AgentHost.DecoyTouched` ([decoys.md](decoys.md), layer 1) |
| `decoy.read` | critical | Decoy file read | The read tripwire (decoys.md layer 2, #97), for a program that isn't a routine opener |
| `trust.rejected` | critical | Trust chain rejected | Broker audit `TrustRejected` |
| `vault.rolled-back` | critical | Vault rolled back | Broker audit `secret-rolled-back` (#83) |
| `trust.break-glass` | high | Paper key used | Broker audit `BreakGlass` |
| `vault.unapproved` | high | Vault changed without approval | `SoloBroker` reload refused (`policy-changed`, [policy-integrity.md](policy-integrity.md)) |
| `approval.invalid` | high | Unapproved broker request | Broker audit `approval-invalid` ([step-up.md](step-up.md), #80) |
| `program.blocked` | high | Blocked program asked again | `ConsentPresenter`, gate `GateDecision.Blocked` |
| `lockdown.refused` | high | Request refused in lockdown | `ConsentPresenter`, gate `GateDecision.LockedDown` |
| `incident.reported` | high | "This wasn't me" | `App.NotMeAsync` |
| `consent.while-locked` | high | Secret requested while locked | A consent request that arrives while the Windows session is locked (new: `ConsentPresenter` and the app's session state) |
| `findings.new` | warning | New findings | `FindingWatch`: new open findings of status `Fail` ([attack-surface.md](attack-surface.md), [guided-setup.md](guided-setup.md)) |
| `findings.new` | info | New findings | The same, status `Warn` only |
| `alerts.failing` | warning | Alerts to a sink are failing | The delivery loop below, sent to the other sinks |
| `alerts.suppressed` | warning | Alerts held back | The rate limit below: how many it held back while a bucket was empty |
| `alerts.test` | info | Test alert | **Send a test alert** in the app |
| `alerts.alive` | info | Tiresias is running | The heartbeat below, to the webhooks that asked for one |

Broker audit events come from the broker in the app (solo mode) as it writes them. A remote
broker's own events are the broker's business, not this page's (see *Not in scope*).

`consent.asked` from a program you never allowed is deliberately **not** an alert: you are at the
dialog, and an alert for each one would teach you to ignore alerts. It becomes
`consent.while-locked` when nobody can be at the dialog.

## Design twice

| | **A. Smart sinks** | **B. Pure planner, thin transports (chosen)** |
|---|---|---|
| Interface | `IAlertSink.SendAsync(Alert alert)`: each sink gets the whole event and decides what to keep, how to dedupe and when to retry | `AlertPlanner.Plan(event, sinks, state, now)` returns deliveries of an already-redacted `AlertPayload`. `IAlertTransport.DeliverAsync(AlertPayload, SinkDefinition, ct)` only formats and sends |
| Where redaction happens | In every sink, once per sink | Once, in the planner, before any transport sees the event |
| A new sink | Must re-implement redaction, dedupe and rate limits, and can get any of them wrong | Writes a formatter and a sender. It cannot see what the payload doesn't carry |
| Proving no secret leaves | A test per sink, and the next sink's author must remember to write one | One canary test over the planner, plus one per formatter over a payload that can only hold allowed fields |
| Matches the repo | Decisions spread into I/O | "Decisions are pure, I/O stays at the edges", like grants and doctor checks |
| Cost | Fewer types | A planner state (dedupe windows, buckets) the app keeps between calls |

B wins. Redaction is the property that matters most, and B makes it a type that a sink cannot
widen. A's only gain is fewer types.

## Shape

### The planner

```csharp
// Tiresias.Core/Alerts: pure, clock injected, no I/O.
public sealed record AlertEvent(AlertKind Kind, AlertSubject Subject, DateTimeOffset At);
public sealed record AlertPlan(IReadOnlyList<Delivery> Now, AlertState Next);
public sealed record AlertSetup(string Machine, byte[] InstallKey, IReadOnlyList<SinkDefinition> Sinks);
public static AlertPlan Plan(AlertEvent e, AlertSetup setup, AlertState state, DateTimeOffset now);
public static AlertPlan Tick(AlertSetup setup, AlertState state, DateTimeOffset now); // window summaries
```

`AlertKind` is the table above: event name, severity and title in one place. `AlertSubject` holds
what the source knows (program path, process id, decoy kind, service, secret or variable names,
finding keys) and is never serialized. The planner turns it into a `TrustedDetail` only for trusted
sinks, and into a dedupe key for all of them.

Per sink, in order: drop below the sink's threshold, dedupe, rate-limit, redact, emit a `Delivery`.

### The payload

`tiresias.alert/v1`, the webhook's body as is, and what the other sinks format from:

```json
{
  "schema": "tiresias.alert/v1",
  "id": "01JD2K8Q4X9V7M3N5P6R8S0T2W",
  "event": "decoy.used",
  "severity": "critical",
  "title": "Decoy credential used",
  "machine": "workstation",
  "at": "2026-11-21T10:15:00Z",
  "count": 1,
  "key": "decoy.used:5e1f0c9a2b7d4e86",
  "detail": {
    "program": "C:\\Users\\alice\\AppData\\Local\\Temp\\x.exe",
    "processId": 4242,
    "what": "the decoy admin token"
  }
}
```

| Field | Meaning |
|---|---|
| `schema` | The format and its version. A change bumps it; a receiver refuses a version it doesn't know |
| `id` | A ULID per delivery, also sent as `Idempotency-Key` so a receiver can drop a retry |
| `event`, `severity`, `title` | From the events table. `title` is never built from the event's data |
| `machine` | The label you typed when you added the first sink: required, never the host name |
| `at` | When the first occurrence happened, UTC |
| `count` | Occurrences this delivery stands for (see *Dedupe*) |
| `key` | `event:` plus the first 16 hex of HMAC-SHA-256 over the subject, keyed by a random per-install key. Stable for one subject on one machine, so a receiver can group repeats; useless for guessing the subject, even a guessable path |
| `detail` | **Trusted sinks only**: absent on a public one, not empty. Program path, process id, the processes that started it, decoy kind, service, secret or variable names, finding titles. Never a value, a token, a command line or key material |

`AlertPayload` and `TrustedDetail` are records with exactly these fields. There is no free-text
field and no dictionary: a field that isn't in the record can't leave.

### Sinks

`alerts.json` (sealed, `tiresias:alerts`) holds one document:

```json
{ "v": 1, "machine": "workstation", "sinks": [
  { "id": "phone", "kind": "ntfy", "url": "https://ntfy.sh/<topic>", "token": "tk_…",
    "threshold": "high", "redaction": "public" },
  { "id": "desk", "kind": "lcdhub", "threshold": "warning", "redaction": "public" },
  { "id": "siem", "kind": "webhook", "url": "https://hooks.example.com/tiresias",
    "headers": { "Authorization": "Bearer …" }, "threshold": "high", "redaction": "trusted" } ] }
```

Default thresholds: ntfy and webhook `high`, LcdHub `warning`. Mutes and raised thresholds live in
`app.json`, since they only narrow.

| | ntfy | LcdHub | Webhook |
|---|---|---|---|
| Transport | HTTPS `POST` to the topic URL (any ntfy server) | Named pipe `LcdHub`, `CurrentUserOnly`, binary wire v4 | HTTPS `POST`, `application/json` |
| Credential | `Authorization: Bearer <token>`, optional | None: the pipe is per user | The headers you set, e.g. `Authorization` |
| Severity | ntfy `Priority` 2/3/4/5 for info/warning/high/critical | Status level `Info` / `Warn` / `Bad` (high and critical) | `severity` field |
| What shows | `Title` header: the title; body: "<severity> on <machine>, ×<count>. Open Tiresias." `Tags` from the severity. Trusted adds the program's file name to the body | A status-strip item: key `tiresias:<event>`, text "<title> ×<count>", lifetime 24 hours | The payload |
| Cleared | Never | When Home shows the findings (`FindingWatch.Shown`), or when the lifetime ends | Never |

Rules for every HTTP sink: HTTPS only (plain HTTP to loopback is allowed, for a local relay); no
redirects followed, so headers never reach another host; a 10-second timeout; the system proxy.
Header names must be RFC 9110 tokens, values may not hold CR or LF, and `Host`, `Content-Length`,
`Content-Type` and `Idempotency-Key` can't be set.

ntfy is the first choice for a phone. Use an access token that can only **write** to the topic, so
a stolen token can't read your alerts back, and a long random topic name.

LcdHub shows nothing while the session is locked, by its own design, and keeps the status item
until you unlock, so it is the "while you were away" view. A rendered alert frame that takes over
the panel for `critical` is a later phase: the protocol's alerts are pictures, not text.

### Dedupe and rate limits

All in the planner's state, per sink:

- **Dedupe.** The same `key` within 10 minutes is one alert: the first is sent at once, repeats
  only count. When the window closes with repeats, one more delivery says `count: N`.
- **Rate limit.** A token bucket of 10 per hour, burst 5. `critical` has its own bucket of 30 per
  hour, so a flood of findings can't hide a decoy. When a bucket is empty, alerts are counted, and
  one `alerts.suppressed` summary goes out when it refills.
- **Storm.** More than 100 events in a minute from one source turns that source into one alert
  per window. The activity log still has every one.

### Delivery

- An in-memory queue per sink, drained by one worker. Retries back off 30 s, 1, 2, 4… minutes up
  to 30 minutes, and an alert is dropped after 24 hours.
- `429` and `503` wait for `Retry-After`. Any other `4xx` stops the sink: its definition is wrong,
  and retrying would only repeat the refusal.
- A sink that has failed for 15 minutes, or stopped, is a finding on Home ("Alerts to `phone`
  aren't arriving") and an `alerts.failing` alert to the other sinks. Delivery errors are logged
  with the sink id, status code and exception type, never the URL, a header or the body.
- The queue holds only redacted payloads. It is not written to disk in v1: alerts lost when the app
  exits are still in the activity log.

### Heartbeat

A sink can't tell a quiet machine from a dead app ([D-alerts-silenced](threats/D-alerts-silenced.md)).
A webhook can ask for a heartbeat: an `alerts.alive` every N minutes, which a receiver that expects
it (a dead man's switch, a cron monitor) turns into "nothing heard from `workstation`".

- **Opt-in per webhook, off by default.** `"heartbeatMinutes": 15` on the sink in `alerts.json`,
  5 to 60 whole minutes; the form offers off, 5, 15, 30 and 60. Turning it on sends something new,
  so it is a sealed save, behind Hello like the rest of the definition.
- **Webhooks only.** On ntfy a heartbeat would be a push to your phone every interval, and ntfy
  can't notice silence; LcdHub is a screen beside the machine, which has nobody to tell.
- **What leaves: the machine label and the time.** An ordinary `tiresias.alert/v1` with `event`
  `alerts.alive`, `severity` `info`, `title` "Tiresias is running", `count` 1, `at` the send time
  and a `key` fixed per install. Never `detail`, on a trusted sink too. It widens nothing: a public
  sink already gets the label and times with every alert.
- **The schedule.** `AlertPlanner.Tick` sends the first at once (the app ticks right after unlock)
  and the next once the interval has passed since the last, outside threshold, dedupe and rate
  limits. A muted or removed sink gets none; unmuting sends one at once. The app ticks every minute,
  so beats are N to N+1 minutes apart.
- **Delivery.** Through the sink's queue like any alert, so a sink stopped by a 4xx stops beating
  too, which is the point. A newer heartbeat replaces one still waiting, so a receiver back from an
  outage gets one, not a backlog.
- **What a receiver should expect.** One beat per interval, plus up to a minute's jitter and the
  retry backoff. Alarm after about two intervals of silence. Expect silence after a restart until
  the first unlock (see *Settled*), and when the app or the session ends: the receiver can't tell
  those from an attack, and shouldn't try.

### Signed webhooks

A webhook's own `Authorization` header says who may post. A signature also proves the body came
from this machine and wasn't replayed.

- **Scheme: [Standard Webhooks](https://www.standardwebhooks.com/)**, so a receiver checks it with an
  off-the-shelf library instead of code written for Tiresias. Three headers on every request:
  `webhook-id` (the payload's `id`, also the `Idempotency-Key`), `webhook-timestamp` (Unix seconds,
  the attempt's own time) and `webhook-signature: v1,<base64 HMAC-SHA-256 over
  "<id>.<timestamp>.<body>">`, over exactly the bytes sent.
- **The key.** A `whsec_` secret (base64 of 24 to 64 bytes) per webhook: pasted from the receiver,
  or made by **New secret** in the form (32 random bytes) and copied to the receiver. It is
  `"signing"` on the sink in sealed `alerts.json`, so adding or changing it needs Hello, and it never
  leaves the machine: only the HMAC does. The form is kept out of screen capture, like the header,
  and a sink prints as its kind and id only, so no log line or exception can show the key.
- **Replay.** The receiver refuses a timestamp more than 5 minutes from its own clock (the spec's
  tolerance) and remembers `webhook-id`s inside that window. Each retry signs again with its own
  time and the same id, so a late retry still verifies and a replayed one doesn't.
- **Headers.** `webhook-id`, `webhook-timestamp` and `webhook-signature` are reserved, so a user
  header can't fake or override a signature. Without a secret, none is sent.
- **What leaves.** Nothing new: the id and a time are in the body already.

### While locked

Locking ends the lease and forgets every consent, but not the sink definitions the app opened at
unlock. Without them, alerts would stop exactly when you are away. What stays in memory can post to
your ntfy topic or webhook, nothing more, and anything that reads the app's memory already reads
much more (desktop-app.md).

The sources keep running while locked: the decoy listener, the consent gate and the broker in the
app. `consent.while-locked` exists because of that.

After the app starts, nothing is sent until the first unlock opens `alerts.json`. Events in that gap
wait in the queue and go out after it (see *Settled*).

## Tests

- **Planner** (`AlertPlannerTests`): threshold per sink; dedupe window and the `count` summary;
  each bucket, the critical bucket under a flood, and the suppressed summary; storm collapse; a
  muted sink gets nothing.
- **Canary**: every string the planner can see (program path, process chain, service, secret and
  variable names, decoy kind, finding titles, a secret value and a placeholder token handed in
  beside them) is a unique `CANARY-<n>`. Each event kind goes through the planner and every
  transport's formatter (ntfy request line, headers and body; webhook body and headers; LcdHub
  wire bytes) into captured bytes. For a public sink, no canary appears. For a trusted sink, the
  name and path canaries may appear in `detail` only, and the value and token canaries never.
- **Shape pins**: `AlertPayload` and `TrustedDetail` property lists are pinned by reflection, so a new
  field fails a test until someone decides it may leave. A golden `tiresias.alert/v1` document pins
  the JSON.
- **Credentials**: the sink's token and headers appear only in the request's headers, never in the
  body, a log line (captured `AppLog`) or an exception message from a failing fake handler.
- **Transports**: a fake `HttpMessageHandler` and a fake pipe. No redirect is followed; a `4xx`
  stops the sink; `Retry-After` is honoured; CR/LF and reserved header names are refused.
- **Sealed config**: `alerts.json` round-trips through `UserSecretsVault`; a widening edit needs the
  Hello wrapper, a mute doesn't.

## Threats

[I-101](threats/I-101.md): alerts carry facts about the machine to services outside it.
[D-alerts-silenced](threats/D-alerts-silenced.md): a program running as you can stop alerts from
leaving.

## Not in scope

- **A remote broker's alerts.** A broker on a VPS sees trust and approval failures for every
  device. Alerting from there is a broker feature with its own config.
- **Other sinks** (email, Teams, Slack). Each is a formatter over the same payload; Slack and Teams
  webhooks already take a JSON POST.

## Settled

- **Alerts before the first unlock: the gap stays.** After a reboot, nothing goes out until you
  unlock once. A DPAPI-protected copy of `alerts.json` would close that gap, but would put the sink
  credentials where any program running as you can read them without Hello.
- **The machine label is required.** Adding the first sink asks for it, and the form doesn't save
  without one. It is never filled in from the host name.

## Phases

1. **Core and Protocol, pure. Done.** `AlertKind`, `AlertEvent`, `AlertPlanner` (threshold, dedupe,
   buckets, storms, redaction), `AlertPayload` v1 and its JSON. Planner, canary and shape tests.
   Nothing sends. What it settled that the design left open, or changed:
   - `Plan` and `Tick` take an `AlertSetup` (sinks, the machine label, a per-install key) instead
     of the sink list alone: the payload needs the label, and `key` and `id` need the key.
   - `id` is 48 bits of milliseconds and 80 bits of an HMAC over a sequence number in the state,
     not a random number, so the planner stays pure. Still unique per install and unguessable.
   - The critical bucket's burst is 10. `alerts.suppressed` ignores the sink's threshold (it is
     about that sink's own deliveries) and counts occurrences, so a held-back `count: N` summary
     adds N, and every event ends up in some delivery's `count`.
   - A storm's source is the event name, per sink. It ends after a minute with 100 or fewer.
     Its window has no `detail`: it stands for many subjects.
   - `TrustedDetail` is `program`, `processId`, `parents`, `what`, `service`, `names`, `findings`.
   - The canary covers the planner and the payload's JSON. The value and placeholder-token
     canaries and the per-formatter canaries come with the first source mapping and formatter
     (phases 2 to 5): `AlertSubject` has no field that can hold a value, and no formatter exists yet.
2. **Webhook end to end. Done.** Sealed `alerts.json` (`AlertsConfig`, `AlertsFile`, `AlertsStore`),
   the transport and the delivery worker (`WebhookTransport`, `AlertSender`, `DeliveryPolicy`),
   `AlertCenter` tying the planner to the worker, an **Alerts** card to add a webhook behind Hello
   (asking for the required machine label first), **Send a test alert**, and `decoy.used` wired.
   README, CHANGELOG, I-101 to `mitigated`. What it settled or changed:
   - **Settings is About.** The app has no separate Settings page; its settings (start with Windows,
     the admin tier) are cards on **About**, so **Alerts** is one too. Adding opens a dialog, kept out
     of screen capture.
   - **Sink ids are the user's**: 1 to 32 of `a-z`, `0-9`, `-`, such as `siem`. Logs and (phase 6)
     findings name them; they never leave the machine, except as a trusted sink's `detail.what` in
     `alerts.failing` (phase 6).
   - **The form takes one header.** `alerts.json` holds any number; a second one waits for a need.
   - **Narrowing in `app.json`** is `SinkNarrowing`: muted, a raised threshold (a lower one is
     ignored), removed. The card mutes and removes; a mute also drops what waits for that sink, so unmuting replays nothing; a raised threshold has no control yet. A removal
     stops the sink at once and leaves `alerts.json` at once if unlocked, else at the next unlock,
     since sealing needs the Hello wrapper.
   - **`alerts.json` refuses plain keys beside its seal** instead of merging them as a
     `secrets.json` does, and a plain (never sealed) file: anything that could add a sink goes through
     a sealed save. A file that doesn't open turns alerts off, logged, and doesn't fail the unlock.
     The recovery restore gives `alerts.json` back to a new Hello key with everything else sealed.
   - **`Retry-After`** sets the earliest retry, but never sooner than the backoff, so `Retry-After: 0`
     can't make the worker spin. A **3xx** stops the sink like a 4xx: it isn't followed, and the
     definition is what needs fixing. A sink restarts when its URL or headers change, or when a test
     alert gets through.
   - **Send a test alert** goes to one sink, now, outside dedupe and rate limits (a second test after
     fixing the receiver mustn't be deduped away), built by the planner with its redaction. One
     attempt, no retry; the card shows the status code or the exception type.
   - The canary now runs through the first source mapping (`AlertSources.DecoyUsed`) and the webhook
     formatter into captured request bytes, with a value and a placeholder token beside the event.
3. **ntfy. Done.** `NtfyFormat`, and an **Add ntfy...** form on the Alerts card (server, topic,
   optional token, with hints to use a write-only token and a long random topic), sealed like the
   webhook. What it settled or changed:
   - **One HTTP transport.** `WebhookTransport` became `HttpAlertTransport`, which checks a sink and
     hands it to its kind's formatter; `WebhookRules` became `SinkRules`. A sink is an `AlertSink`
     record (`WebhookSink`, `NtfySink`) whose `ToString` is sealed to its kind and id, so no kind can
     print its address or token.
   - **The form takes the server and the topic apart** (the server prefilled with `https://ntfy.sh`);
     `alerts.json` keeps the joined topic URL as `url`, beside `token` when there is one. A server may
     sit under a path, but has no query or fragment. A topic follows ntfy's own rule, 1 to 64 of
     `A-Z`, `a-z`, `0-9`, `-`, `_`; a token is 1 to 256 visible ASCII characters. Both are checked
     again before every send.
   - **Priority** is 2/3/4/5 as designed; 1 (min) is never used, so an alert always shows. **Tags**
     are emoji names: `information_source`, `large_orange_diamond`, `warning`, `rotating_light`
     for info to critical.
   - **The body** is "Critical on desk, ×1. Open Tiresias.", in English (it leaves the machine; it
     isn't the app's UI). A trusted sink adds the program's file name in brackets and nothing else
     from `detail`: never the folder, which can name the user, nor the parents, names or decoy kind.
   - **`Title` is the event table's title as is**; a test pins every title to printable ASCII, so it
     fits a header without encoding. `Content-Type` is `text/plain; charset=utf-8`.
   - The canary runs through the decoy mapping, the planner and the ntfy formatter into the captured
     request line, headers and body: no name canary on a public sink, only the program's file name on
     a trusted one, never a value, a placeholder or the folder; the token once, in `Authorization`.
4. **LcdHub. Done.** `LcdHubLink` (the pipe client, wire v4 status items), `LcdHubFormat`, an
   **Add LcdHub...** form on the Alerts card, and clearing from `FindingWatch.Shown`. What it settled
   or changed:
   - **The link stays connected while it has something to show, and only then.** LcdHub drops a
     producer's status items when it disconnects, so a one-shot send would vanish at once. The link
     connects when an item arrives, sends every item again after the hub restarts or starts late
     (with what is left of its lifetime), and disconnects when nothing is left, so Tiresias isn't in
     the hub's producer list (as `Tiresias`) while idle. It writes only Hello and Status and skips
     whatever the hub sends.
   - **No hub is not a failure.** LcdHub deliveries don't go through `AlertSender`'s queue and retries:
     an item waits in the link, retried every 5 seconds, until a hub appears or its 24 hours end.
     A screen that isn't running is normal, so phase 6 won't count it as a failing sink.
   - **One item per event, counting up.** The key is `tiresias:<event>`, so a second subject of the
     same event updates the line instead of adding one. The count adds every delivery since the item
     was last cleared (a dedupe summary's `count` holds only the repeats), the level is the worst
     seen, and each update renews the 24 hours.
   - **Never `detail`, trusted or not.** The text is the title and count only, so the form has no
     trusted choice: the screen faces whoever stands at the desk.
   - **Clearing takes every Tiresias item off**, not just findings: Home showing the findings means
     you are back at the machine, which is what the "while you were away" view waits for. Removing
     the sink clears it too. Muting stops new items and leaves what is shown to its lifetime.
   - **One LcdHub sink per machine**, default id `desk`, default threshold `warning`. In `alerts.json`
     it is `{"id", "kind": "lcdhub", "threshold", "redaction"}`, with no address or credential.
   - **Send a test alert** shows "Test alert ×1" for one minute, not 24 hours, and reports whether a
     hub took it within 3 seconds; if none did, it still shows should one start within the minute.
   - **Pipe squatting is not checked beyond `CurrentUserOnly`**, which already refuses a pipe served
     by another user. The serving process could be compared to `LcdHub.exe`, but anything running as
     you can take that name, and the hub can sit anywhere under any name, so the check would refuse
     a real hub before it stopped a squatter. What a squatter learns is what the screen shows anyone:
     event titles and counts (I-101, D-alerts-silenced).
   - A demo (`--demo`) leaves the real LcdHub alone.
   - The canary runs through the decoy mapping, the planner and the link into the bytes a fake hub
     received, for a public and a trusted sink: no canary, no user name, no machine label.
5. **The other events. Done.** Every source in the events table but `alerts.*` is wired, each a thin
   mapping in `AlertSources` (Core) or `AlertTriggers` (the app's `Logic/`). What it settled or changed:
   - **`decoy.read`** comes from the read tripwire (#97) through the same `DecoyTouched` as
     `decoy.used`, but only for a program that isn't a routine opener (an indexer, an antivirus): the
     same programs the app notifies of. Otherwise every scan would be a critical alert.
   - **Consent alerts are decided at the gate**, when a request's turn comes: `Blocked` is
     `program.blocked`, `LockedDown` is `lockdown.refused`, and a request the gate lets through while
     the Windows session is locked is `consent.while-locked`. One request raises one alert at most. A
     request asked with someone at the machine raises none.
   - **"The session is locked"** means locked, logged off or disconnected (locally or over Remote
     Desktop) since the last session switch, until it is unlocked, logged on or connected again. The
     app assumes unlocked when it starts.
   - **Consent and incident subjects** carry the program, its process id, the processes that started
     it, and the secret or variable names asked for. A `tir` placeholder or `tir exec` approval
     carries no names: its lines are `tir`'s own text, which can hold a command. The request's heading
     and command line never go.
   - **Broker events come from the solo broker's audit log**: as it writes it (`AuditLog.Appended`)
     when the app hosts the broker, or from the Windows service's journal, read every 30 seconds while
     the service runs (`AuditTail`). The journal's first read after the app starts only sets where to
     begin, as does one that no longer extends the last (replaced, shrunk, or a chain that doesn't
     verify): records the app didn't see written never alert late. `trust.rejected` carries the verifier's failure kind (`Fork`,
     `Rollback`...), `trust.break-glass` nothing, `vault.rolled-back` and `vault.unapproved` the
     secret's name (`policy-not-approved: <slug>` is the refused reload's record), `approval.invalid`
     the service and the calling process. The record's free-text reason never goes whole. A reload
     that refuses several secrets writes a record, and so an alert, per secret.
   - **The admin tier's decoy incidents** (decoys the admin service holds) raise `decoy.used` as the
     app receives them, with the program, its process chain and the decoy kind, as a decoy the app
     holds does. After a restart, incidents not yet reviewed in Activity alert once more.
   - **`findings.new` is one event per background check run**, naming each new finding by its title,
     never its detail: a warning when any of them fails, info when they only warn. New means open, not
     shown on Home (`seen-findings.json`) and not alerted on before by this run of the app; a finding
     that goes away and comes back alerts again. After a restart, findings still unshown alert once
     more. Home running the checks itself raises nothing: you are looking at them.
   - The canary runs every source's event, built from inputs with a value and a placeholder token
     beside the names, through the planner into the webhook's, ntfy's and a fake LcdHub's captured
     bytes, public and trusted.
6. **Failing sinks. Done.** `SinkHealth` (pure), tracked per sink by `AlertSender`; `AlertCenter`
   raises `alerts.failing` and keeps `Failing`, which Home's doctor run (`Doctor.FailingAlerts`) turns
   into a finding with an **Open Alerts** button. D-alerts-silenced updated. What it settled or changed:
   - **Failing** is a stop (a non-429/503 4xx, a 3xx, a sink that fails its rules), at once, or no
     delivery for 15 minutes since the first failed attempt, checked on the minute tick. A delivery
     clears it, and so does a test alert that gets through, a changed URL or header, or removing the
     sink. A **muted** sink is no finding: muting takes it out of the sender, backlog and all. LcdHub never counts, as phase 4 said.
   - **`alerts.failing` ignores the other sinks' thresholds**, as `alerts.suppressed` does: ntfy and
     webhook default to `high`, so with the threshold applied the warning would reach only LcdHub.
     Mutes still apply. One per sink each time it starts failing, deduped by the planner as usual.
   - **The planner skips the sink an event is about** (`AlertSubject.Sink`), so the rule is pure and
     tested there. A trusted sink gets the id as `detail.what`; a public sink gets the event alone; the
     ntfy body and LcdHub line never show it. `Sink` is hashed into `key` only when set, so every
     other subject's key is unchanged.
   - **The finding** is one per sink, `Fail`, of kind "alert sinks that aren't delivering", its
     dismissal bound to stopped or failing, so a stop after a dismissed failure shows again. It names
     the sink by id only. `tir doctor` never shows it: the CLI sends no alerts. Home rechecks, and the
     tray badge updates, when the failing set changes.
   - The state lives in memory: after the app restarts, a sink counts as failing again only once it
     fails again.
   - The canary runs a failing webhook and ntfy sink with canary URL, header and token beside a public
     and a trusted webhook and ntfy: none of them appears in another sink's request, the log or the
     finding; the id only in a trusted webhook's `detail`.
7. **Later.** Signed webhooks and the heartbeat **done** (*Heartbeat*, *Signed webhooks* above);
   an LcdHub alert frame for `critical` follows in its own PR. What it settled or changed:
   - **Signing is Standard Webhooks**, not a scheme of Tiresias's own: the HMAC-SHA-256 over
     timestamp and body the design sketched, with header names and a secret format receivers'
     libraries already check. The id in the signature is the payload's.
   - **The heartbeat is for webhooks only**, 5 to 60 minutes, off by default, and is a payload of
     the existing schema rather than a new one, so a receiver needs no second parser.
   - The form only adds sinks: to sign or beat on an existing webhook, remove it and add it again.

Each phase merges on its own, and only phase 2 onwards is user-facing.
