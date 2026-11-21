---
id: D-alerts-silenced
title: A program running as the user can stop alerts from leaving
stride: Denial of service
likelihood: 3
impact: 2
status: open
issue: 101
control: A receiver that expects a heartbeat
---

**Threat.** Alerts ([design](../alerts.md)) leave from the app, in the user's session. A program
running as the user can end the app, block its traffic with a per-user proxy setting, squat the
`LcdHub` pipe name, or flood low-severity events to drain the rate limits, and then trip a decoy
unseen.

**Today.** Webhook, ntfy and LcdHub are built, and so is the failing-sink check (phase 6): a sink
whose receiver refuses alerts, or that hasn't delivered for 15 minutes, is a finding on Home and an
`alerts.failing` alert on every other unmuted sink, whatever its threshold. That catches a blocked
or refused route while another route still works and the app still runs; it can't catch a block on
every route at once, a killed app, or a receiver that answers 2xx and drops the alert. A
program that serves the `LcdHub` pipe before the hub does takes the status items, and Tiresias
can't tell: `CurrentUserOnly` refuses only another user's pipe, and a check of the serving
program's name would stop the real hub (which runs from anywhere, under any name) sooner than a
squatter (which can take that name); LcdHub is never counted as failing, since a screen that
isn't running is normal. `critical` has its own rate-limit bucket, so a flood of findings can't hide
a decoy, and storms collapse per source. Killing the app also stops the decoy listener and the
consent gate, which the next unlock shows.

**Closes it.** Only a receiver that notices silence: an opt-in heartbeat per sink (phase 7, still to come),
and the Windows service ([desktop-app.md](../desktop-app.md)) running the sources and the sender
outside the user's reach. Until then this is a stated limit.
