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

**Today.** Webhook, ntfy and LcdHub are built; the failing-sink finding is not (phase 6). A
program that serves the `LcdHub` pipe before the hub does takes the status items, and Tiresias
can't tell: `CurrentUserOnly` refuses only another user's pipe, and a check of the serving
program's name would stop the real hub (which runs from anywhere, under any name) sooner than a
squatter (which can take that name). The design gives `critical` its own rate-limit bucket, so a flood of findings
can't hide a decoy, collapses storms per source, and raises a finding and an `alerts.failing` alert
on the other sinks when one stops delivering. Killing the app also stops the decoy listener and the
consent gate, which the next unlock shows. A webhook can ask for a heartbeat
([design](../alerts.md#heartbeat)): an `alerts.alive` every 5 to 60 minutes, so a receiver that
expects it sees silence within about two intervals when the app is ended, its traffic is blocked
or the sink stops; a signed webhook ([design](../alerts.md#signed-webhooks)) also lets that receiver
refuse beats forged with a stolen header. The silence doesn't say why, and comes after every
restart until the first unlock.

**Closes it.** A receiver that notices silence, which the heartbeat now gives a webhook that opts
in: the attack is then seen, not prevented. Preventing it needs the Windows service
([desktop-app.md](../desktop-app.md)) running the sources and the sender outside the user's reach.
Without a heartbeat receiver this stays a stated limit.
