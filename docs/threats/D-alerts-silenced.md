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

**Today.** Not built. The design gives `critical` its own rate-limit bucket, so a flood of findings
can't hide a decoy, collapses storms per source, and raises a finding and an `alerts.failing` alert
on the other sinks when one stops delivering. Killing the app also stops the decoy listener and the
consent gate, which the next unlock shows.

**Closes it.** Only a receiver that notices silence: an opt-in heartbeat per sink (later phase),
and the Windows service ([desktop-app.md](../desktop-app.md)) running the sources and the sender
outside the user's reach. Until then this is a stated limit.
