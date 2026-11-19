---
id: R-observed-process
title: The process the forwarder reports to the broker is unsigned and can be wrong
stride: Repudiation
likelihood: 2
impact: 2
status: accepted
control: ASVS V16 Security Logging
---

**Threat.** The forwarder names the calling process in `X-Tiresias-Observed-Process`. Anything that
reaches the broker directly can set that header, and the port-to-PID lookup races with connection
teardown, so the audit record can name the wrong program.

**Today.** The broker records the header and never decides on it. The VPN stands between the
forwarder and the broker.

**Accepted because** the forwarder has no device key to sign with; the record is evidence, not
authorization.
