---
id: E-lease-outlives-lock
title: A lease can outlive a lock or sleep when the agent misses the event
stride: Elevation of privilege
likelihood: 2
impact: 2
status: mitigated
control: ASVS V7 Session Management
---

**Threat.** Leases end when the workstation locks or sleeps, but only if `tir agent` (or the app) is
running and sees the event. Otherwise a lease stays usable on an unattended machine.

**Today.** The broker ends a lease once its heartbeat goes missing past the timeout, and at the hard
cap in every case.
