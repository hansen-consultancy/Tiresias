---
id: D-decoy-block
title: A trusted program led to a decoy endpoint is blocked
stride: Denial of service
likelihood: 2
impact: 2
status: accepted
issue: 39
control: Unblock from the finding on Home
---

**Threat.** Anything that can make a trusted program connect to a decoy port (a link it fetches, a
repository's config pointing at the decoy URL) gets that program blocked: `node.exe`, `git.exe` or
an editor then receives no lease, placeholder or consent dialog until the user unblocks it.

**Today.** The block raises a notification and a finding on Home naming the program and the decoy
it used, with **Unblock (that was me)** one click away ([decoys.md](../decoys.md)). There is no
lockdown, and nothing else is refused.

**Accepted because** blocking the program that used a decoy is the point of the layer, and the
cost of a wrong block is one click. Blocking an interpreter blocks every script it runs, which the
finding's path makes visible.
