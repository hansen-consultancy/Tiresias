---
id: I-plaintext-lingers
title: A decrypted value lives briefly as a managed string in the broker
stride: Information disclosure
likelihood: 1
impact: 3
status: accepted
control: ASVS V14 Data Protection
---

**Threat.** While the broker builds an upstream request, the real credential exists as a managed
string that can't be zeroed, so a memory dump of the broker taken then holds it.

**Today.** The window is one request; the value never reaches logs, audit records or exceptions.

**Accepted because** the HTTP stack takes strings; zeroing would need a custom client.
