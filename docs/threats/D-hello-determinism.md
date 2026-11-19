---
id: D-hello-determinism
title: The vault can't be unwrapped if Hello signatures stop being deterministic
stride: Denial of service
likelihood: 1
impact: 3
status: open
control: Recovery key (paper key)
---

**Threat.** The wrap key is HKDF of a Hello RSA PKCS#1 v1.5 signature over a fixed challenge. If
Windows made those signatures randomised, unwrap would fail, closed.

**Today.** Nothing is exposed, and the recovery key can still open the vault.

**Closes it.** A command that re-wraps the vault from the recovery key.
