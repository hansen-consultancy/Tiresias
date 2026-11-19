---
id: I-same-user
title: Malware already running as the user can read what that user's processes hold
stride: Information disclosure
likelihood: 3
impact: 3
status: accepted
control: ASVS V14 Data Protection
---

**Threat.** A program running as the user can read the memory of the user's other processes: a
terminal's environment after `tir run`, an application's configuration after it loaded sealed user
secrets, and the agent while the solo broker runs inside the app.

**Today.** Sealing protects against reading the registry, files and new processes, and consent
stops silent use through Tiresias. Placeholders keep the real value out of the process where a tool
allows it.

**Accepted because** no user-mode design can stop a process reading a sibling of the same account.
Moving the broker into the Windows service under its own account narrows it.
