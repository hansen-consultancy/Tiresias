---
id: S-devcontainer-ask
title: A container or program poses as a devcontainer to get sealed variables and git credentials
stride: Spoofing
likelihood: 2
impact: 3
status: open
issue: 113
control: ASVS V7 Session Management
---

**Threat.** Devcontainers that ask ([design](../devcontainers.md)) add an endpoint in the agent
that any container on the machine reaches through Docker Desktop's `host.docker.internal` relay,
and every relayed connection comes from Docker Desktop's backend process. Only the ticket in the
request says which devcontainer asks. A malicious image, package or VS Code extension in any
container, or a program running as the user, tries to: ask without a ticket, guess one, take one
from a devcontainer's environment, keep using one after the user locks, or get consent for a
folder the user didn't open.

**Today.** Not built; the design holds it back this way:

- the endpoint listens on loopback only, like every other Tiresias listener, and refuses a missing,
  unknown or ended ticket before reading the request body; tickets are 256 random bits, held in
  the agent's memory only, never logged;
- a ticket is minted only for a folder whose `devcontainer.json` asks for one, after a consent
  dialog naming that folder, and it ends at lock or after 10 hours;
- a ticket opens nothing by itself: every variable or git credential goes through consent naming
  the devcontainer's folder, with **Allow once** the default and allowances ending with the ticket.

**Closes it.** Mitigated when phase 6b ships with the endpoint and ticket tests. The residual is
accepted: anything inside the devcontainer can read its ticket, and consent can't tell a tool from
a malicious package next to it, as [I-same-user](I-same-user.md) accepts for the host.
