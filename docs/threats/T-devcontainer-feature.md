---
id: T-devcontainer-feature
title: A tampered tir-remote or devcontainer feature collects the tokens a devcontainer asks for
stride: Tampering
likelihood: 1
impact: 3
status: mitigated
issue: 113
control: ASVS V12 Secure Communication
---

**Threat.** The devcontainer feature ([design](../devcontainers.md)) downloads `tir-remote` into
every container that uses it and makes it git's credential helper, so whatever binary lands there
receives every token the user approves for that devcontainer. Someone who can change the download
on the way, swap a release asset, or publish their own feature under a name the user mistakes for
Tiresias's gets those tokens, and the ticket with them.

**Today.** Built in phase 6c (`devcontainer-features/src/tiresias`, `app-release.yml`):

- the feature is published only by `app-release.yml` from an `app-v*` tag, after the release it
  belongs to, and carries that release's SHA-256 list and version inside it; `install.sh`
  downloads over HTTPS from that release and installs nothing whose hash differs;
- releases here are immutable, so an asset can't be replaced after the feature pinned its hash;
- the helper answers only for HTTPS hosts mapped with `tir env git add`, which is sealed with the
  variables, so a repository's config can't point a token at another host.

**Closes it.** The residual is accepted: the GitHub account and ghcr.io namespace that publish
both are trusted, as they are for the app's own updates, and a user who adds someone else's
feature trusts its author.
