# Road to a public 0.1

Tiresias has to be easy to install, easy to understand and well documented, or nobody will trust
it with their credentials. This is the list that has to be done before the repository goes
public.

## Product

- [ ] Desktop tray app hosting the agent, consent dialogs and the secrets editor
      ([design](desktop-app.md))
- [ ] User-secrets agent side: pipe server, keys-only consent, sealing on first load, `tir secrets`
- [ ] Local activity log, plus `tir activity` and the app's activity window
- [ ] Solo mode: local broker as a Windows service ([design](desktop-app.md#solo-mode))
- [ ] winget + Velopack installer, signed with Azure Trusted Signing

## Identity

- [x] Logo: a closed eye whose lashes are key teeth (`assets/logo.svg`)
- [x] Small icon drawn for 16/32 px (`assets/icon-16.svg`)
- [ ] PNG exports: NuGet icon (128 px), tray `.ico` (16/32/48), social preview
- [ ] Tray icon states: locked, unlocked, a consent waiting, an error
- [ ] NuGet package icon, and the GitHub social preview image

## Documentation

A documentation site on GitHub Pages, built with **MkDocs Material**: plain Markdown in `docs/`,
built-in search, versioning through `mike`, and no JavaScript toolchain to maintain. API reference
is not the priority; guides are.

| Section | Pages |
|---|---|
| **Getting started** | What Tiresias is (2 minutes) · Install · First unlock · Solo or with a broker |
| **Guides** | Protect `secrets.json` in an existing app · Give an AI agent API access without the key · `tir exec` with the GitHub CLI · SQL Server with per-lease logins · RavenDB through the broker · Set up a broker on a VPS · Enrol a second device · Lose a device, revoke it · Recover with the paper key · Teams and tenants · Known locations and alerts · Timestamped audit evidence |
| **Concepts** | Placeholders · Leases · Grants, ceilings and elevation · Consent · Trust chain · Control plane · Audit log and anchoring |
| **Reference** | CLI · Configuration (Keyring, broker, forwarder) · Broker endpoints · Control-plane protocol · File formats (vault, sealed `secrets.json`, trust links, audit records) |
| **Security** | Whitepaper (design, threat model, cryptography) · Honest limits · Reporting a vulnerability |

Every guide states its goal, its prerequisites, the exact steps (GUI and CLI), and how to check
that it worked. Every page of a guide is tested against a real install before the release that
ships it.

## Launch

- [ ] Review the import for names that must not be public
- [ ] Add the `DENYLIST` secret; set up nuget.org trusted publishing; enable private
      vulnerability reporting
- [ ] Make the repository public, tag `v0.1.0-preview.1`
