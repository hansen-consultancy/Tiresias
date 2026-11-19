# Road to a public 0.1

Tiresias has to be easy to install, easy to understand and well documented, or nobody will trust
it with their credentials. This is the list that has to be done before the repository goes
public.

## Product

- [x] Desktop tray app hosting the agent, consent dialogs and the secrets editor
      ([design](desktop-app.md), [try it](testing-on-windows.md))
- [x] User-secrets agent side: pipe server, keys-only consent, sealing on first load, `tir secrets`
- [x] Local activity log and the app's activity window
- [ ] `tir activity`
- [x] Solo mode, with the broker hosted in the app ([design](desktop-app.md#solo-mode))
- [ ] Solo mode: local broker as a Windows service
- [ ] Step-up at the broker: minting, elevation and tokens need an approval only the vault can
      produce ([design](step-up.md), #23)
- [ ] Trust-chain links that add a key need a Windows Hello signature ([design](trust-links.md), #41)
- [ ] Seal user environment variables and hand them back per shell session ([design](environment-variables.md))
- [x] Databases for applications: SQL Server logins per lease, RavenDB through the broker ([design](databases.md))
- [ ] RavenDB subscriptions through the broker (the TCP relay, [phase 3](databases.md#phases))
- [ ] Guided setup: the strongest option first, findings with one-click fixes, and a "What do you
      need?" flow ([design](guided-setup.md), #32)
- [ ] Attack surface: installed software, extensions and global tools, ranked by what uses
      credentials ([design](attack-surface.md), #34)
- [x] Velopack installer and auto-update from GitHub Releases (`app-release.yml`)
- [ ] Signed with Azure Artifact Signing (the workflow is ready; it needs the Azure setup in
      [releasing.md](releasing.md))
- [ ] winget

## Identity

- [x] Logo: a closed eye whose lashes are key teeth (`assets/logo.svg`)
- [x] Small icon drawn for 16/32 px (`assets/icon-16.svg`)
- [x] Exports in `assets/export/` (regenerate with `python assets/export-icons.py`): NuGet icon, app and
      tray `.ico` files, social preview
- [ ] Upload `social-preview.png` in the repository settings
- [ ] Tray icon states: locked, unlocked, a consent waiting, an error

## Documentation

A documentation site on GitHub Pages, built with **MkDocs Material**: plain Markdown in `docs/`,
built-in search, versioning through `mike`, and no JavaScript toolchain to maintain. API reference
is not the priority; guides are.

| Section | Pages |
|---|---|
| **Getting started** | What Tiresias is (2 minutes) · Install · First unlock · Solo or with a broker |
| **Guides** | [Need no secret at all](avoid-secrets.md) · Protect `secrets.json` in an existing app · Seal environment variables · Give an AI agent API access without the key · `tir exec` with the GitHub CLI · SQL Server with per-lease logins · RavenDB through the broker · Set up a broker on a VPS · Enrol a second device · Lose a device, revoke it · Recover with the paper key · Teams and tenants · Known locations and alerts · Timestamped audit evidence |
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
