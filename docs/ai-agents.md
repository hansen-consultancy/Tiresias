# AI coding agents

**Status:** built: `tir ai` and `tir ai --snippet`.

An agent such as Claude Code, Codex or Copilot runs as you, so it can read every plain-text
secret you can. Tiresias gives it a better way: placeholders through `tir exec`, sealed variables
through `tir run`, and protected user secrets with no command at all, each after your consent. An
agent only uses that if it knows Tiresias is there.

## Tell every session once

```powershell
tir ai --snippet
```

prints a few lines to paste into your `CLAUDE.md`, `AGENTS.md` or the equivalent for your agent
(user-wide or per repository). They say Tiresias is installed, to run `tir ai` before a task needs
a credential, and never to read, print or ask for a secret value. Tiresias doesn't edit those files
for you.

## What the agent reads

`tir ai` prints the instructions themselves, from the installed `tir`, so they follow its version
and the snippet never needs changing:

- **Rules:** no secret values in output, files or chat; don't search `.env`, `secrets.json`,
  `NuGet.Config` and the like; say what it is about to request and why, and take a no as final;
  leave setup (`tir service add`, `tir env set`, `tir unlock`...) to you, and never start
  `tir agent`.
- **Looking first:** `tir status`, `tir service list`, `tir doctor` and `tir advise` need no
  prompt; `tir env list` and `tir secrets list` cost one Windows Hello prompt. None prints a value.
- **Using credentials:** `tir exec` and the variables it sets (`<SLUG>_TOKEN`, `<SLUG>_BASE_URL`,
  `<SLUG>_SQL_URL`, `GH_TOKEN`), `tir run --only`, and what needs no command (user secrets, NuGet).
- **When something is missing:** stop and tell you, with the command that would set it up.

Every command and flag the instructions name is checked against `tir`'s own usage by a test, and
every command in the usage against what `tir` dispatches, so a renamed command fails the build
rather than sending an agent to one that doesn't exist.
