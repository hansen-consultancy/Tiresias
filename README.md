<p align="center"><img src="assets/logo.svg" width="112" alt=""></p>

# Tiresias

**Let AI agents and tools use your credentials without ever seeing them.**

Tiresias is named for the blind seer of Greek myth, who knew what he could not see. It keeps your
API keys, database logins and certificates encrypted on disk and unlocks them for a working day
with Windows Hello. Agents and tools get *placeholders* instead of secrets. A broker swaps the
placeholder for the real credential on the way out, from an address your upstreams can allow-list.

> **Status: preview (0.x).** The formats are versioned, but they can still change before 1.0.
> Windows is the supported workstation. The broker and forwarder also run on Linux.

## What problem does it solve?

Developer machines are full of plaintext secrets: `secrets.json` files, `.env` files, CLI token
caches, environment variables. Anything running as you can read them, and AI agents and their
tools run as you. Tiresias moves those secrets behind three things:

- **Encryption at rest.** Secrets are sealed under keys that only open with a Windows Hello
  gesture. Nothing is stored in plaintext.
- **Use without seeing.** A tool gets a short-lived `tirph_…` placeholder. The broker swaps in
  the real credential, and only for the requests its grant allows: read-only unless you elevate,
  path rules, and an expiry.
- **Consent and audit.** You see what is asking (which process, which service, why) before a
  placeholder is minted. Every decision lands in a hash-linked audit log, optionally timestamped
  by an RFC 3161 authority.

## The pieces

| Piece | What it is |
|---|---|
| Tiresias app | The Windows tray app: unlock with Windows Hello, approve requests in a dialog, edit user secrets, see activity and status. In solo mode it also hosts the broker |
| `tir` (Keyring) | The CLI and agent on your workstation: vault, unlock, consent, `tir exec`, `tir doctor` |
| Broker | Holds the ciphertext. During a lease it injects credentials into HTTP, SQL Server and RavenDB traffic |
| Forwarder | A loopback relay on your workstation that tells the broker which local process is calling |
| `Tiresias.Extensions.Configuration` | A drop-in replacement for `AddUserSecrets`: your `secrets.json` is sealed in place, with no code change |
| `Tiresias.Core`, `Tiresias.Protocol` | The shared libraries: vault, trust chain, grants, leases, audit, wire formats |

## Protected user secrets, no code change

```xml
<PackageReference Include="Tiresias.Extensions.Configuration" Version="0.1.0-preview.2" />
```

Your existing `builder.Configuration.AddUserSecrets<Program>()` and
`WebApplication.CreateBuilder(args)` calls are rerouted at compile time by a C# interceptor. The
agent (the tray app, or `tir agent` in a terminal) answers on a per-user named pipe.

- **With the agent running:** the first load converts `secrets.json` into a sealed envelope that
  is still valid JSON. After that, a consent prompt shows the requesting executable and the
  secret *keys* (never values) before the app gets them.
- **While locked:** for a sealed file the app offers to unlock with Windows Hello, then asks as
  usual (`tir agent` refuses it with a message saying to unlock); a plaintext one is
  served unchanged and sealed on the first load after you unlock. "Allow for this session" lasts
  until you lock (or 12 hours).
- **Editing:** `tir secrets list | set <key> | remove <key>` in the project folder, or the app's
  editor. No command prints a value or writes the file back in clear.
- **Without the agent:** a colleague who doesn't use Tiresias keeps the stock plaintext
  behaviour, with no delay. A sealed file waits up to a minute for the agent (an app started at
  sign-in races the tray app starting with it), then fails loudly instead of silently loading
  nothing.

## Solo mode: no server needed

`tir solo init` sets Tiresias up on one PC with no VPS. The broker runs inside the agent (the tray
app, or `tir agent`) on `127.0.0.1:7780` and identifies the calling process from the loopback
connection, so no forwarder is needed. The trust chain has this one device, its genesis
co-signed by a key derived from the paper recovery key. Encryption at rest, Hello unlock,
leases, placeholders, consent and audit all work, offline too. What you give up: requests leave
from your own connection (no fixed IP to allow-list), and the secrets stay on the same machine
as your agents, with no protection from code running as admin. `tir doctor` lists these every
time. The broker shares the agent's process unless you run `tir solo service install` as
administrator, which moves it into a Windows service under its own account
(see [docs/broker-service.md](docs/broker-service.md)).

Services are added with one command, for example
`tir service add httpbin --upstream https://httpbin.org --allow '^/headers$'`, which asks for the
secret's value when the vault doesn't have it yet, then shows the change and asks you to approve
it with Windows Hello: the secret is then bound to that service's settings, and the broker refuses
it if anything else edits them. `tir service list` and `tir service remove` do the rest. The solo broker picks vault changes up at its next request, without a lock and
unlock.

## Alerts when you're away

The tray app can push serious events to your phone through [ntfy](https://ntfy.sh), post them
to a webhook of your choice, or show them on an [LcdHub](https://github.com/stevehansen/LcdHub)
screen beside the PC, so a used decoy reaches you when you aren't looking. In
**About**, **Alerts**, the first one you add asks for a name for this PC (it goes with every alert,
so pick one that says nothing more).

- **Add ntfy...** asks for the server (`https://ntfy.sh` or your own), the topic your phone's ntfy
  app subscribes to, and an optional access token. Use a long random topic name, and a token that
  can only write to it, so a stolen one can't read your alerts back. Each alert is a notification
  with the event as its title, its severity as the priority, and a line such as "Critical on desk,
  ×1. Open Tiresias."
- **Add a webhook...** asks for the URL (HTTPS, or plain HTTP to localhost) and an optional header
  such as `Authorization`. Each alert is one `tiresias.alert/v1` JSON POST: the event, its severity
  and time, and the PC's name.
- **Add LcdHub...** puts a line such as "Decoy credential used ×1" in the status strip of the LcdHub
  running on this PC, warnings and worse by default. It goes when Home shows your findings, or after
  24 hours. LcdHub shows nothing while the PC is locked and keeps the line for when you unlock; if
  LcdHub isn't running, the line waits for it. It never shows more than the event and how often.

Topics, tokens, URLs and headers are sealed like your secrets and saving needs Windows Hello;
muting or removing one doesn't. **Send a test alert** checks it arrives. One you mark trusted also
gets program paths and names (ntfy: the program's file name only); nothing ever gets a value or a
token. Alerts open at the first unlock after the app starts, then keep working while the session is
locked. What raises one: a decoy credential used (including one the admin service holds) or a decoy file read; a blocked program asking
again, a request refused in lockdown, "This wasn't me", and a program asking for a secret while
the PC is locked; the solo broker (in the app or the Windows service) rejecting the trust chain, a paper key used, the vault rolled back
or changed without your approval, and an unapproved broker request; and new findings the background
checks turn up that Home hasn't shown. A program asking while you're at the PC doesn't: you are at
the dialog (see [docs/alerts.md](docs/alerts.md)).

When alerts stop arriving somewhere, because the receiver refused them or nothing has gone through
for 15 minutes, Home shows "alerts to `phone` aren't arriving" with a button to the Alerts card, and
your other alerts get an "Alerts to a sink are failing" (naming the one failing only if trusted). The
finding goes once that sink delivers again (a test alert counts), or when you fix or remove it.

## AI coding agents

`tir ai --install` writes a few lines into `~/.claude/CLAUDE.md` (`--install <file>`: your agent's
`AGENTS.md`) that tell every agent session Tiresias is installed and to run `tir ai` before it
needs a credential. `tir ai` prints how: `tir exec` and `tir run`, what to look at first, and never
to read, print or ask for a secret value.
See [docs/ai-agents.md](docs/ai-agents.md).

## Trust model in one paragraph

Devices are enrolled into a per-tenant **trust chain**: hash-linked, signed links rooted in a
genesis hash you pin at setup, so a server relaying the chain cannot add a device, and every link
that adds trust needs a Windows Hello signature, so a program running as you cannot either. A **paper
recovery key** can repair the chain if every device is lost. Brokers verify the chain themselves,
and so does the Keyring before it hands the broker any key. A control plane (an optional HTTP
service) only relays chains, approves known locations and collects audit summaries. It is never
a root of trust.

## Install from source

There is no installer yet. On Windows 11, with Windows Hello set up and the .NET 11 SDK plus the
.NET 10 runtime installed:

```powershell
git clone https://github.com/hansen-consultancy/Tiresias.git
cd Tiresias
dotnet publish src/Tiresias.App -c Release -o "$env:LOCALAPPDATA\Programs\Tiresias\app"
dotnet publish src/Tiresias.Keyring -c Release -o "$env:LOCALAPPDATA\Programs\Tiresias\cli"
& "$env:LOCALAPPDATA\Programs\Tiresias\app\Tiresias.exe"
```

The first run sets up Windows Hello, your paper recovery key and solo mode. Add the `cli` folder
to your PATH for `tir`. [docs/testing-on-windows.md](docs/testing-on-windows.md) walks through
everything from there: a sample app's protected user secrets, the consent dialog, `tir exec`, and
activity.

## Building

```bash
dotnet build Tiresias.slnx
dotnet test src/Tiresias.Tests/Tiresias.Tests.csproj
```

You need the .NET 11 SDK, plus the .NET 10 runtime for the `net10.0` libraries. The app and the
Keyring build on Windows only; the tests run anywhere.

What changed in each release: [CHANGELOG.md](CHANGELOG.md). How releases are made and signed:
[docs/releasing.md](docs/releasing.md).

## License

MIT. See [LICENSE](LICENSE).
