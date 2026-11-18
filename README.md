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
time. The broker shares the agent's process for now; running it as a Windows service under its
own account is planned (see [docs/desktop-app.md](docs/desktop-app.md#solo-mode)).

Services are added with one command, for example
`tir service add httpbin --upstream https://httpbin.org --allow '^/headers$'`, which asks for the
secret's value when the vault doesn't have it yet. `tir service list` and `tir service remove`
do the rest. The solo broker picks vault changes up at its next request, without a lock and
unlock.

## Trust model in one paragraph

Devices are enrolled into a per-tenant **trust chain**: hash-linked, signed links rooted in a
genesis hash you pin at setup, so a server relaying the chain cannot add a device. A **paper
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
