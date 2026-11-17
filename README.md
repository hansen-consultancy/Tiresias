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
library side is done. The agent's side (consent prompt, sealing on first load, `tir secrets`) is
still being built.

- **With the agent running:** the first load converts `secrets.json` into a sealed envelope that
  is still valid JSON. After that, a consent prompt shows the requesting executable and the
  secret *keys* (never values) before the app gets them.
- **Without the agent:** a colleague who doesn't use Tiresias keeps the stock plaintext
  behaviour. A sealed file fails loudly instead of silently loading nothing.

## Trust model in one paragraph

Devices are enrolled into a per-tenant **trust chain**: hash-linked, signed links rooted in a
genesis hash you pin at setup, so a server relaying the chain cannot add a device. A **paper
recovery key** can repair the chain if every device is lost. Brokers verify the chain themselves,
and so does the Keyring before it hands the broker any key. A control plane (an optional HTTP
service) only relays chains, approves known locations and collects audit summaries. It is never
a root of trust.

## Building

```bash
dotnet build Tiresias.slnx
dotnet test src/Tiresias.Tests/Tiresias.Tests.csproj
```

You need the .NET 11 SDK, plus the .NET 10 runtime for the `net10.0` libraries. The Keyring
builds on Windows only.

## License

MIT. See [LICENSE](LICENSE).
