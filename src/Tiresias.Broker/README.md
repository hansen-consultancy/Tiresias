# Tiresias

Design: see the repository's design document.

| Piece | Runs | Holds |
|---|---|---|
| `Tiresias.Broker` | the broker host, VPN interface only (NetBird in the reference setup), `:7780` | vault ciphertext, its Ed25519 identity, and, during a lease only, DEKs in RAM |
| `tir` (`Tiresias.Keyring`) | the admin's workstation, as the admin | the Windows Hello credential (TPM), a DPAPI-protected Ed25519 device key, the broker pin |
| `Tiresias.Forwarder` | the workstation, `127.0.0.1:7781` | nothing secret: it relays `/svc/**` to the broker and adds `X-Tiresias-Observed-Process` |

`tir` keeps its state in `%LOCALAPPDATA%\Tiresias` (`broker.json`, `keyring.json`, `device.key`,
`lease.json`, and `vault.json` by default).

## Setup, in order

1. **Recovery key:** `tir recovery init`. Write the base32 key on paper. Only the public half is stored.
2. **Broker identity:** start the broker once. It creates `identity.key` and logs `Broker identity (pin this in the Keyring): <b64>`.
3. **Enrol:** `tir enroll --broker http://<broker>:7780 --broker-key <b64>`. Copy the printed `Devices` entry into the broker's `appsettings.json` (`Broker:Devices`). With a trust chain instead, set `Broker:TrustChainPath` and `Broker:PinnedGenesisHash`: the chain's active devices replace `Devices`, the accepted head is kept in `<chain>.head`, and a device-signed `POST /trust/chain` delivers a longer chain.
4. **Secrets:** `tir vault add llm-read` once per credential. The value is the whole `Authorization` header (`Bearer sk-…`). It is typed without echo, or piped in with `--from-stdin`. Each add takes a Hello prompt.
5. **Policy:** edit `services` in the local `vault.json` by hand (grants, methods, allow/deny regexes). It is policy, not secret.
6. **Deploy:** copy `vault.json` to the broker's `Broker:VaultPath` and restart the broker.
7. **Forwarder:** set `Forwarder:BrokerUrl` and run it (see below).
8. **Daily:** run `tir agent` in a terminal and leave it running. Then `tir unlock` (one Hello prompt opens the workday lease).
9. **Hand out access:** `tir grant llm --consumer claude:my-worktree --ceiling read --purpose "model list" --for 1h` shows the consent lines, asks y/N, then asks for Hello, and prints a `tirph_…` token.
10. **Point the tool at it:** `LLM_API_BASE=http://127.0.0.1:7781/svc/llm` and `LLM_API_TOKEN=tirph_…`.
11. **Writes behind elevation:** `tir elevate llm admin --for 15m`. `tir lock` ends the lease, and so do locking, sleeping or logging off while `tir agent` runs.

## Solo mode (in-process)

`tir solo init` and the agent host this broker inside the agent on `127.0.0.1:7780` instead (see
the main README). The one setting only solo mode uses is `Broker:IdentifyLoopbackCaller`: on the
placeholder routes the broker then drops every client-sent `X-Tiresias-*` header and records the
local calling process itself, from the loopback connection's TCP table, as the forwarder would.

## Forwarder service account

Run the forwarder as its own Windows service account, not as the admin. Then malware running as the admin can't
read the forwarder's memory or replace its binary. Service installation is not automated. Use
`sc.exe create` or NSSM with a dedicated local account and grant it read access to the publish
folder only. The forwarder refuses to start on any non-loopback listen address (`urls`,
`Kestrel:Endpoints`, `HTTP(S)_PORTS`) and stops if it ever finds itself bound to one.

## Honest limits

- **Hello wrap rests on determinism.** The wrap key is HKDF of a Hello RSA PKCS#1 v1.5 signature over a fixed challenge. If Windows ever made those signatures randomised, unwrap would fail closed, and you would re-wrap from the recovery key. Re-wrapping from the recovery key has no command yet.
- **The design's key is different.** The design names a P-256 CNG key with a Hello UI policy. This build uses `KeyCredentialManager` (RSA), because it is the supported Hello API.
- **`X-Tiresias-Observed-Process` is unsigned.** The forwarder has no device key, so the broker records the header and never decides on it. Anything that can reach the broker directly could set it. Only the VPN stands between the two.
- **The PID can be wrong.** The port→PID lookup races with connection teardown. Under a separate account, the image path of the admin's processes may be unreadable, and then only the PID is shown.
- **`tir grant` doesn't observe a process.** It mints on the admin's own consent, so its `Process` line reads "unknown". No flow lets an agent ask for its own placeholder yet.
- **Policy is bound, not signed.** Each secret is bound to its policy (upstream, grant rules, which grant uses it) when a change is approved with Windows Hello, and the broker refuses it under any other, and refuses unbound secrets (`tir vault migrate` binds those). Restoring an older `vault.json` restores an older, once-approved policy, which still works: the rollback check needs storage the user's account can't write, which comes with the Windows service. See [policy integrity](../../docs/policy-integrity.md).
- **Step-up rests on the unlocked agent.** `/placeholder`, `/elevate` and `/token` need an approval signed with a key derived from the Hello wrap, which the broker learns only from a seal that opens the vault ([step-up at the broker](../../docs/step-up.md)). The unlocked app holds that key in memory, and a program at the same integrity level can click Allow in its consent dialog.
- **The agent can miss events.** If `tir agent` isn't running, or misses the event, a lock or sleep doesn't end the lease. The broker ends it once the heartbeat goes missing past its timeout, or at the hard cap.
- **Plaintext lingers briefly.** A decrypted value exists briefly as a managed string while the broker builds the upstream header, and it can't be zeroed.
