# Trust-chain links that add a key

Status: **phases 1 and 2 built**; the flows of phase 3 are not. Tracks issue #41. This page
designs how the trust chain stops accepting a new key that only the DPAPI device key vouches for.

## The problem

Every link after genesis is authorized by the Ed25519 device keys of existing devices
(`TrustChainVerifier`). Those keys are DPAPI-protected to the user's account, with no user presence.
So a program running as the user can do what an authorized device can:

1. Sign an `AddDevice` for that user, introducing a key it generated, countersign it with that key,
   and `POST /trust/chain`, signed with the same device key. The broker extends the chain.
2. On an administrator's device with the default threshold of 1, do the same with `AddUser`,
   including a new administrator.

The new key is the program's own, so unlike the DPAPI device key it can leave the machine. With a
remote broker it signs management requests from anywhere that reaches the broker, and it outlives
the program's removal until someone notices and revokes it. In solo mode the broker listens on
loopback only, so the new key works only on this machine. It still survives a cleanup, and the
broker lists it as one of the user's devices.

Step-up (#23, [step-up.md](step-up.md)) limits what such a key can do, because minting, elevation
and tokens will need an approval only the vault can produce. It doesn't stop the key being added,
and it can't stop a forged admin from changing the policy.

**Nothing in Tiresias adds a device today.** `tir solo init` writes a genesis. No command, window or
wizard builds `AddDevice`, `AddUser`, `AddBroker` or `SetPolicy`. Closing this now breaks no flow;
the planned **Move to a broker** and **Add a device** flows are built on the rule below.

## Which links matter

| Link | Effect | Needs presence |
|---|---|---|
| `AddDevice`, `AddUser` | Introduces a key that can sign requests and links | Yes |
| `AddBroker` | Names a broker identity that Keyrings accept | Yes |
| `SetPolicy` | Changes the admin threshold | Yes, both ways: lowering it weakens the chain, raising it to the admin count can be used to lock others out |
| `RevokeDevice`, `RemoveUser` | Takes access away | No: denial of service at worst, and the same program can already end leases |

## Decisions

- **Each device has a second key that needs a person: its Windows Hello key.** It is the
  non-exportable TPM-backed key `HelloKeyWrapper` already uses (`KeyCredentialManager`, credential
  `Tiresias`). Using it shows a Hello prompt every time.
- **Links that add trust are signed with the Hello key, as well as the device key, of every device
  that authorizes them.** A link only the device key signed is refused. Each new key a link
  introduces brings its own Hello key and countersigns with it, so presence is shown on the new
  device too.
- **The chain anchors the Hello keys.** Genesis names the first device's Hello key, and genesis is
  countersigned by the paper key. Every later Hello key arrives in a link that an existing Hello key
  signed. A program holding only device keys can't introduce a Hello key, so it can't add anything.
- **Old devices bind their Hello key once, with the paper key.** A device enrolled before this has
  no Hello key in the chain. A `BindHello` link names it, signed by the device key, the Hello key
  and the paper key. A solo chain, with one device and no history worth keeping, may instead start
  again with a new genesis.
- **Paper keys stay break-glass.** They authorize the one-time binding and recovery, not routine
  additions, so every paper-key signature still means something unusual happened.

## Design twice

| | **A. Paper key on every link that adds trust** | **B. Hello signature, anchored at genesis (chosen)** |
|---|---|---|
| What vouches for a new key | The offline paper key | A Hello gesture on an existing device and on the new one |
| Each new device or user | Find the paper key and type it | One Hello prompt on each machine |
| Paper-key uses | Routine: every addition, so the break-glass alert means nothing | Only the binding of old devices and recovery |
| Without the paper key at hand | No new device can be added at all | Unaffected |
| New verifier code | None beyond the rule | RSA verification of Hello signatures; a `Hello` field on device references |

B wins: the paper key keeps its meaning, and adding a device costs one gesture per machine.

## Shape

### Device references

`DeviceRef` gains `Hello`, the Hello key's public key (RSA, SubjectPublicKeyInfo), which is required
for a device and absent for a paper key. `LinkSignature` gains an optional `Hello` signature: RSA
PKCS#1 SHA-256 over `tiresias/v1/link\n` followed by `TrustChain.SignedBytes(link)`. The prefix keeps a link
signature apart from every other Hello use (`tiresias/v1/presence`, the wrap's challenge), so one
can never stand in for another.

### The verifier's rule

For `AddDevice`, `AddUser`, `AddBroker`, `SetPolicy` and `BindHello`:

- every authorizing device signature carries a Hello signature that verifies under that device's
  Hello key in the chain, unless the authorizer is a paper key;
- every introduced device countersigns with both of its keys;
- an authorizer whose device has no Hello key yet fails with `PresenceRequired`, unless the link is
  a `BindHello` for that device signed by a paper key.

`RevokeDevice` and `RemoveUser` keep today's rule. Genesis names the device's Hello key, and its
paper-key countersignature anchors it.

**As built, a genesis without a Hello key is still accepted**, so chains made before this rule keep
working: refusing it would stop every existing solo broker. Its device then authorizes nothing that
needs presence until a `BindHello` names its key, which needs the paper key. A program with only the
device key gains nothing from such a genesis. `tir solo init` always writes the Hello key.

### Who builds links

| Flow | Prompts |
|---|---|
| Add a device (planned) | The new device makes its keys and shows its Hello prompt to countersign; an existing device of the same user signs with one Hello prompt. The two exchange the link as a file or a code, never through the broker unsigned |
| Add a user (planned) | As above, with an admin's device authorizing, and with as many admins as the threshold needs |
| Bind an old device | `tir trust bind-hello`: one Hello prompt, and the paper key typed once (hidden; S/5, Z/2, T/7, U/V forgiven as in restore) |
| Solo, starting again | `tir solo init` again, with the vault resealed to the new genesis's broker |

## Tests

- `TrustChainVerifierTests`:
  - `AddDevice` with device-key signatures but no Hello signature fails `PresenceRequired`;
  - a Hello signature by another device's Hello key, or over another link, fails;
  - a new device that didn't countersign with its Hello key fails;
  - `BindHello` without the paper key fails, and with it succeeds once;
  - a genesis without a Hello key is accepted, but its device can't authorize until bound;
  - revocation still needs only device keys;
  - a link signed with the `tiresias/v1/presence` prefix instead of the link prefix doesn't verify.
- `BrokerTrust` and the broker's `POST /trust/chain`: a chain extended without presence is refused
  and the head doesn't move.

## Not in scope

- **A Hello prompt the user is tricked into.** The prompt doesn't show what it signs. A program can
  start the link flow's prompt and hope the user approves. Tiresias's own flows show what is being
  added before the prompt, but the prompt itself can't prove that.
- **Reading the agent's memory.** Hello keys never leave the TPM. A program that controls the
  user's session can still wait for a real prompt and swap the bytes being signed.
- **Files the user can write.** The broker's accepted head, and in solo mode the pinned genesis
  hash and the chain file itself, live where a program running as the user can replace them.
  Replacing the whole chain gives that program a chain of its own, but no secret: the vault still
  opens only with Hello. Protecting those files is the Windows service's job, as for policy
  integrity.

## Phases

1. **Built.** Core: `Hello` on `DeviceRef` and `LinkSignature`, the prefix, `BindHello`, the
   verifier's rule and `PresenceRequired`. The broker and the Keyring both refuse links without
   presence, since no flow builds them yet. The `hello` fields are written only when set, so links
   made before keep their bytes and hashes; an older verifier drops them and fails closed.
2. **Built.** `tir solo init` and the app's first run write the Hello key into genesis (one more
   Hello prompt); `tir trust bind-hello` for existing chains (with the app running, in solo mode);
   `tir doctor` warns when this device's Hello key isn't in the chain. It asks the broker for the
   chain it serves (`GET /trust/chain`), the one `bind-hello` extends, and reads the solo chain file
   only when the broker doesn't answer: a broker running as the Windows service keeps its chain
   where the user can't read it, so the file alone went stale after `bind-hello`.
3. The Add a device and Move to a broker flows, built on this rule.
