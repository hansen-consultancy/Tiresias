# Threat model

One file per finding, named by its ID. There is no shared header, version, review date or history
table: `git log docs/threats` is the history, and two branches adding findings never touch the same
file.

The summary is never written by hand. Print it, and check every file, with:

```bash
python -I tools/threats.py           # summary, highest score first
python -I tools/threats.py --check   # validation only, as CI runs it
```

## A finding

```markdown
---
id: S-41
title: A program running as the user can add a device key to the trust chain
stride: Spoofing
likelihood: 3
impact: 4
status: open
issue: 41
control: ASVS V6 Authentication
---

**Threat.** Who does what, by which path, and what they gain.

**Today.** What holds it back now, with links to the code or design.

**Closes it.** What would move it to resolved, or why it is accepted.
```

| Field | Values |
|---|---|
| `id` | `<letter>-<issue number>`, or `<letter>-<slug>` when no issue tracks it. It is the file name without `.md`. The letter is the STRIDE category's: `S`, `T`, `R`, `I`, `D`, `E` |
| `stride` | `Spoofing`, `Tampering`, `Repudiation`, `Information disclosure`, `Denial of service`, `Elevation of privilege` |
| `likelihood`, `impact` | 1 (low) to 4 (high). The score is their product; 8 or more is **high** |
| `status` | `open` · `mitigated` (reduced, a residual remains) · `accepted` (a stated limit, with the reason) · `resolved` (closed; kept for the record) |
| `issue` | The GitHub issue number. Required for an `open` high finding |
| `control` | The OWASP ASVS 5.0 chapter that addresses it, or the infrastructure that does where ASVS is thin (repudiation, denial of service) |

ASVS chapters by category: **Spoofing** V6 Authentication, V7 Session Management, V9 Self-contained
Tokens; **Tampering** V2 Validation and Business Logic, V4 API, V5 File Handling, V11 Cryptography,
V12 Secure Communication; **Information disclosure** V13 Configuration, V14 Data Protection,
V11/V12; **Elevation of privilege** V8 Authorization; **Repudiation** V16 Security Logging.

## When to add or change one

In the same PR as the change, never as a follow-up:

- a change that adds a trust boundary, a credential path, an endpoint or a stored secret adds the
  finding it creates;
- a change that mitigates or closes a finding updates its `status`, its scores and its **Today**;
- a limit stated in a README's *Honest limits* has a finding here, `accepted` or better.

A vulnerability in a released build is reported privately first ([SECURITY.md](../../SECURITY.md)),
and gets its file once the fix ships.
