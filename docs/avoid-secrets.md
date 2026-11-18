# Need no secret at all

**Status:** a guide in progress; add to it whenever a service offers a way out of a long-lived key.

The safest secret is the one that doesn't exist. Tiresias protects keys you can't avoid; before
sealing one, check whether the service lets you drop it. Each switch below removes a text secret
that could leak from a file, an environment variable or a log.

| Instead of | Use | Why it is better |
|---|---|---|
| A NuGet API key in CI | **Trusted publishing** on nuget.org: the workflow's OIDC token is exchanged for a key valid about an hour | Nothing stored in the repository's secrets; a leaked token expires on its own |
| An npm or PyPI token in CI | **Trusted publishing** (npm provenance, PyPI trusted publishers), same OIDC exchange | As above |
| Cloud credentials in CI (Azure, AWS, Google) | **Workload identity federation** / OIDC from GitHub Actions | No client secret to rotate; access is bound to the repository and branch |
| A password for a website or an account | **Passkeys** | Phishing-resistant, and nothing reusable to steal from a database or a paste |
| A personal access token for git | **Git Credential Manager** with browser sign-in, or SSH keys held by an agent (Windows Hello, a hardware key) | No token in a file or a remote URL |
| A GitHub token for automation | A **GitHub App** installation token (minted per run, valid one hour; `tir exec` does this) | Scoped to chosen repositories, short-lived |
| A SQL password in a connection string | **Integrated / Entra ID authentication** where the server supports it | The connection string holds no secret |
| An API key for a service on the same cloud | **Managed identity** | The platform hands the app a token; nothing to configure |
| A long-lived API key you must keep | A key with the **narrowest scope and an expiry**, sealed in Tiresias and handed out as a placeholder | Least privilege, and the real key never reaches the program |

## When a secret is unavoidable

- Seal it: user secrets and environment variables go into Tiresias rather than into files or the
  Windows environment ([environment variables](environment-variables.md)).
- Prefer placeholder delivery (`tir exec`) over handing out the real value.
- Give it an expiry and a reminder to rotate it.
