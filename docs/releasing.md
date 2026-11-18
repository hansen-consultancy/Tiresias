# Releasing

Tiresias ships two things, and they version independently:

| What | Tag | Workflow | Where it goes |
|---|---|---|---|
| NuGet packages (`Tiresias.Core`, `Tiresias.Protocol`, `Tiresias.Extensions.Configuration`) | `v0.1.0-preview.3` | `release.yml` | nuget.org, plus a GitHub release |
| Desktop app (`Tiresias.exe` and `tir.exe`) | `app-v0.1.0-preview.3` | `app-release.yml` | a GitHub release that installed apps update from |

Both take their release notes from `CHANGELOG.md`: the section whose heading is the version
(`## [0.1.0-preview.3] - 2026-11-17`). The workflow fails if that section is missing or empty.
The app release packs the same section into the update, so the app shows those notes before it
restarts.

## Release steps

1. **Changelog.** In `CHANGELOG.md`, rename the lines under `## [Unreleased]` to a new heading,
   `## [<version>] - <yyyy-MM-dd>`. Leave an empty `## [Unreleased]` above it. Add the version's
   compare link at the bottom, next to the others. Merge that to `main`.
2. **Tag `main`,** for the packages, the app or both:

   ```bash
   git tag v0.1.0-preview.3 && git push origin v0.1.0-preview.3
   git tag app-v0.1.0-preview.3 && git push origin app-v0.1.0-preview.3
   ```

   A version with a `-` (a preview) is published as a GitHub pre-release. Preview builds of the app
   update to preview releases; stable builds only to stable ones.
3. **Check the run.** For the app, the **Verify signatures** step lists each signed file and its
   signer.
4. **Check the release** on GitHub. An app release carries `TiresiasApp-win-Setup.exe` (the
   installer), `TiresiasApp-win-Portable.zip`, the `-full.nupkg` and `-delta.nupkg` packages, and the
   `releases.win.json` feed that installed apps read.

The NuGet workflow needs nuget.org trusted publishing (the `nuget` environment and the
`NUGET_USER` secret, see `release.yml`). The app workflow needs the one-time Azure setup below.
Without it, the workflow stops at its first step and names each missing variable. It never
publishes an unsigned app.

## One-time Azure setup for code signing

The app, `tir` and the installer are signed with **Azure Artifact Signing** (formerly Trusted
Signing). GitHub Actions signs in to Azure with OIDC, so no secret is stored anywhere: Azure trusts
tokens that GitHub issues for this repository's `app-release` environment.

You need an Azure subscription, and rights to create resources and role assignments in it.

### 1. Artifact Signing account and certificate profile

1. In the Azure portal, create an **Artifact Signing account** (search for "Artifact Signing").
   Pick a region; the account's **endpoint** URI depends on it, for example
   `https://weu.codesigning.azure.net/` for West Europe.
2. In the account, complete **identity validation** for the publisher name that should appear on
   the signature. This takes from hours to days.
3. Create a **certificate profile** of type **Public Trust**, linked to that validated identity.

Note three values: the endpoint URI, the account name and the certificate profile name.

### 2. App registration with a federated credential

1. Go to **Microsoft Entra ID**, then **App registrations**, then **New registration**. Name it
   (for example `tiresias-app-release`) and choose single tenant. No redirect URI is needed.
2. Note its **Application (client) ID** and **Directory (tenant) ID**.
3. Open **Certificates & secrets**, then **Federated credentials**, then **Add credential**:
   - scenario: **GitHub Actions deploying Azure resources**;
   - organization: `hansen-consultancy`, organization ID: `18004248`;
   - repository: `Tiresias`, repository ID: `1461937520`;
   - entity type: **Environment**; environment name: `app-release`.

   The subject this creates is
   `repo:hansen-consultancy@18004248/Tiresias@1461937520:environment:app-release`. The repository
   issues tokens in GitHub's immutable-ID subject format, so leaving the two ID fields empty
   stores the literal `{Organization ID}` and the sign-in fails. To see the format a repository
   uses, run `gh api repos/hansen-consultancy/Tiresias/actions/oidc/customization/sub`. An
   environment is used rather than a tag, because Azure doesn't take wildcards and every release
   has its own tag.

### 3. Signer role

On the **certificate profile** (or the whole Artifact Signing account), open **Access control
(IAM)**, then **Add role assignment**. Choose **Artifact Signing Certificate Profile Signer**
(named "Trusted Signing Certificate Profile Signer" in older portals) and assign it to the app
registration from step 2.

### 4. GitHub environment and variables

1. In the repository settings, create the environment **`app-release`**. Under **Deployment
   branches and tags**, allow only tags matching `app-v*`, so nothing else can sign as Tiresias.
2. Add these as **variables** (not secrets; none of them grants anything on its own), on the
   repository or on the environment:

   | Variable | Value |
   |---|---|
   | `AZURE_CLIENT_ID` | the app registration's Application (client) ID |
   | `AZURE_TENANT_ID` | the Directory (tenant) ID |
   | `AZURE_SUBSCRIPTION_ID` | the subscription that holds the Artifact Signing account |
   | `AZURE_SIGNING_ENDPOINT` | the account's endpoint URI |
   | `AZURE_SIGNING_ACCOUNT` | the Artifact Signing account name |
   | `AZURE_SIGNING_PROFILE` | the certificate profile name |

Keep the values out of the repository. The workflow reads them only from these variables.

### Certificate lifetime

Artifact Signing issues a new certificate every day, valid for three days, so the certificate
profile always shows an expiry date a few days away. That is expected and needs no renewal. A
signature stays valid after its certificate expires only because it carries a trusted timestamp.
The **Verify signatures** step therefore fails on any file whose signature has no timestamp. What
does need renewing is the identity validation behind the profile, before its own expiry date.

### Checking the setup

Push a pre-release tag such as `app-v0.1.0-preview.3`. If the signing setup is incomplete, the
run fails. A failure at **Check signing configuration** means a variable is missing. A failure at
**Azure sign-in** means the federated credential's subject doesn't match the environment. A
signing error during **Pack** usually means the role assignment is missing or hasn't taken effect
yet; it can take a few minutes. Nothing is published until the signatures are verified. After a
failure, fix the setup and re-run the workflow, or delete the tag and push it again.

## Not covered yet

- winget: the manifest and its submission.
- The NuGet packages are not Authenticode-signed. nuget.org signs them as the repository.
