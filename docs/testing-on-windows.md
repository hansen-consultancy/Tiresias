# Testing on Windows

This page walks through Tiresias on one Windows 11 PC in solo mode, with no server. You build it
from source, run the tray app, protect a sample app's user secrets, approve a request in the
consent dialog, and call an API through the solo broker with `tir exec`. Each step says how to
check that it worked.

You need:

- Windows 11 with Windows Hello set up: a PIN is enough, face or fingerprint also work. Check it in
  Settings > Accounts > Sign-in options.
- The .NET 11 SDK and the .NET 10 runtime.
- Git, and PowerShell 7 (`pwsh`) for the commands below.

## 1. Build

```powershell
git clone https://github.com/hansen-consultancy/Tiresias.git
cd Tiresias
dotnet build Tiresias.slnx
dotnet test src/Tiresias.Tests/Tiresias.Tests.csproj
```

Then publish the app and `tir` into folders of their own. The commands below put `tir` on the
PATH for this terminal session:

```powershell
$root = "$env:LOCALAPPDATA\Programs\Tiresias"
dotnet publish src/Tiresias.App -c Release -o "$root\app"
dotnet publish src/Tiresias.Keyring -c Release -o "$root\cli"
$env:PATH = "$root\cli;$env:PATH"
tir status
```

**To start from scratch,** quit the app and rename `%LOCALAPPDATA%\Tiresias`, which holds the
Keyring, the vault and the logs. Renaming keeps a backup. The Windows Hello key Tiresias created
stays in Windows, so the wizard skips its Hello step.

## 2. Run the app and finish the first run

```powershell
& "$root\app\Tiresias.exe"
```

The **Set up Tiresias** window opens:

1. **Welcome**, then **Continue with Windows Hello**. Windows asks for your PIN, face or
   fingerprint.
2. **Write down your recovery key.** It is shown once. Write it on paper and tick the box.
3. **Check your copy.** Type the two groups it asks for. If you get them wrong, use **Show the
   key again**.
4. **How do you want to run Tiresias?** Keep **Solo (recommended)**.
5. **You're all set.**

Check that it worked:

- The tray icon (next to the clock, maybe behind the ^ arrow) shows **Unlocked until ...** and
  **Solo: the broker runs in this app**.
- `tir status` prints `App: Unlocked until ...` and ` - Solo, hosted by the app` after the broker
  line.
- **Status...** in the tray menu shows the checks. A solo PC has two warnings, egress and
  isolation. They are the solo trade-offs, not faults.

Things worth trying:

- **Start the app a second time.** The running one comes forward and no second icon appears.
- **Close the wizard halfway, then start the app again.** It continues at the first missing step.
  If you close it after the recovery key was shown, a resumed solo setup asks you to type the key
  back from paper.
- **Run `tir agent` while the app runs.** It refuses and says the app is the agent.

## 3. Unlock and lock

- **Lock** in the tray menu. The headline changes to **Locked**.
- **Unlock with Windows Hello** in the tray menu. It takes one Hello prompt.
- `tir lock` and `tir unlock` do the same through the app, and print what happened.
- **Lock the workstation (Win+L)** and sign back in. The app is locked. Any consent dialog that
  was open is answered **Deny**.
- **Cancel the Hello prompt.** The app explains what happened and offers **Try again**.

## 4. Protect a sample app's user secrets

`samples/ProtectedSecretsSample` is a minimal ASP.NET Core app. It references
`Tiresias.Extensions.Configuration` as a project. An app of your own would use the package
instead:

```xml
<PackageReference Include="Tiresias.Extensions.Configuration" Version="0.1.0-preview.2" />
```

You can also pack the library locally and use that:

```powershell
dotnet pack src/Tiresias.Extensions.Configuration -c Release -o "$HOME\tiresias-feed"
dotnet nuget add source "$HOME\tiresias-feed" --name tiresias-local
```

Either way, `Program.cs` keeps its plain `WebApplication.CreateBuilder(args)` call, and an
interceptor reroutes it when the app compiles.

First give the sample a secret, the usual way. It is plaintext at this point:

```powershell
dotnet user-secrets set Demo:ApiKey example-value --project samples/ProtectedSecretsSample
```

With the app unlocked, run the sample:

```powershell
dotnet run --project samples/ProtectedSecretsSample
```

1. The **consent dialog** appears on top of everything else. It shows the program asking (the
   sample's path) and the key `Demo:ApiKey`, but not its value. It also shows a countdown.
2. Choose **Allow for this session**.
3. In a second terminal, run `curl.exe http://localhost:5080/`. It answers
   `Demo:ApiKey is set (13 characters).`

Check that the file is sealed: open
`%APPDATA%\Microsoft\UserSecrets\tiresias-sample-2f7c\secrets.json`. It still holds valid JSON,
but now it is a sealed envelope and `example-value` is nowhere in it.

Things worth trying:

- **Run the sample again.** There is no dialog this time, because the session allowance holds until
  you lock or for 12 hours.
- **Choose Deny,** or let the countdown run out. The sample starts without the secret.
- **Lock, then run the sample.** It refuses the sealed file with a message to unlock.
- **Start the sample several times at once.** The dialogs come one after another, and each says how
  many are waiting.
- **Edit the secrets.** Tray menu > **Edit user secrets...**, then pick the project. Values are
  masked until you press **Show**. **Save** seals the file again. Try a screenshot or a screen
  share: the window shows up black. You can do the same from a terminal with `tir secrets list` and
  `tir secrets set Demo:ApiKey` in the sample's folder.
- **Quit the app, then run the sample.** It fails with a message instead of loading nothing. The
  sealed file needs the agent.

## 5. `tir exec` through the solo broker

Add a secret to the vault. Its value is the whole `Authorization` header. Use a dummy one: this
demo calls a public echo service.

```powershell
tir vault add httpbin-demo
# Value: Bearer example-token
```

Then describe what may use it. Open `%LOCALAPPDATA%\Tiresias\vault.json` and replace its
`"services": []` with:

```json
"services": [
  {
    "slug": "httpbin",
    "upstream": "https://httpbin.org",
    "grants": [
      { "name": "read", "secretSlug": "httpbin-demo", "requiresElevation": false,
        "methods": [ "GET" ], "allow": [ "^/headers$" ], "deny": [], "maxBodyBytes": null }
    ]
  }
]
```

The solo broker reads the vault when it starts, so restart the lease with `tir lock`, then
`tir unlock`. Then run a command with a placeholder in its environment:

```powershell
tir exec httpbin --purpose "try the solo broker" -- pwsh -NoProfile -Command 'curl.exe -s "$env:HTTPBIN_BASE_URL/headers" -H "Authorization: Bearer $env:HTTPBIN_TOKEN"'
```

1. `tir` prints what is being approved, then says it is waiting for the app.
2. The app's **consent dialog** shows `tir exec pwsh` and what it gets. Choose **Allow once**.
3. Windows Hello asks you to confirm.
4. httpbin echoes the request headers. `Authorization` reads `Bearer example-token`. The child
   process only held a `tirph_...` placeholder (`$env:HTTPBIN_TOKEN`); the broker swapped in the
   real value on the way out.

Things worth trying:

- **Call another path,** for example `/get` instead of `/headers`. The broker refuses it, because
  the grant only allows `^/headers$`.
- **Use the placeholder after the command exits.** It no longer works: `tir exec` revokes it when
  the child exits.
- **Quit the app and run the same `tir exec`.** It asks `Approve?` in the terminal instead, and
  needs the broker, so start `tir agent` first.

## 6. Activity and status

- **Activity...** in the tray menu lists every consent answer (user secrets) and every broker
  decision (lease, placeholder, allowed or denied request). Filter it by period, outcome
  (**Denied** shows the refused `/get`), source or text.
- **Status...** runs the same checks as `tir doctor`. **Copy details** puts them on the clipboard
  for an issue.
- If something fails, the app's problem screen has **Copy details** too. Stack traces never appear
  on screen. They are in `%LOCALAPPDATA%\Tiresias\app.log`.

## 7. Updates

A build from source doesn't update itself. To try updates you need two app releases: install the
older one with its `Tiresias-win-Setup.exe`, then publish the newer one. Within a day, or at the
next start, the tray menu offers **Update to ... available - restart to apply**. Choosing it shows
the release notes, then restarts into the new version. Choose it while a consent dialog or the
secrets editor is open: it asks you to finish that first.

## What you can't test yet

These are not built yet (see [desktop-app.md](desktop-app.md#what-is-built)):

- the solo broker as a Windows service;
- enrolling with a remote broker from the app (use `tir enroll`);
- re-sealing your secrets from the recovery key after the Windows Hello key is lost.
