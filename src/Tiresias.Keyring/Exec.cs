using System.Diagnostics;
using Tiresias.Access;
using Tiresias.Client;
using Tiresias.Agent;
using Tiresias.Vault;

namespace Tiresias.Keyring;

/// <summary>
/// <c>tir exec</c>: one consent for a set of services, then a child process whose environment holds
/// placeholders (and, for a GitHub App, an installation token) per <see cref="ExecPlan"/>. The
/// placeholders are revoked when the child exits, so nothing it leaked outlives it.
/// </summary>
static class Exec
{
    public static async Task<int> RunAsync(CommandLine args)
    {
        var slugs = args.Require(1, "service").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (args.Rest.Count == 0)
            throw new UsageException("Nothing to run. Put the command after --.");
        var settings = KeyringStore.Settings;
        var vault = VaultFile.Load(settings.VaultPath);
        var services = slugs.Select(s => vault.FindService(s) ?? throw new UsageException($"No service '{s}' in {settings.VaultPath}.")).ToArray();
        var consumer = $"exec:{Path.GetFileName(args.Rest[0])}";
        var purpose = args.Require("--purpose");
        var duration = Terminal.ParseDuration(args.Option("--for") ?? "1h");
        var ceiling = args.Option("--ceiling");

        var requests = services.Where(s => !ExecPlan.IsGitHubApp(s))
            .Select(s => (Service: s, Request: new AccessRequest(consumer, null, s.Slug, ceiling, purpose, duration)))
            .ToArray();
        var problems = requests.SelectMany(r => Consent.Validate(r.Request, r.Service)).ToArray();
        if (problems.Length > 0)
            return Fail(string.Join(Environment.NewLine, problems));

        var lines = new List<string> { $"Run: {string.Join(' ', args.Rest)}" };
        foreach (var (service, request) in requests)
            lines.AddRange(Consent.Describe(request, service).Select(line => "  " + line).Append(""));
        foreach (var service in services.Where(ExecPlan.IsGitHubApp))
            lines.Add($"  {service.Slug}: a GitHub App installation token in GH_TOKEN (valid up to 1 h)");
        foreach (var service in services)
            if (ExecPlan.LoginGrant(service, ceiling) is { } login)
                lines.Add($"  {service.Slug}: a temporary SQL login ({login.Name}) in {ExecPlan.EnvName(service.Slug)}_CONNECTION_STRING, dropped when the lease ends");
        foreach (var line in lines)
            Console.WriteLine(line);
        if (!await AppLink.ApproveAsync($"tir exec {Path.GetFileName(args.Rest[0])}", lines))
            return Fail("Not approved.");
        HelloKeyWrapper.ConfirmPresence($"exec\n{string.Join(',', slugs)}\n{consumer}");

        using var client = BrokerClient.For(await Commands.ReachableBrokerAsync());
        var credentials = new List<ExecCredential>();
        var minted = new List<string>();
        try
        {
            foreach (var service in services)
            {
                var response = ExecPlan.IsGitHubApp(service)
                    ? await client.PostAsync($"/token/{service.Slug}")
                    : await client.PostAsync("/placeholder", requests.Single(r => r.Service == service).Request);
                if (!response.Ok || response.Body is not { } body)
                    return Fail($"{service.Slug}: {response.Describe()}");
                var token = body.GetProperty("token").GetString()!;
                if (!ExecPlan.IsGitHubApp(service))
                    minted.Add(token);
                var connectionString = ExecPlan.LoginGrant(service, ceiling) is { } login
                    ? (await SqlLogin.RequestAsync(service.Slug, login.Name, token)).ConnectionString
                    : null;
                credentials.Add(new(service, token, connectionString));
            }

            var start = new ProcessStartInfo(args.Rest[0]) { UseShellExecute = false };
            foreach (var arg in args.Rest.Skip(1))
                start.ArgumentList.Add(arg);
            foreach (var (name, value) in ExecPlan.Environment(credentials, PlaceholderMinter.Endpoint))
                start.Environment[name] = value;
            using var child = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {args.Rest[0]}.");
            await child.WaitForExitAsync();
            return child.ExitCode;
        }
        finally
        {
            foreach (var token in minted)
                await client.PostAsync("/placeholder/revoke", new { token });
        }
    }

    static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 1;
    }
}
