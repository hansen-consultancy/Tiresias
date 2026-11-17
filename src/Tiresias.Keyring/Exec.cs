using System.Diagnostics;
using Tiresias.Access;
using Tiresias.Client;
using Tiresias.Vault;

namespace Tiresias.Keyring;

/// <summary>
/// <c>tir exec</c>: one consent for a set of services, then a child process whose environment holds
/// placeholders (and, for a GitHub App, an installation token) per <see cref="ExecPlan"/>. The
/// placeholders are revoked when the child exits, so nothing it leaked outlives it.
/// </summary>
static class Exec
{
    static readonly Uri Forwarder = new("http://127.0.0.1:7781");

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

        Console.WriteLine($"Run: {string.Join(' ', args.Rest)}");
        foreach (var (service, request) in requests)
        {
            foreach (var line in Consent.Describe(request, service))
                Console.WriteLine("  " + line);
            Console.WriteLine();
        }
        foreach (var service in services.Where(ExecPlan.IsGitHubApp))
            Console.WriteLine($"  {service.Slug}: a GitHub App installation token in GH_TOKEN (valid up to 1 h)");
        if (!Terminal.Confirm("Approve?"))
            return Fail("Not approved.");
        HelloKeyWrapper.ConfirmPresence($"exec\n{string.Join(',', slugs)}\n{consumer}");

        using var client = Commands.Client(KeyringStore.RequireBroker(), settings);
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
                credentials.Add(new(service, token));
            }

            var start = new ProcessStartInfo(args.Rest[0]) { UseShellExecute = false };
            foreach (var arg in args.Rest.Skip(1))
                start.ArgumentList.Add(arg);
            foreach (var (name, value) in ExecPlan.Environment(credentials, Forwarder))
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
