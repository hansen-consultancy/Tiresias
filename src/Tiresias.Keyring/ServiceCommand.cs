using Tiresias.Agent;
using Tiresias.Policy;
using Tiresias.Vault;

namespace Tiresias.Keyring;

/// <summary><c>tir service add|list|remove</c>: the vault's services, without editing its JSON by hand.</summary>
static class ServiceCommand
{
    public static int Run(CommandLine args) => args.At(1) switch
    {
        "add" => Add(args),
        "list" => List(),
        "remove" => Remove(args),
        _ => throw new UsageException("Use tir service add, tir service list or tir service remove."),
    };

    static int Add(CommandLine args)
    {
        var input = new ServiceInput(
            args.Require(2, "slug"),
            args.Require("--upstream"),
            args.Option("--secret"),
            args.Options("--method"),
            args.Options("--allow"),
            args.Options("--deny"),
            args.Option("--grant"),
            args.Flag("--elevation"));
        var plan = ServicePlanner.Plan(input, VaultEditor.Load());
        if (plan.Service is not { } service)
        {
            foreach (var problem in plan.Problems)
                Console.Error.WriteLine(problem.Message);
            return 2;
        }

        if (plan.NeedsSecret)
        {
            Console.WriteLine($"Secret {plan.SecretSlug} isn't in the vault yet.");
            var version = Commands.SealSecret(plan.SecretSlug, args.Flag("--from-stdin"));
            Console.WriteLine($"Sealed {plan.SecretSlug} v{version}.");
        }
        else
            Console.WriteLine($"Using secret {plan.SecretSlug}, already in the vault.");

        VaultEditor.AddService(service);
        var grant = service.Grants[0];
        Console.WriteLine($"Added service {service.Slug} -> {service.Upstream}: grant {grant.Name}, {Describe(grant)}.");
        if (plan.AllowsEveryPath)
            Console.WriteLine($"Every path is allowed. To narrow it, remove and add again with e.g. --allow '^/v1/models$' (one --allow per pattern).");
        Console.WriteLine(Commands.PickedUp());
        Console.WriteLine($"Try it: tir exec {service.Slug} --purpose \"try {service.Slug}\" -- <command>");
        return 0;
    }

    static int List()
    {
        var vault = VaultEditor.Load();
        if (vault.Services.Count == 0)
        {
            Console.WriteLine($"No services in {VaultEditor.Path}. Add one: tir service add <slug> --upstream https://api.example.com");
            return 0;
        }
        foreach (var service in vault.Services.OrderBy(s => s.Slug, StringComparer.Ordinal))
        {
            Console.WriteLine($"{service.Slug}  {service.Upstream}");
            foreach (var grant in service.Grants)
                Console.WriteLine($"  {grant.Name}: secret {grant.SecretSlug}{(vault.FindSecret(grant.SecretSlug) is null ? " (MISSING from the vault)" : "")}, {Describe(grant)}");
        }
        return 0;
    }

    static int Remove(CommandLine args)
    {
        var slug = args.Require(2, "slug");
        if (!VaultEditor.RemoveService(slug))
            throw new InvalidOperationException($"No service named {slug}. tir service list shows them.");
        Console.WriteLine($"Removed service {slug}. Its secret stays in the vault, so adding the service again reuses it. {Commands.PickedUp()}");
        return 0;
    }

    static string Describe(Grant grant) =>
        $"{string.Join(",", grant.Rule.Methods.Order(StringComparer.Ordinal))} {string.Join(" ", grant.Rule.Allow)}"
        + (grant.Rule.Deny is { Count: > 0 } deny ? $", deny {string.Join(" ", deny)}" : "")
        + (grant.RequiresElevation ? ", needs elevation" : "");
}
