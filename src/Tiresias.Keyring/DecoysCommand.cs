using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using Tiresias.AdminTier;
using Tiresias.Agent;
using Tiresias.Decoys;

namespace Tiresias.Keyring;

/// <summary><c>tir decoys</c>: place, list and remove decoy credentials. No decoy value is printed: the files hold them.</summary>
static class DecoysCommand
{
    public static int Run(CommandLine args) => args.At(1) switch
    {
        "place" => Place(args.Require(2, "kind"), args.At(3)),
        "list" => List(),
        "remove" => Remove(),
        "adopt" => Enroll(),
        "enroll" => (int)AdminTierSetup.Run("adopt-decoys", AppContext.BaseDirectory),
        // What remove runs elevated when the admin tier holds the decoys: not for typing.
        "release" => (int)AdminDecoys.Release(),
        _ => throw new UsageException("tir decoys takes place, list, adopt or remove."),
    };

    static int Place(string kind, string? where)
    {
        var placed = AdminDecoys.Place(kind switch
        {
            "passwords" => DecoyKind.PasswordsFile,
            "project" => DecoyKind.Project,
            "variables" => DecoyKind.Variables,
            _ => throw new UsageException("A decoy is passwords, project or variables."),
        }, where);
        Console.WriteLine($"Placed a decoy: {placed.Where}.");
        Console.WriteLine("A program that uses it is seen while the app or tir agent runs.");
        if (AdminClient.Installed)
            Console.WriteLine("Run tir decoys adopt to verify these placements and enable service monitoring (UAC).");
        return 0;
    }

    static int Enroll()
    {
        if (!AdminClient.Installed || RunElevated(enroll: true) != AdminSetupResult.Done)
        {
            Console.Error.WriteLine("Service enrollment was not completed. Existing local placements are kept.");
            return 1;
        }
        return List();
    }

    static int List()
    {
        if (DecoyStore.Current is null && Unanswered())
            return 1;
        if (DecoyStore.Current is null && AdminDecoys.Status() is { Held: true } held)
        {
            Console.WriteLine($"Held by the admin tier: {string.Join(", ", held.Kinds)}; {held.Files} file(s).");
            Console.WriteLine(held.Listening ? "Service listeners are active." : "Service listeners are waiting for their ports.");
            Console.WriteLine("Places, ports and values stay with it; tir decoys remove takes them back (UAC) and removes them.");
            return 0;
        }
        if (DecoyStore.Current is not { Placed.Count: > 0 } set)
        {
            if (AdminDecoys.Status() is { NeedsVerification: true })
            {
                Console.WriteLine("A previous registration needs verification. Run tir decoys adopt (UAC).");
                return 0;
            }
            Console.WriteLine("No decoys placed. tir decoys place passwords puts one in Documents.");
            return 0;
        }
        foreach (var placed in set.Placed)
            Console.WriteLine($"{placed.Kind,-14} {placed.Where}  (since {placed.Placed:yyyy-MM-dd})");
        Console.WriteLine($"Endpoints: HTTP on 127.0.0.1:{set.HttpPort}, SQL Server on 127.0.0.1:{set.SqlPort}.");
        return 0;
    }

    static int Remove()
    {
        if (DecoyStore.Current is null && Unanswered())
            return 1;
        if (DecoyStore.Current is null && AdminDecoys.Status() is { Held: true } or { NeedsVerification: true })
        {
            Console.WriteLine("The admin tier holds the decoys; giving them back takes an administrator (UAC).");
            if (RunElevated(enroll: false) is not AdminSetupResult.Done || DecoyStore.Current is null)
            {
                Console.Error.WriteLine("The admin tier still holds the decoys: nothing was removed.");
                return 1;
            }
        }
        var (left, kept) = DecoyStore.RemoveAll();
        if (kept.Count > 0)
            Console.WriteLine($"Kept {string.Join(", ", kept)}: changed since Tiresias placed it, so it is yours now.");
        if (left.Count == 0)
        {
            Console.WriteLine(kept.Count == 0 ? "Every decoy is removed." : "Every other decoy is removed.");
            return 0;
        }
        Console.Error.WriteLine($"Couldn't remove: {string.Join(", ", left)}. Close what holds them and run this again.");
        return 1;
    }

    /// <summary>Whether the admin tier is installed but doesn't answer: it may hold decoys that can't be listed or given back now.</summary>
    static bool Unanswered()
    {
        if (!AdminClient.Installed || AdminDecoys.Status() is not null)
            return false;
        Console.Error.WriteLine("The admin tier is installed but didn't answer, so decoys it may hold can't be seen or given back. Set it up again on the Tiresias app's About page to start it, then run this again.");
        return true;
    }

    /// <summary><c>tir decoys release</c>, elevated: this process when it already is, otherwise a copy started through UAC.</summary>
    static AdminSetupResult? RunElevated(bool enroll)
    {
        if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            return AdminTierSetup.Run(enroll ? "adopt-decoys" : "release-decoys", AppContext.BaseDirectory);
        try
        {
            using var process = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, ["decoys", enroll ? "enroll" : "release"]) { UseShellExecute = true, Verb = "runas" });
            if (process is null || !process.WaitForExit(TimeSpan.FromMinutes(2)))
                return AdminSetupResult.Failed;
            return (AdminSetupResult)process.ExitCode;
        }
        catch (Win32Exception)
        {
            // Declined at the UAC prompt.
            return null;
        }
    }
}
