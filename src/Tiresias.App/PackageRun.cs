using System.Windows;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.App.Views;
using Tiresias.Client;

namespace Tiresias.App;

/// <summary>Asks before a package fix runs, saying exactly what will run, then runs it and lists the packages again.</summary>
static class PackageRun
{
    /// <summary>What to tell the user afterwards, and whether it worked; <c>null</c> when the user said no.</summary>
    public static async Task<(string Message, bool Done)?> ApproveAndRunAsync(Window? owner, PackageFix fix)
    {
        var ask = PackageActions.Ask(fix);
        if (!AskWindow.Confirm(owner, Text.Format(ask.Heading, fix.Name), Text.Format(ask.Body, fix.Command.Text), Text.Get(ask.Action)))
            return null;
        var exit = await Desktop.RunPackageAsync(fix.Command);
        var (key, done) = PackageActions.Outcome(exit);
        // The day's listing no longer says what is installed: take it again, off the UI thread.
        await Task.Run(() => ToolInventory.Current(refresh: true));
        return (Text.Format(key, fix.Name, fix.Command.Text, exit ?? 0), done);
    }
}
