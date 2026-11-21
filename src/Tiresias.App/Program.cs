using Tiresias.Agent;
using Velopack;

namespace Tiresias.App;

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        // Handles Velopack's install, update and uninstall hooks (and exits for them) before any UI.
        VelopackApp.Build()
            .OnAfterInstallFastCallback(_ => StartWithWindows.Set(true))
            .OnBeforeUninstallFastCallback(_ =>
            {
                TirOnPath.Remove();
                StartWithWindows.Set(false);
                RemoveAdminTier();
            })
            .Run();
        // Run elevated by AdminTierElevation, after its UAC prompt: no window, just the step and its exit code.
        if (args is [AdminTierElevation.Argument, var verb])
            return (int)AdminTierSetup.Run(verb, AppContext.BaseDirectory);
        var app = new App();
        app.InitializeComponent();
        app.Run();
        return 0;
    }

    /// <summary>Uninstalling the app takes the admin tier with it, behind its own UAC prompt; declined, it stays until removed by hand.</summary>
    static void RemoveAdminTier()
    {
        // Declined or failed, uninstalling goes on: the service runs from %ProgramFiles%, not from the app's folder.
        if (Task.Run(AdminClient.FactsAsync).GetAwaiter().GetResult().Installed)
            AdminTierElevation.Run("remove", TimeSpan.FromSeconds(20));
    }
}
