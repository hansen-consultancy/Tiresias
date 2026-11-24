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
        // Velopack starts the app in its version folder, and everything the app starts inherits the
        // working folder. A program still running there holds the folder, and the next update can't
        // move it (#149).
        Environment.CurrentDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        // Run elevated by AdminTierElevation, after its UAC prompt: no window, just the step and its exit code.
        if (args is [AdminTierElevation.Argument, var verb])
            return (int)AdminTierSetup.Run(verb, AppContext.BaseDirectory);
        if (args is [AdminTierElevation.Argument, "review-incidents", var id] &&
            long.TryParse(id, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var through) && through > 0)
        {
            var history = AdminIncidents.History();
            if (history?.Events.FirstOrDefault(e => e.Id == through) is not { } last)
                return (int)AdminTier.AdminSetupResult.Failed;
            if (history.ReviewedThrough >= through)
                return (int)AdminTier.AdminSetupResult.Done;
            var count = history.Events.Count(e => e.Id > history.ReviewedThrough && e.Id <= through);
            return Confirm(Text.Format("AdminIncidents_ConfirmReview", count, last.Hit.At.ToLocalTime().ToString("g", System.Globalization.CultureInfo.CurrentCulture)))
                ? (int)AdminIncidents.Review(through) : (int)AdminTier.AdminSetupResult.Failed;
        }
        if (args is [AdminTierElevation.Argument, "unblock-program", var program])
            return AdminTier.AdminArgs.Program(program) && Confirm(Text.Format("AdminIncidents_ConfirmUnblock", program))
                && AdminDecoys.Thaw(program) == AdminTier.AdminSetupResult.Done
                ? (int)AdminProgramBlocks.Unblock(program) : (int)AdminTier.AdminSetupResult.Failed;
        var app = new App();
        app.InitializeComponent();
        app.Run();
        return 0;
    }

    static bool Confirm(string action) => System.Windows.MessageBox.Show(action, "Tiresias",
        System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Question,
        System.Windows.MessageBoxResult.No) == System.Windows.MessageBoxResult.Yes;

    /// <summary>Uninstalling the app takes the admin tier with it, behind its own UAC prompt; declined, it stays until removed by hand.</summary>
    static void RemoveAdminTier()
    {
        // Declined or failed, uninstalling goes on: the service runs from %ProgramFiles%, not from the app's folder.
        if (Task.Run(AdminClient.FactsAsync).GetAwaiter().GetResult().Installed)
            AdminTierElevation.Run("remove", TimeSpan.FromSeconds(20));
    }
}
