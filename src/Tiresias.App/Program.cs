using Velopack;

namespace Tiresias.App;

static class Program
{
    [STAThread]
    static void Main()
    {
        // Handles Velopack's install, update and uninstall hooks (and exits for them) before any UI.
        VelopackApp.Build().Run();
        var app = new App();
        app.InitializeComponent();
        app.Run();
    }
}
