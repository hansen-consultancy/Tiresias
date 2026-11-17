using System.Globalization;
using Tiresias.Agent;

namespace Tiresias.App;

/// <summary>
/// The app's diagnostic log, <c>%LOCALAPPDATA%\Tiresias\app.log</c>: agent events and full exception
/// details (stack traces go here, never on screen). Nothing written here carries a secret value;
/// the agent's messages and exceptions never contain one. Rolled over at 1 MB.
/// </summary>
public static class AppLog
{
    const long MaxBytes = 1024 * 1024;
    static readonly Lock Gate = new();

    public static string Path => System.IO.Path.Combine(KeyringStore.Directory, "app.log");

    public static void Info(string message) => Write("info ", message);

    public static void Error(Exception e, string? context = null) => Write("error", $"{context}{(context is null ? "" : ": ")}{e}");

    static void Write(string level, string message)
    {
        lock (Gate)
        {
            try
            {
                Directory.CreateDirectory(KeyringStore.Directory);
                if (File.Exists(Path) && new FileInfo(Path).Length > MaxBytes)
                    File.Move(Path, Path + ".1", overwrite: true);
                File.AppendAllText(Path, string.Create(CultureInfo.InvariantCulture, $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz} {level} {message}{Environment.NewLine}"));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // The log is a convenience; failing to write it must not take the agent down.
            }
        }
    }
}
