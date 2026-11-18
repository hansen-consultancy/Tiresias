namespace Tiresias.App.Logic;

/// <summary>The command Windows runs at sign-in to start the app, as kept under the <c>Run</c> key.</summary>
public static class SignInStart
{
    /// <summary>Quoted: an install folder under a profile with a space in its name still starts.</summary>
    public static string Command(string exe) => $"\"{exe}\"";

    /// <summary>Whether <paramref name="command"/> starts <paramref name="exe"/>, quoted or not, in any case.</summary>
    public static bool Starts(string? command, string exe) =>
        command is not null && string.Equals(command.Trim().Trim('"'), exe, StringComparison.OrdinalIgnoreCase);
}
