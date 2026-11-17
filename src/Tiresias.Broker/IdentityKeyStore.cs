using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Tiresias.Broker;

/// <summary>
/// Where the broker keeps its identity's raw private key at rest. <see cref="Load"/> returns null
/// when there is none yet; the caller owns and clears the bytes.
/// </summary>
interface IIdentityKeyStore
{
    byte[]? Load();
    void Save(byte[] raw);
}

static class IdentityKeyStore
{
    /// <summary>DPAPI on Windows; elsewhere a file only the service account can read, which is weaker and says so.</summary>
    public static IIdentityKeyStore ForPlatform(string path, ILogger logger) =>
        OperatingSystem.IsWindows() ? new DpapiKeyStore(path, logger) : new OwnerOnlyFileKeyStore(path, logger);
}

/// <summary>
/// The key DPAPI-protected to the account the broker runs as (<c>CurrentUser</c> scope, so another
/// local account, or a copy of the file on another machine, can't open it). A file from before
/// this store, plain base64, is read once and rewritten protected.
/// </summary>
[SupportedOSPlatform("windows")]
sealed class DpapiKeyStore(string path, ILogger logger) : IIdentityKeyStore
{
    const string Prefix = "dpapi:";
    static readonly byte[] Entropy = "Tiresias.Broker identity v1"u8.ToArray();

    public byte[]? Load()
    {
        if (!File.Exists(path))
            return null;
        var text = File.ReadAllText(path).Trim();
        if (text.StartsWith(Prefix, StringComparison.Ordinal))
            return ProtectedData.Unprotect(Convert.FromBase64String(text[Prefix.Length..]), Entropy, DataProtectionScope.CurrentUser);

        var raw = Convert.FromBase64String(text);
        Save(raw);
        logger.LogWarning("Broker identity key at {Path} was stored in the clear; it is now DPAPI-protected to this account.", path);
        return raw;
    }

    public void Save(byte[] raw)
    {
        var temp = path + ".tmp";
        File.WriteAllText(temp, Prefix + Convert.ToBase64String(ProtectedData.Protect(raw, Entropy, DataProtectionScope.CurrentUser)), Encoding.ASCII);
        File.Move(temp, path, overwrite: true);
    }
}

/// <summary>
/// The key in the clear, base64, in a file created mode 600. There is no DPAPI equivalent every
/// Linux host has, so the file mode is the whole protection: anyone who is root or the service
/// account reads it. A file found wider than 600 is narrowed, with a warning.
/// </summary>
[UnsupportedOSPlatform("windows")]
sealed class OwnerOnlyFileKeyStore(string path, ILogger logger) : IIdentityKeyStore
{
    const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public byte[]? Load()
    {
        if (!File.Exists(path))
            return null;
        Warn();
        var mode = File.GetUnixFileMode(path);
        if (mode != OwnerOnly)
        {
            logger.LogWarning("Broker identity key at {Path} had mode {Mode}; narrowed to 600.", path, mode);
            File.SetUnixFileMode(path, OwnerOnly);
        }
        return Convert.FromBase64String(File.ReadAllText(path).Trim());
    }

    public void Save(byte[] raw)
    {
        Warn();
        var temp = path + ".tmp";
        using (var stream = new FileStream(temp, new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, UnixCreateMode = OwnerOnly }))
            stream.Write(Encoding.ASCII.GetBytes(Convert.ToBase64String(raw)));
        File.Move(temp, path, overwrite: true);
    }

    void Warn() => logger.LogWarning(
        "Broker identity key at {Path} is protected by its file mode only (no DPAPI on this platform). Keep the broker's account and host to itself.", path);
}
