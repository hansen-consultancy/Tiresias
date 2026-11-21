namespace Tiresias.Admin;

/// <summary>Appends <see cref="Tiresias.AdminTier.AdminAction"/> lines, rolling over at 10 MB so a caller can't fill the disk.</summary>
sealed class ActionLog(string path)
{
    const long MaxBytes = 10 * 1024 * 1024;
    readonly Lock gate = new();

    public void Append(string line)
    {
        lock (gate)
        {
            if (File.Exists(path) && new FileInfo(path).Length > MaxBytes)
                File.Move(path, path + ".1", overwrite: true);
            File.AppendAllText(path, line + Environment.NewLine);
        }
    }
}
