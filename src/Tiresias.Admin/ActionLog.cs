using Tiresias.AdminTier;

namespace Tiresias.Admin;

/// <summary>All requests share a rolling action log. Authorized changes also have a durable history
/// whose retention is independent of ordinary request traffic.</summary>
sealed class ActionLog(string path)
{
    const long MaxBytes = 10 * 1024 * 1024;
    readonly Lock gate = new();
    readonly string changes = Path.Combine(Path.GetDirectoryName(path)!, "changes.jsonl");

    public void Append(AdminAction action)
    {
        lock (gate)
        {
            if (action.ActingFor is not null && AdminCallerPolicy.NeedsElevation(action.Op))
            {
                using var stream = new FileStream(changes, FileMode.Append, FileAccess.Write, FileShare.Read);
                var change = action with { Image = null };
                stream.Write(System.Text.Encoding.UTF8.GetBytes(change.ToLine() + Environment.NewLine));
                stream.Flush(flushToDisk: true);
            }
            if (File.Exists(path) && new FileInfo(path).Length > MaxBytes)
                File.Move(path, path + ".1", overwrite: true);
            File.AppendAllText(path, action.ToLine() + Environment.NewLine);
        }
    }
}
