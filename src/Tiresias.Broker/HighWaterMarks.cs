using System.Text.Json;
using NSec.Cryptography;

namespace Tiresias.Broker;

/// <summary>
/// The highest version of each secret a broker has authenticated, kept in a file across restarts so a
/// restored older vault is refused even while no lease is open (docs/broker-service.md). Only
/// meaningful where the user's account can't write the file: the Windows service's state folder.
/// </summary>
public sealed class HighWaterMarks(string path, PublicKey revisionKey)
{
    internal PublicKey RevisionKey { get; } = revisionKey;

    public IReadOnlyDictionary<string, int> Load()
    {
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, int>>(File.ReadAllBytes(path))
                ?? throw new InvalidDataException("The saved vault revisions are missing.");
        }
        catch (FileNotFoundException)
        {
            return new Dictionary<string, int>();
        }
    }

    public void Save(IReadOnlyDictionary<string, int> marks)
    {
        var temp = path + ".tmp";
        File.WriteAllBytes(temp, JsonSerializer.SerializeToUtf8Bytes(marks));
        File.Move(temp, path, overwrite: true);
    }
}
