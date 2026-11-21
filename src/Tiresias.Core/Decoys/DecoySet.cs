using System.Security.Cryptography;
using System.Text.Json;

namespace Tiresias.Decoys;

/// <summary>What the user chose to place; each kind is one item in the short list they pick from.</summary>
public enum DecoyKind
{
    /// <summary>A <c>passwords.txt</c> with a connection string and an admin URL and token.</summary>
    PasswordsFile,
    /// <summary>A new folder that looks like an old project: <c>appsettings.Production.json</c> and <c>.env</c>.</summary>
    Project,
    /// <summary>User environment variables with the admin URL and token.</summary>
    Variables,
}

/// <summary>A decoy in place: a file Tiresias created, a folder it created, or a user variable it set.</summary>
public sealed record PlacedDecoy(DecoyKind Kind, string Where, DateTimeOffset Placed);

/// <summary>
/// The decoy values of this install. They look like the real kind and open nothing anywhere: each
/// names an endpoint on loopback that only Tiresias listens on, so using one is seen.
/// </summary>
public sealed record DecoyValues(string SqlUser, string SqlPassword, string AdminToken, string ApiKey);

/// <summary>Which decoy value a caller presented, for the activity log and the finding.</summary>
public enum DecoyUse
{
    /// <summary>Something connected to a decoy port without presenting a value (or one that couldn't be read).</summary>
    Connected,
    SqlPassword,
    AdminToken,
    ApiKey,
}

/// <summary>
/// The decoys of this install: their values, the two loopback ports they point to, and where each
/// was placed. Kept in <c>decoys.json</c> beside the keyring; a decoy value is worthless, so it is
/// stored as it is. Immutable.
/// </summary>
public sealed record DecoySet(int HttpPort, int SqlPort, DecoyValues Values, IReadOnlyList<PlacedDecoy> Placed)
{
    /// <summary>The file format; a change bumps it.</summary>
    public const int Version = 1;

    public const string FileName = "decoys.json";

    public string HttpUrl => $"http://127.0.0.1:{HttpPort}";

    /// <summary>Encrypt=False: the decoy listener speaks no TLS, and a client that insists on it is still seen connecting.</summary>
    public string ConnectionString =>
        $"Server=127.0.0.1,{SqlPort};Database=Billing;User Id={Values.SqlUser};Password={Values.SqlPassword};Encrypt=False";

    /// <summary>
    /// New values and ports for an install. Ports are random per install, so a decoy doesn't give
    /// Tiresias away by a fixed number; <paramref name="free"/> says whether a port can be listened on.
    /// </summary>
    public static DecoySet Mint(Func<int, bool> free)
    {
        var http = Port(free, except: 0);
        var sql = Port(free, except: http);
        return new(http, sql, new("billing_admin", Random(Alphabet + "!#%+", 20), Random(Alphabet, 48), "sk-proj-" + Random(Alphabet + "-_", 156)), []);
    }

    const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    static string Random(string alphabet, int length) => RandomNumberGenerator.GetString(alphabet, length);

    static int Port(Func<int, bool> free, int except)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            var port = RandomNumberGenerator.GetInt32(20000, 40000);
            if (port != except && free(port))
                return port;
        }
        throw new InvalidOperationException("No free loopback port found for the decoys.");
    }

    /// <summary>The decoy value in <paramref name="presented"/> (a header, a password), or <c>null</c> when it holds none.</summary>
    public DecoyUse? Recognise(string? presented)
    {
        if (string.IsNullOrEmpty(presented))
            return null;
        if (presented.Contains(Values.ApiKey, StringComparison.Ordinal))
            return DecoyUse.ApiKey;
        if (presented.Contains(Values.AdminToken, StringComparison.Ordinal))
            return DecoyUse.AdminToken;
        if (presented.Contains(Values.SqlPassword, StringComparison.Ordinal))
            return DecoyUse.SqlPassword;
        return null;
    }

    /// <summary>Whether a path is a decoy file or inside a decoy folder; the doctor skips these, so a decoy is never a finding to seal.</summary>
    public bool Covers(string path)
    {
        var full = Path.GetFullPath(path);
        return Placed.Any(p => p.Kind != DecoyKind.Variables
            && (SamePath(full, p.Where) || full.StartsWith(Path.TrimEndingDirectorySeparator(p.Where) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)));
    }

    static bool SamePath(string a, string b) =>
        string.Equals(Path.TrimEndingDirectorySeparator(a), Path.TrimEndingDirectorySeparator(b), StringComparison.OrdinalIgnoreCase);

    public DecoySet With(PlacedDecoy placed) => this with { Placed = [.. Placed, placed] };

    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public string ToJson() => JsonSerializer.Serialize(new File(Version, HttpPort, SqlPort, Values, [.. Placed]), Json);

    /// <returns><c>null</c> for no file, a damaged one, or one from a newer Tiresias.</returns>
    public static DecoySet? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;
        try
        {
            var file = JsonSerializer.Deserialize<File>(json, Json);
            if (file is not { V: Version, Values: { } values } || file.HttpPort <= 0 || file.SqlPort <= 0)
                return null;
            return new(file.HttpPort, file.SqlPort, values, [.. (file.Placed ?? []).Where(p => !string.IsNullOrEmpty(p.Where))]);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    sealed record File(int V, int HttpPort, int SqlPort, DecoyValues? Values, PlacedDecoy[]? Placed);
}
