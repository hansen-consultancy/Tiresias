using System.Net.Http.Headers;
using System.Text;
using Tiresias.Client;

namespace Tiresias.Agent;

/// <summary>
/// The opt-in online lookups (docs/attack-surface.md#trust): their answers on disk,
/// <c>trust-lookups.json</c> beside the keyring. The file exists only while lookups are on, so the
/// checks and <c>tir doctor</c> read <c>null</c> once the user turns them off.
/// </summary>
public static class TrustLookupStore
{
    static readonly Lock gate = new();

    static string FilePath => Path.Combine(KeyringStore.Directory, "trust-lookups.json");

    /// <summary>The saved answers; <c>null</c> while lookups are off. A damaged file reads as on, with nothing asked yet.</summary>
    public static TrustLookups? Load()
    {
        lock (gate)
        {
            try
            {
                return File.Exists(FilePath) ? TrustLookups.Parse(File.ReadAllText(FilePath)) ?? TrustLookups.Empty : null;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Asks OSV.dev about the global tools whose answer is a day old or missing and saves what it said.
    /// Sends each tool's ecosystem, name and version, nothing else. Asking takes seconds, and the user
    /// may turn lookups off meanwhile: <paramref name="stillOn"/> is asked again under the lock that
    /// <see cref="Clear"/> takes, so answers are never saved after they were deleted.
    /// </summary>
    /// <returns>The answers, or <c>null</c> when lookups were off by the time they came.</returns>
    public static async Task<TrustLookups?> RefreshAsync(IEnumerable<GlobalTool> tools, Func<bool> stillOn, CancellationToken cancellationToken = default)
    {
        var refreshed = await (Load() ?? TrustLookups.Empty).RefreshAsync(tools, OsvSource.Instance, DateTimeOffset.UtcNow, cancellationToken);
        return Save(refreshed, stillOn) ? refreshed : null;
    }

    /// <summary>Turns lookups off: the saved answers go, so no finding stands on them.</summary>
    public static void Clear()
    {
        lock (gate)
        {
            try
            {
                File.Delete(FilePath);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Still there: the next turn off tries again.
            }
        }
    }

    /// <summary>A unique temporary name: the app and <c>tir</c> may both be writing.</summary>
    /// <returns>Whether lookups were still on.</returns>
    static bool Save(TrustLookups lookups, Func<bool> stillOn)
    {
        lock (gate)
        {
            if (!stillOn())
                return false;
            try
            {
                Directory.CreateDirectory(KeyringStore.Directory);
                var temp = $"{FilePath}.{Guid.NewGuid():N}.tmp";
                File.WriteAllText(temp, lookups.ToJson());
                File.Move(temp, FilePath, overwrite: true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // Not saved: the next refresh asks again.
            }
            return true;
        }
    }

    /// <summary>OSV.dev's query API over HTTPS. A demo never goes online.</summary>
    sealed class OsvSource : IAdvisorySource
    {
        public static readonly OsvSource Instance = new();

        static readonly HttpClient http = Client();

        static HttpClient Client()
        {
            var client = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("Tiresias", null));
            return client;
        }

        public async Task<IReadOnlyList<Advisory>?> AdvisoriesAsync(PackageQuery package, CancellationToken cancellationToken)
        {
            if (DemoMode.On)
                return null;
            try
            {
                using var content = new StringContent(Osv.QueryJson(package), Encoding.UTF8, "application/json");
                using var response = await http.PostAsync(Osv.QueryUrl, content, cancellationToken);
                return response.IsSuccessStatusCode ? Osv.Parse(await response.Content.ReadAsStringAsync(cancellationToken), package) : null;
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
            {
                return null;
            }
        }
    }
}
