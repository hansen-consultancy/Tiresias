using Tiresias.EnvironmentVariables;

namespace Tiresias.Keyring;

/// <summary>One standalone command's release after a decision on its authenticated delivery terms.</summary>
internal static class StandaloneEnvironmentConsent
{
    const string DialogUnavailable = "The Tiresias consent dialog was unavailable.";

    public static async Task<Delivery?> RequestAsync(IReadOnlyList<string> commandLine, IReadOnlyList<string> terms,
        Func<IReadOnlyList<string>, IReadOnlyList<string>, Task<bool>> confirm, Func<Task<Delivery>> deliver, Action<bool, string?> record)
    {
        if (terms.Count > 0)
        {
            bool approved;
            try
            {
                approved = await confirm(commandLine, terms);
            }
            catch (Exception)
            {
                record(false, DialogUnavailable);
                throw new InvalidOperationException(DialogUnavailable + " The command was stopped.");
            }
            if (!approved)
            {
                record(false, null);
                return null;
            }
        }
        var delivery = await deliver();
        record(true, null);
        return delivery;
    }
}
