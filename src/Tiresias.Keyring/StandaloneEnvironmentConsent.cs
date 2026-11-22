using Tiresias.EnvironmentVariables;

namespace Tiresias.Keyring;

/// <summary>One standalone command's release after a decision on its authenticated delivery terms.</summary>
internal static class StandaloneEnvironmentConsent
{
    public static async Task<Delivery?> RequestAsync(IReadOnlyList<string> commandLine, IReadOnlyList<string> terms,
        Func<IReadOnlyList<string>, IReadOnlyList<string>, Task<bool>> confirm, Func<Task<Delivery>> deliver, Action<bool> record)
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
                record(false);
                throw new InvalidOperationException("The Tiresias consent dialog was unavailable. The command was stopped.");
            }
            if (!approved)
            {
                record(false);
                return null;
            }
        }
        var delivery = await deliver();
        record(true);
        return delivery;
    }
}
