using System.Text.Json;
using Tiresias.EnvironmentVariables;

namespace Tiresias.Keyring;

/// <summary>One standalone command's release. Only authenticated delivery terms are displayed or recorded.</summary>
internal static class StandaloneEnvironmentConsent
{
    public static async Task<Delivery?> RequestAsync(IReadOnlyList<string> commandLine, IReadOnlyList<string> terms,
        Func<string, bool> confirm, Func<Task<Delivery>> deliver, Action<bool> record)
    {
        if (terms.Count > 0)
        {
            // Quote each argument, including embedded line breaks, so it cannot become part of the list of variables.
            var command = string.Join(' ', commandLine.Select(arg => JsonSerializer.Serialize(arg)));
            var message = $"Allow this command to receive these variables once?\n\n{command}\n\n{string.Join("\n", terms)}";
            if (!confirm(message))
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
