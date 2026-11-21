using Tiresias.AdminTier;

namespace Tiresias.App.Logic;

public enum AdminTierAction
{
    /// <summary>Runs the install step: sets it up, or sets it up again when stopped (it repairs and starts it).</summary>
    SetUp,
    /// <summary>The same install step, offered as such when the service is older than the app.</summary>
    Update,
    Remove,
}

/// <summary>The admin tier on the About page: what state it is in, in words, and what can be done about it.</summary>
public static class AdminTierCard
{
    public static Phrase Describe(AdminTierFacts tier) => tier.State switch
    {
        AdminTierState.NotInstalled => new("About_AdminTier_NotInstalled"),
        AdminTierState.Stopped => new("About_AdminTier_Stopped"),
        AdminTierState.NotAnswering => new("About_AdminTier_NotAnswering"),
        AdminTierState.Older => new("About_AdminTier_Older", tier.Status!.Version, tier.AppVersion),
        _ => new("About_AdminTier_Running", tier.Status!.Version),
    };

    public static IReadOnlyList<AdminTierAction> Actions(AdminTierState state) => state switch
    {
        AdminTierState.NotInstalled => [AdminTierAction.SetUp],
        AdminTierState.Older => [AdminTierAction.Update, AdminTierAction.Remove],
        AdminTierState.Stopped or AdminTierState.NotAnswering => [AdminTierAction.SetUp, AdminTierAction.Remove],
        _ => [AdminTierAction.Remove],
    };

    /// <summary>What came of the elevated step; <paramref name="result"/> is <c>null</c> when the UAC prompt was declined.</summary>
    public static Phrase Outcome(AdminSetupResult? result, bool removing) => result switch
    {
        null => new("AdminTier_Declined"),
        AdminSetupResult.Done => new(removing ? "AdminTier_Removed" : "AdminTier_SetUp"),
        AdminSetupResult.FilesMissing => new("AdminTier_FilesMissing"),
        AdminSetupResult.DidNotStart => new("AdminTier_DidNotStart"),
        _ => new("AdminTier_Failed", (int)result),
    };
}
