using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>
/// A position in words (docs/app-design.md, rule 4). The app never shows <c>E5/C3</c>: it says
/// "Readable, unchecked", with a tooltip saying what each word means. The codes stay in <c>tir</c>,
/// the docs and Copy details.
/// </summary>
public static class PositionWords
{
    /// <summary>The short word for each axis, then the sentence its tooltip shows.</summary>
    public static (string Word, string Meaning) Of(Exposure exposure) => exposure switch
    {
        Exposure.NothingToCopy => ("Position_NothingToCopy", "Position_NothingToCopyTip"),
        Exposure.ShortLived => ("Position_ShortLived", "Position_ShortLivedTip"),
        Exposure.BrokerOnly => ("Position_BrokerOnly", "Position_BrokerOnlyTip"),
        Exposure.Sealed => ("Position_Sealed", "Position_SealedTip"),
        _ => ("Position_Readable", "Position_ReadableTip"),
    };

    public static (string Word, string Meaning) Of(Control control) => control switch
    {
        Control.Approved => ("Position_Approved", "Position_ApprovedTip"),
        Control.Recorded => ("Position_Recorded", "Position_RecordedTip"),
        _ => ("Position_Silent", "Position_SilentTip"),
    };
}
