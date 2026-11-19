namespace Tiresias.Client;

/// <summary>What can escape from a credential's delivery, and whether it works elsewhere once it has (docs/guided-setup.md). Lower is stronger.</summary>
public enum Exposure
{
    /// <summary>The service accepts an identity; no reusable secret exists.</summary>
    NothingToCopy = 1,

    /// <summary>Minted for this lease or run and expires with it.</summary>
    ShortLived = 2,

    /// <summary>The broker holds the secret; the program gets something useless elsewhere.</summary>
    BrokerOnly = 3,

    /// <summary>Encrypted at rest, given to the program as its value.</summary>
    Sealed = 4,

    /// <summary>Anything running as the user can read it.</summary>
    Readable = 5,
}

/// <summary>Which programs on this device may use a credential, and whether anyone sees or approves each use. Lower is stronger.</summary>
public enum Control
{
    /// <summary>Use needs the user's consent, naming the program; every use is recorded.</summary>
    Approved = 1,

    /// <summary>Every use is recorded, but nothing asks.</summary>
    Recorded = 2,

    /// <summary>Any program running as the user can use it, unrecorded.</summary>
    Silent = 3,
}

/// <summary>Where a delivery sits on both axes, written as on the design page: <c>E5/C3</c>.</summary>
public readonly record struct Position(Exposure Exposure, Control Control)
{
    /// <summary>A plaintext file or variable: readable and usable by anything running as the user.</summary>
    public static readonly Position Plaintext = new(Exposure.Readable, Control.Silent);

    /// <summary>Sealed by Tiresias and handed out after consent.</summary>
    public static readonly Position SealedApproved = new(Exposure.Sealed, Control.Approved);

    public override string ToString() => $"E{(int)Exposure}/C{(int)Control}";
}
