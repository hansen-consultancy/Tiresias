namespace Tiresias.Client;

/// <summary>
/// Who stands behind installed code, as far as Tiresias can check it: the subject of a valid
/// Authenticode signature, or an extension's marketplace publisher id. Never a name the code states
/// about itself (an uninstall entry's <c>Publisher</c>, an extension's display name, a signature that
/// doesn't verify), since anyone can write any name there. Trust is given to a <see cref="Key"/>.
/// </summary>
/// <param name="Key">What trust matches: <c>signer:</c> and the certificate's whole subject, or <c>marketplace:</c> and the publisher id.</param>
/// <param name="Name">What the user is shown.</param>
public sealed record Publisher(string Key, string Name)
{
    /// <summary>
    /// The signer of a file whose signature verified. The whole subject (organisation, place, country),
    /// not its common name alone, so another company with the same name is another publisher; and not
    /// the certificate's thumbprint, which changes at every yearly renewal.
    /// </summary>
    public static Publisher Signed(string subject, string? name) =>
        new("signer:" + subject, string.IsNullOrWhiteSpace(name) ? subject : name);

    /// <summary>An extension's marketplace publisher, by the id the marketplace gave it; none when the id isn't known.</summary>
    public static Publisher? Marketplace(string? id, string? name) =>
        string.IsNullOrWhiteSpace(id) ? null : new("marketplace:" + id, string.IsNullOrWhiteSpace(name) ? id : name);
}

/// <summary>A publisher the user trusts, and since when.</summary>
public sealed record TrustedPublisher(string Key, string Name, DateTimeOffset At);
