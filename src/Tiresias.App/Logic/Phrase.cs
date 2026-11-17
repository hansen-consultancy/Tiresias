namespace Tiresias.App.Logic;

/// <summary>
/// A sentence for the user, by its key in <c>Strings.resx</c> plus the values it is formatted with.
/// The decisions in this folder return phrases rather than text, so every word the app shows is in
/// that one file, and a test checks that each key used exists there.
/// </summary>
public sealed record Phrase(string Key, params object?[] Args);
