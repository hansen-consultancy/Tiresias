using System.Globalization;
using System.Resources;
using System.Windows.Markup;
using Tiresias.App.Logic;

namespace Tiresias.App;

/// <summary>
/// Every string the app shows comes from <c>Strings.resx</c> through here: <see cref="Get"/> in code,
/// <c>{l:S Key}</c> in XAML. A test checks that each key used in the app exists and each key in the
/// file is used.
/// </summary>
public static class Text
{
    static readonly ResourceManager Resources = new("Tiresias.App.Strings", typeof(Text).Assembly);

    public static string Get(string key) => Resources.GetString(key, CultureInfo.CurrentUICulture) ?? key;

    public static string Format(string key, params object?[] args) => string.Format(CultureInfo.CurrentCulture, Get(key), args);

    /// <summary>A phrase's text; an argument that is itself a phrase is put in words first.</summary>
    public static string Of(Phrase phrase) =>
        phrase.Args.Length == 0 ? Get(phrase.Key) : Format(phrase.Key, [.. phrase.Args.Select(a => a is Phrase inner ? Of(inner) : a)]);
}

/// <summary><c>{l:S Key}</c>: a string from <c>Strings.resx</c> in XAML.</summary>
[MarkupExtensionReturnType(typeof(string))]
public sealed class S(string key) : MarkupExtension
{
    public string Key { get; set; } = key;

    public override object ProvideValue(IServiceProvider serviceProvider) => Text.Get(Key);
}
