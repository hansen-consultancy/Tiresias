using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using Tiresias.Agent;
using Tiresias.App.Logic;
using Tiresias.Client;

namespace Tiresias.App.Views;

/// <summary>
/// <i>What do you need?</i>: the app's one way to add anything. The user picks a need, or types
/// one, and gets every way to meet it strongest first (<see cref="NeedCatalog"/>, the same advice
/// as <c>tir advise</c>). An option opens the window that does the work, or a guide when there is
/// nothing for Tiresias to hold. What is typed is matched here and never leaves the machine.
/// </summary>
public partial class NeedsWindow : Window
{
    readonly NeedsViewModel model = new(new NeedFacts(HasBroker: KeyringStore.Broker is not null));

    public NeedsWindow()
    {
        InitializeComponent();
        DataContext = model;
    }

    void OnClose(object sender, RoutedEventArgs e) => Close();

    void OnChoose(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).DataContext is not OptionRow { IsAvailable: true } row)
            return;
        var (step, _) = NeedView.Button(row.Option.Action);
        AppLog.Info($"what do you need: {row.Option.Id}");
        if (step == NeedStep.OpenGuide)
        {
            Desktop.Open(NeedView.GuideUrl(AppBuild.Repository));
            return;
        }
        Close();
        if (HomeAreas.Of(step) is { } area)
            Home.Open(area);
        switch (step)
        {
            case NeedStep.AddService:
                App.Current.ShowPage<ServicesPage>()?.Add((row.Option.Action as AddService)?.Upstream);
                break;
            case NeedStep.SetUpSqlServer:
                App.Current.ShowPage<ServicesPage>()?.SetUpSqlServer();
                break;
            case NeedStep.SetUpRaven:
                App.Current.ShowPage<ServicesPage>()?.SetUpRaven();
                break;
            case NeedStep.OpenEnvironment:
                App.Current.ShowPage<EnvironmentPage>();
                break;
            case NeedStep.OpenSecrets:
                App.Current.ShowPage<SecretsPage>();
                break;
        }
    }
}

public sealed partial class NeedsViewModel(NeedFacts facts) : ObservableObject
{
    public ObservableCollection<NeedRow> Needs { get; } = [.. Rows(NeedMatcher.Match(""), facts)];

    [ObservableProperty]
    public partial string Search { get; set; } = "";

    partial void OnSearchChanged(string value)
    {
        Needs.Clear();
        foreach (var row in Rows(NeedMatcher.Match(value), facts))
            Needs.Add(row);
    }

    static IEnumerable<NeedRow> Rows(IReadOnlyList<NeedMatch> matches, NeedFacts facts) =>
        matches.Select((match, index) => new NeedRow(match, NeedCatalog.Rank(match.Need, facts)) { IsExpanded = NeedView.Expanded(index, match) });
}

public sealed partial class NeedRow(NeedMatch match, IReadOnlyList<RankedOption> ranked) : ObservableObject
{
    public string Title => match.Need.Title;

    public IReadOnlyList<OptionRow> Options { get; } = [.. ranked.Select(r => new OptionRow(r, named: r.Option.Id == match.Preselect))];

    [ObservableProperty]
    public partial bool IsExpanded { get; set; }
}

public sealed class OptionRow(RankedOption ranked, bool named)
{
    public NeedOption Option => ranked.Option;

    public string Title => Option.Title;

    /// <summary>The option's position in words, such as "Stays in Tiresias, asks you".</summary>
    public string Position => PositionText.Short(Option.Position);

    public string PositionMeaning => PositionText.Meaning(Option.Position, null);

    public string Summary => Option.Summary;

    public string GivesUp => Option.GivesUp is { } givesUp ? Text.Format("Needs_GivesUp", givesUp) : "";

    public string Unavailable => ranked.Unavailable ?? "";

    public bool IsAvailable => ranked.Unavailable is null;

    /// <summary>Recommended wins over "you named it": the recommendation is the point of the list.</summary>
    public string Badge => ranked.Recommended ? Text.Get("Needs_Recommended") : named ? Text.Get("Needs_Named") : "";

    public string ActionLabel => Text.Get(NeedView.Button(Option.Action).Label);

    public string ActionName => Text.Format("Needs_ActionName", ActionLabel, Title);

    public string Spoken => string.Join(" ", new[] { Title, Position, Badge, Summary, GivesUp, Unavailable }.Where(s => s.Length > 0));
}
