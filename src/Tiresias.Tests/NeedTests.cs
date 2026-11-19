using NUnit.Framework;
using Tiresias.Client;

namespace Tiresias.Tests;

public class NeedCatalogTests
{
    static IEnumerable<NeedOption> AllOptions => NeedCatalog.Needs.SelectMany(n => n.Options);

    [Test]
    public void Every_need_has_an_option() =>
        Assert.That(NeedCatalog.Needs, Has.All.Matches<Need>(n => n.Options.Count > 0));

    [Test]
    public void Ids_are_unique() => Assert.Multiple(() =>
    {
        Assert.That(NeedCatalog.Needs.Select(n => n.Id), Is.Unique);
        foreach (var need in NeedCatalog.Needs)
            Assert.That(need.Options.Select(o => o.Id), Is.Unique, need.Id);
    });

    [Test]
    public void Only_the_strongest_option_of_a_need_gives_nothing_up() => Assert.Multiple(() =>
    {
        foreach (var need in NeedCatalog.Needs)
        {
            var ranked = NeedCatalog.Rank(need, new(HasBroker: true));
            Assert.That(ranked[0].Option.GivesUp, Is.Null, need.Id);
            Assert.That(ranked.Skip(1).Select(r => r.Option.GivesUp), Has.All.Not.Null.And.Not.Empty, need.Id);
        }
    });

    [Test]
    public void No_two_needs_or_services_claim_the_same_phrase()
    {
        var phrases = NeedCatalog.Needs.SelectMany(n => n.Phrases)
            .Concat(NeedCatalog.Services.SelectMany(s => s.Aliases))
            .Select(p => string.Join(' ', NeedMatcher.Tokens(p)));
        Assert.That(phrases, Is.Unique);
    }

    [Test]
    public void No_phrase_is_only_stop_words() =>
        Assert.That(NeedCatalog.Needs.SelectMany(n => n.Phrases).Concat(NeedCatalog.Services.SelectMany(s => s.Aliases)),
            Has.All.Matches<string>(p => NeedMatcher.Tokens(p).Count > 0));

    [Test]
    public void Every_known_service_points_at_an_option() => Assert.Multiple(() =>
    {
        foreach (var service in NeedCatalog.Services)
            Assert.That(NeedCatalog.Find(service.NeedId).Options.Select(o => o.Id), Does.Contain(service.OptionId), service.Name);
    });

    [Test]
    public void An_option_without_a_secret_is_a_guide_and_a_guide_needs_no_broker() => Assert.Multiple(() =>
    {
        foreach (var option in AllOptions.Where(o => o.Position.Exposure == Exposure.NothingToCopy))
            Assert.That(option.Action, Is.TypeOf<FollowGuide>(), option.Id);
        foreach (var option in AllOptions.Where(o => o.Action is FollowGuide))
            Assert.That(option.NeedsBroker, Is.False, option.Id);
    });

    [Test]
    public void An_option_that_stores_a_service_needs_a_broker() =>
        Assert.That(AllOptions.Where(o => o.Action is AddService), Has.All.Matches<NeedOption>(o => o.NeedsBroker));

    [Test]
    public void Every_guide_names_a_row_of_the_page() => Assert.Multiple(() =>
    {
        var page = File.ReadAllText(Path.Combine(RepoRoot(), FollowGuide.Page));
        foreach (var guide in AllOptions.Select(o => o.Action).OfType<FollowGuide>().Distinct())
            Assert.That(page, Does.Contain($"**{guide.Topic}**"), guide.Topic);
    });

    [Test]
    public void Every_action_says_what_to_do() =>
        Assert.That(AllOptions.Select(o => o.Action.Instruction), Has.All.Not.Empty);

    [Test]
    public void Options_that_lead_to_the_same_place_are_the_same_value()
    {
        var git = NeedCatalog.Find("git").Options.Single(o => o.Id == "app-token").Action;
        var cli = NeedCatalog.Find("cli-sign-in").Options.Single(o => o.Id == "exec-token").Action;

        Assert.That(git, Is.EqualTo(cli));
    }

    static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(TestContext.CurrentContext.TestDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "Tiresias.slnx")))
                return dir.FullName;
        throw new DirectoryNotFoundException("Tiresias.slnx not found above the test directory.");
    }
}

public class OptionRankingTests
{
    static NeedOption Option(string id, Exposure exposure, Control control, bool needsBroker = false) =>
        new(id, id, id, new(exposure, control), new SealVariable(), NeedsBroker: needsBroker);

    static Need NeedOf(params NeedOption[] options) => new("test", "Test", ["test"], options);

    static string[] Ids(IEnumerable<RankedOption> ranked) => [.. ranked.Select(r => r.Option.Id)];

    [Test]
    public void Control_ranks_before_exposure()
    {
        var need = NeedOf(Option("identity", Exposure.NothingToCopy, Control.Silent), Option("placeholder", Exposure.BrokerOnly, Control.Approved));

        Assert.That(Ids(NeedCatalog.Rank(need, new(true))), Is.EqualTo(new[] { "placeholder", "identity" }));
    }

    [Test]
    public void Within_a_control_the_lower_exposure_ranks_first()
    {
        var need = NeedOf(Option("sealed", Exposure.Sealed, Control.Approved), Option("lease", Exposure.ShortLived, Control.Approved),
            Option("recorded", Exposure.NothingToCopy, Control.Recorded));

        Assert.That(Ids(NeedCatalog.Rank(need, new(true))), Is.EqualTo(new[] { "lease", "sealed", "recorded" }));
    }

    [Test]
    public void Ties_keep_catalogue_order()
    {
        var need = NeedOf(Option("b", Exposure.Sealed, Control.Approved), Option("a", Exposure.Sealed, Control.Approved));

        Assert.That(Ids(NeedCatalog.Rank(need, new(true))), Is.EqualTo(new[] { "b", "a" }));
    }

    [Test]
    public void The_recommended_option_is_the_first_available()
    {
        var need = NeedOf(Option("lease", Exposure.ShortLived, Control.Approved, needsBroker: true), Option("sealed", Exposure.Sealed, Control.Approved));

        var ranked = NeedCatalog.Rank(need, new(HasBroker: false));

        Assert.That(Ids(ranked), Is.EqualTo(new[] { "lease", "sealed" }), "an unavailable option keeps its place");
        Assert.That(ranked[0], Has.Property(nameof(RankedOption.Recommended)).False.And.Property(nameof(RankedOption.Unavailable)).Not.Null);
        Assert.That(ranked[1], Has.Property(nameof(RankedOption.Recommended)).True.And.Property(nameof(RankedOption.Unavailable)).Null);
    }

    [Test]
    public void Exactly_one_option_is_recommended_when_any_is_available()
    {
        var ranked = NeedCatalog.Rank(NeedCatalog.Find("database"), new(true));

        Assert.That(ranked.Count(r => r.Recommended), Is.EqualTo(1));
        Assert.That(ranked[0].Recommended, Is.True);
    }

    [Test]
    public void Nothing_is_recommended_when_nothing_is_available()
    {
        var need = NeedOf(Option("lease", Exposure.ShortLived, Control.Approved, needsBroker: true));

        Assert.That(NeedCatalog.Rank(need, new(false)).Single().Recommended, Is.False);
    }

    [Test]
    public void A_placeholder_ranks_above_an_identity_any_program_can_use()
    {
        var ranked = Ids(NeedCatalog.Rank(NeedCatalog.Find("api-key"), new(true)));

        Assert.That(Array.IndexOf(ranked, "placeholder"), Is.LessThan(Array.IndexOf(ranked, "identity")));
    }
}

public class NeedMatcherTests
{
    static string[] Needs(string text) => [.. NeedMatcher.Match(text).Select(m => m.Need.Id)];

    [TestCase("database", "database")]
    [TestCase("my connection string", "database")]
    [TestCase("OpenAI key for a script", "api-key")]
    [TestCase("ravendb", "database")]
    [TestCase("publish to nuget", "publish")]
    [TestCase("gh", "cli-sign-in")]
    [TestCase("git push", "git")]
    [TestCase("secrets.json", "project-secrets")]
    [TestCase("command-line tool", "cli-key")]
    public void Finds_the_need(string text, string need) =>
        Assert.That(Needs(text)[0], Is.EqualTo(need));

    [Test]
    public void A_partial_word_finds_the_need_but_scores_less()
    {
        Assert.That(Needs("datab")[0], Is.EqualTo("database"));
        Assert.That(NeedMatcher.Match("datab")[0].Score, Is.LessThan(NeedMatcher.Match("database")[0].Score));
    }

    [Test]
    public void Two_letters_never_match_as_a_start() =>
        Assert.That(NeedMatcher.Match("da").All(m => m.Score == 0), Is.True);

    [Test]
    public void A_phrase_of_several_words_needs_all_of_them()
    {
        Assert.That(NeedMatcher.Match("connection").All(m => m.Score == 0), Is.True);
        Assert.That(Needs("connection string")[0], Is.EqualTo("database"));
    }

    [Test]
    public void A_named_service_preselects_its_option()
    {
        var match = NeedMatcher.Match("my EF Core app talks to Azure SQL")[0];

        Assert.That((match.Need.Id, match.Preselect), Is.EqualTo(("database", "sql-lease")));
        Assert.That(NeedMatcher.Match("RavenDB")[0].Preselect, Is.EqualTo("raven"));
        Assert.That(NeedMatcher.Match("a database")[0].Preselect, Is.Null);
    }

    [TestCase("")]
    [TestCase("   ")]
    [TestCase("the and of")]
    [TestCase("xyzzy")]
    public void Nothing_matched_returns_the_whole_catalogue(string text)
    {
        Assert.That(Needs(text), Is.EqualTo(NeedCatalog.Needs.Select(n => n.Id)));
        Assert.That(NeedMatcher.Match(text).Select(m => m.Score), Has.All.Zero);
    }

    [Test]
    public void Needs_are_ordered_by_score_then_catalogue()
    {
        var scores = NeedMatcher.Match("OpenAI key for a script").Select(m => m.Score).ToArray();

        Assert.That(scores, Is.Ordered.Descending);
        Assert.That(scores, Has.All.Positive);
    }

    [Test]
    public void The_same_text_gives_the_same_order()
    {
        var first = Needs("sql key token git");

        Assert.That(Needs("sql key token git"), Is.EqualTo(first));
    }

    [Test]
    public void Tokens_are_lowercase_words_without_stop_words() =>
        Assert.That(NeedMatcher.Tokens("My EF-Core app, for SQL!"), Is.EqualTo(new[] { "ef", "core", "sql" }));
}

public class NeedViewTests
{
    [Test]
    public void Every_option_has_a_button_in_the_app() => Assert.Multiple(() =>
    {
        foreach (var option in NeedCatalog.Needs.SelectMany(n => n.Options))
            Assert.That(() => Tiresias.App.Logic.NeedView.Button(option.Action), Throws.Nothing, option.Id);
    });

    [Test]
    public void A_guide_opens_the_page_and_a_service_kind_its_window() => Assert.Multiple(() =>
    {
        Assert.That(Tiresias.App.Logic.NeedView.Button(new FollowGuide("Passkeys")).Step, Is.EqualTo(Tiresias.App.Logic.NeedStep.OpenGuide));
        Assert.That(Tiresias.App.Logic.NeedView.Button(new AddService(ServiceKind.SqlServer)).Step, Is.EqualTo(Tiresias.App.Logic.NeedStep.SetUpSqlServer));
        Assert.That(Tiresias.App.Logic.NeedView.Button(new AddService(ServiceKind.RavenDb)).Step, Is.EqualTo(Tiresias.App.Logic.NeedStep.SetUpRaven));
        Assert.That(Tiresias.App.Logic.NeedView.GuideUrl("https://github.com/example/repo"), Is.EqualTo("https://github.com/example/repo/blob/main/docs/avoid-secrets.md"));
    });

    [Test]
    public void Only_a_search_that_found_something_opens_the_first_need()
    {
        var found = NeedMatcher.Match("sql");
        var nothing = NeedMatcher.Match("");

        Assert.That(Tiresias.App.Logic.NeedView.Expanded(0, found[0]), Is.True);
        Assert.That(found.Skip(1).Select((m, i) => Tiresias.App.Logic.NeedView.Expanded(i + 1, m)), Has.All.False);
        Assert.That(Tiresias.App.Logic.NeedView.Expanded(0, nothing[0]), Is.False);
    }
}
