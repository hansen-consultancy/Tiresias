using Tiresias.App.Logic;

namespace Tiresias.Tests;

public class CaptureRuleTests
{
    [TestCase("1", ExpectedResult = true)]
    [TestCase(null, ExpectedResult = false)]
    [TestCase("", ExpectedResult = false)]
    [TestCase("0", ExpectedResult = false)]
    [TestCase("true", ExpectedResult = false)]
    [TestCase(" 1", ExpectedResult = false)]
    public bool Only_exactly_1_asks_for_capture(string? variable) => CaptureRule.Allowed(variable);

    [TestCase(false, false, ExpectedResult = true)]
    [TestCase(false, true, ExpectedResult = true)]
    [TestCase(true, true, ExpectedResult = true)]
    [TestCase(true, false, ExpectedResult = false)]
    public bool A_window_is_capturable_only_when_allowed_and_showing_no_values(bool captureAllowed, bool showsValues) =>
        CaptureRule.Excluded(captureAllowed, showsValues);
}
