using Tiresias.Client;

namespace Tiresias.App.Logic;

/// <summary>Enrollment can be retried with the same paper until the administrator approves it.</summary>
internal sealed class FirstRunPaper
{
    readonly IReadOnlyList<string> words;
    readonly Action enroll;

    public FirstRunPaper(byte[] paper, Action enroll)
    {
        words = PaperKey.Words(paper);
        Challenge = PaperKey.Challenge(words.Count);
        this.enroll = enroll;
    }

    public (int First, int Second) Challenge { get; }

    public bool TryEnroll(string first, string second)
    {
        if (!PaperKey.Confirm(words, Challenge, first, second))
            return false;
        enroll();
        return true;
    }
}
