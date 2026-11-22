namespace Tiresias.AdminTier;

public sealed partial record AdminBlocks
{
    /// <summary>Reads the service's path-ordered pages. An interrupted or inconsistent reply cannot appear as a complete blocklist.</summary>
    public static async Task<IReadOnlyList<AdminBlockedProgram>?> ReadAllAsync(Func<string?, Task<AdminBlocks?>> readPage)
    {
        var programs = new List<AdminBlockedProgram>();
        string? after = null;
        while (await readPage(after).ConfigureAwait(false) is { Programs: not null } page)
        {
            foreach (var program in page.Programs)
            {
                if (string.IsNullOrEmpty(program?.Path) || StringComparer.OrdinalIgnoreCase.Compare(program.Path, after) <= 0)
                    return null;
                programs.Add(program);
                after = program.Path;
            }
            if (page.NextAfter is null)
                return programs;
            if (page.Programs.Count == 0 || !StringComparer.OrdinalIgnoreCase.Equals(page.NextAfter, after))
                return null;
        }
        return null;
    }
}
