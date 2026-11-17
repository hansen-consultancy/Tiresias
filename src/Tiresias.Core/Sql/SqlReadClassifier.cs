namespace Tiresias.Sql;

/// <param name="Reason">Why the batch is not provably a read; <c>null</c> when it is.</param>
public sealed record SqlClassification(string? Reason)
{
    public bool IsRead => Reason is null;
}

/// <summary>
/// Decides whether a T-SQL batch is provably <b>one read-only SELECT</b>, for a <c>read</c> grant.
/// It refuses whatever it can't prove, including reads it doesn't understand: a false refusal costs
/// a retry on a write grant, a false allow costs data.
/// </summary>
/// <remarks>
/// <para>Not a parser. It lexes the batch (comments, strings, quoted identifiers) and then requires:
/// the batch starts with <c>SELECT</c> or <c>WITH</c>; no bare word from a deny list appears anywhere
/// (every statement keyword but SELECT/WITH, <c>INTO</c>, <c>EXEC</c>, the <c>OPEN*</c> rowset
/// functions, <c>xp_</c>/<c>sp_</c> procedures, <c>NEXT VALUE FOR</c>, which advances a sequence);
/// only one top-level SELECT, apart from <c>UNION</c>/<c>EXCEPT</c>/<c>INTERSECT</c> arms; no
/// semicolon but leading or trailing ones; balanced parentheses; no ODBC <c>{...}</c> escapes.</para>
/// <para>T-SQL needs no semicolon between statements, so "one statement" rests on the deny list:
/// a second statement must start with a keyword, and every keyword that can start one is denied
/// except SELECT and WITH, whose second top-level occurrence is refused.</para>
/// <para>It is a guard against accidents and a careless agent, not the boundary. The boundary is
/// the temporary login's role (<c>tir_read</c> = <c>db_datareader</c>), and the broker also runs a
/// read in a transaction it rolls back.</para>
/// </remarks>
public static class SqlReadClassifier
{
    static readonly HashSet<string> Denied = new(StringComparer.OrdinalIgnoreCase)
    {
        // Statements other than SELECT / WITH.
        "ADD", "ALTER", "BACKUP", "BEGIN", "BREAK", "BULK", "CHECKPOINT", "CLOSE", "COMMIT", "CONTINUE",
        "CREATE", "DBCC", "DEALLOCATE", "DECLARE", "DELETE", "DENY", "DISABLE", "DROP", "DUMP", "ENABLE",
        "EXEC", "EXECUTE", "GET", "GO", "GOTO", "GRANT", "IF", "INSERT", "KILL", "LOAD", "MERGE", "MOVE",
        "OPEN", "PRINT", "RAISERROR", "READTEXT", "RECEIVE", "RECONFIGURE", "RESTORE", "RETURN", "REVERT",
        "REVOKE", "ROLLBACK", "SAVE", "SEND", "SET", "SETUSER", "SHUTDOWN", "THROW", "TRUNCATE", "UPDATE",
        "UPDATETEXT", "USE", "WAITFOR", "WHILE", "WRITETEXT",
        // Writes or side effects inside a SELECT.
        "INTO", "OUTPUT", "CURSOR", "TRAN", "TRANSACTION",
        // Reach outside the database: other servers, files, providers.
        "OPENROWSET", "OPENQUERY", "OPENDATASOURCE", "OPENXML",
    };

    static readonly HashSet<string> SetOperators = new(StringComparer.OrdinalIgnoreCase) { "UNION", "EXCEPT", "INTERSECT", "ALL" };

    public static SqlClassification Classify(string sql)
    {
        if (Lex(sql, out var tokens) is { } lexError)
            return new(lexError);

        var start = 0;
        var end = tokens.Count;
        while (start < end && tokens[start].Is(";"))
            start++;
        while (end > start && tokens[end - 1].Is(";"))
            end--;
        if (start == end)
            return new("empty batch");

        var first = tokens[start];
        if (!first.IsWord("SELECT") && !first.IsWord("WITH"))
            return new("does not start with SELECT or WITH");

        var depth = 0;
        var topLevelSelects = 0;
        for (var i = start; i < end; i++)
        {
            var token = tokens[i];
            switch (token.Kind)
            {
                case TokenKind.Symbol when token.Is(";"):
                    return new("more than one statement");
                case TokenKind.Symbol when token.Is("("):
                    depth++;
                    break;
                case TokenKind.Symbol when token.Is(")"):
                    if (--depth < 0)
                        return new("unbalanced parentheses");
                    break;
                case TokenKind.Word:
                    if (Denied.Contains(token.Text))
                        return new($"'{token.Text.ToUpperInvariant()}' is not allowed in a read");
                    if (token.Text.StartsWith("xp_", StringComparison.OrdinalIgnoreCase)
                        || token.Text.StartsWith("sp_", StringComparison.OrdinalIgnoreCase))
                        return new($"system procedure '{token.Text}'");
                    if (token.IsWord("NEXT") && i + 1 < end && tokens[i + 1].IsWord("VALUE"))
                        return new("NEXT VALUE FOR advances a sequence");
                    if (token.IsWord("SELECT") && depth == 0)
                    {
                        var setArm = i > start && tokens[i - 1].Kind == TokenKind.Word && SetOperators.Contains(tokens[i - 1].Text);
                        if (!setArm && ++topLevelSelects > 1)
                            return new("more than one statement");
                    }
                    break;
            }
        }
        if (depth != 0)
            return new("unbalanced parentheses");
        return topLevelSelects == 0 ? new("no top-level SELECT") : new(null);
    }

    enum TokenKind
    {
        Word,
        QuotedIdentifier,
        String,
        Number,
        Symbol,
    }

    readonly record struct Token(TokenKind Kind, string Text)
    {
        public bool IsWord(string word) => Kind == TokenKind.Word && Text.Equals(word, StringComparison.OrdinalIgnoreCase);

        public bool Is(string symbol) => Kind == TokenKind.Symbol && Text == symbol;
    }

    /// <returns>Why the batch can't be lexed, or <c>null</c>.</returns>
    static string? Lex(string sql, out List<Token> tokens)
    {
        tokens = [];
        var i = 0;
        while (i < sql.Length)
        {
            var c = sql[i];
            var next = i + 1 < sql.Length ? sql[i + 1] : '\0';
            if (char.IsWhiteSpace(c))
            {
                i++;
            }
            else if (c == '-' && next == '-')
            {
                while (i < sql.Length && sql[i] is not ('\n' or '\r'))
                    i++;
            }
            else if (c == '/' && next == '*')
            {
                // T-SQL block comments nest.
                var depth = 0;
                do
                {
                    if (i + 1 >= sql.Length)
                        return "unterminated comment";
                    if (sql[i] == '/' && sql[i + 1] == '*')
                    {
                        depth++;
                        i += 2;
                    }
                    else if (sql[i] == '*' && sql[i + 1] == '/')
                    {
                        depth--;
                        i += 2;
                    }
                    else
                        i++;
                }
                while (depth > 0);
            }
            else if (c == '\'' || (c is 'N' or 'n' && next == '\'' && !PrecededByWordChar(sql, i)))
            {
                var open = c == '\'' ? i : i + 1;
                if (Quoted(sql, open, '\'') is not { } close)
                    return "unterminated string";
                tokens.Add(new(TokenKind.String, ""));
                i = close + 1;
            }
            else if (c is '[' or '"')
            {
                if (Quoted(sql, i, c == '[' ? ']' : '"') is not { } close)
                    return "unterminated quoted identifier";
                tokens.Add(new(TokenKind.QuotedIdentifier, sql[(i + 1)..close]));
                i = close + 1;
            }
            else if (c is '{' or '}')
            {
                return "ODBC escape sequences are not allowed";
            }
            else if (IsWordStart(c))
            {
                var begin = i;
                while (i < sql.Length && IsWordPart(sql[i]))
                    i++;
                tokens.Add(new(TokenKind.Word, sql[begin..i]));
            }
            else if (char.IsDigit(c) || (c == '.' && char.IsDigit(next)))
            {
                var begin = i;
                while (i < sql.Length && (char.IsLetterOrDigit(sql[i]) || sql[i] == '.'))
                    i++;
                tokens.Add(new(TokenKind.Number, sql[begin..i]));
            }
            else
            {
                tokens.Add(new(TokenKind.Symbol, c.ToString()));
                i++;
            }
        }
        return null;
    }

    /// <returns>The index of the closing quote, or <c>null</c> when there is none. A doubled closing quote is an escaped one.</returns>
    static int? Quoted(string sql, int open, char closing)
    {
        for (var i = open + 1; i < sql.Length; i++)
        {
            if (sql[i] != closing)
                continue;
            if (i + 1 < sql.Length && sql[i + 1] == closing)
            {
                i++;
                continue;
            }
            return i;
        }
        return null;
    }

    static bool PrecededByWordChar(string sql, int i) => i > 0 && IsWordPart(sql[i - 1]);

    static bool IsWordStart(char c) => char.IsLetter(c) || c is '_' or '@' or '#';

    static bool IsWordPart(char c) => char.IsLetterOrDigit(c) || c is '_' or '@' or '#' or '$';
}
