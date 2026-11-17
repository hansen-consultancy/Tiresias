using Tiresias.Sql;

namespace Tiresias.Tests;

public class SqlReadClassifierTests
{
    [TestCase("SELECT 1")]
    [TestCase("select * from dbo.Orders")]
    [TestCase("SELECT * FROM dbo.Orders;")]
    [TestCase(";;SELECT 1;;")]
    [TestCase("SELECT TOP (10) o.Id, c.Name FROM dbo.Orders o JOIN dbo.Customers c ON c.Id = o.CustomerId WHERE o.Total > @min ORDER BY o.Id")]
    [TestCase("WITH recent AS (SELECT * FROM dbo.Orders WHERE Created > @since) SELECT COUNT(*) FROM recent")]
    [TestCase("WITH a AS (SELECT 1 AS x), b AS (SELECT x FROM a) SELECT * FROM b")]
    [TestCase("SELECT 1 UNION SELECT 2")]
    [TestCase("SELECT 1 UNION ALL SELECT 2 EXCEPT SELECT 3 INTERSECT SELECT 4")]
    [TestCase("SELECT (SELECT MAX(Id) FROM dbo.Orders) AS top_id")]
    [TestCase("SELECT * FROM dbo.Orders WHERE Id IN (SELECT OrderId FROM dbo.Lines)")]
    [TestCase("SELECT * FROM dbo.Orders WITH (NOLOCK)")]
    [TestCase("SELECT Id FROM dbo.Orders FOR JSON PATH")]
    [TestCase("SELECT * FROM OPENJSON(@doc)")]
    [TestCase("SELECT DATEADD(day, 1, GETUTCDATE())")]
    [TestCase("SELECT [delete], [insert into] FROM [drop table]")]
    [TestCase("SELECT \"exec\" FROM \"update\"")]
    [TestCase("SELECT 'DELETE FROM x; DROP TABLE y' AS s")]
    [TestCase("SELECT N'it''s; EXEC xp_cmdshell' AS s")]
    [TestCase("SELECT 1 -- ; DROP TABLE x")]
    [TestCase("SELECT 1 /* outer /* EXEC nested */ still comment; */")]
    [TestCase("SELECT [a]]b] FROM t")]
    [TestCase("SELECT @x = 1")]
    [TestCase("SELECT 1.5e3, .5, 0x1F")]
    public void A_single_select_is_a_read(string sql) =>
        Assert.That(SqlReadClassifier.Classify(sql).Reason, Is.Null);

    [TestCase("", "empty batch")]
    [TestCase(" ;; -- nothing\n", "empty batch")]
    [TestCase("INSERT INTO t VALUES (1)", "does not start with SELECT or WITH")]
    [TestCase("UPDATE t SET x = 1", "does not start with SELECT or WITH")]
    [TestCase("dbo.SomeProc", "does not start with SELECT or WITH")]
    [TestCase("(SELECT 1)", "does not start with SELECT or WITH")]
    [TestCase("SELECT 1; SELECT 2", "more than one statement")]
    [TestCase("SELECT 1; DELETE FROM t", "more than one statement")]
    [TestCase("SELECT 1 SELECT 2", "more than one statement")]
    [TestCase("SELECT 1\nWITH x AS (SELECT 2) SELECT * FROM x", "more than one statement")]
    [TestCase("SELECT 1 DELETE FROM t", "'DELETE' is not allowed in a read")]
    [TestCase("SELECT 1 EXEC sp_who", "'EXEC' is not allowed in a read")]
    [TestCase("SELECT * INTO dbo.Copy FROM dbo.Orders", "'INTO' is not allowed in a read")]
    [TestCase("WITH x AS (SELECT 1 AS a) DELETE FROM x", "'DELETE' is not allowed in a read")]
    [TestCase("WITH x AS (SELECT 1 AS a) INSERT INTO t SELECT a FROM x", "'INSERT' is not allowed in a read")]
    [TestCase("WITH x AS (SELECT 1 AS a) UPDATE t SET b = 1", "'UPDATE' is not allowed in a read")]
    [TestCase("WITH x AS (SELECT 1 AS a) MERGE t USING x ON 1 = 1 WHEN MATCHED THEN DELETE;", "'MERGE' is not allowed in a read")]
    [TestCase("SELECT * FROM OPENROWSET('SQLNCLI', 'Server=evil', 'SELECT 1')", "'OPENROWSET' is not allowed in a read")]
    [TestCase("SELECT * FROM OPENQUERY(linked, 'SELECT 1')", "'OPENQUERY' is not allowed in a read")]
    [TestCase("SELECT * FROM OPENDATASOURCE('SQLNCLI', 'x').db.dbo.t", "'OPENDATASOURCE' is not allowed in a read")]
    [TestCase("SELECT * FROM OPENROWSET(BULK 'c:\\secrets.txt', SINGLE_CLOB) AS f", "'OPENROWSET' is not allowed in a read")]
    [TestCase("SELECT 1 WAITFOR DELAY '00:10'", "'WAITFOR' is not allowed in a read")]
    [TestCase("SELECT 1 DECLARE @x int", "'DECLARE' is not allowed in a read")]
    [TestCase("SELECT 1 SET ROWCOUNT 0", "'SET' is not allowed in a read")]
    [TestCase("SELECT 1 USE master", "'USE' is not allowed in a read")]
    [TestCase("SELECT 1 GRANT CONTROL TO public", "'GRANT' is not allowed in a read")]
    [TestCase("SELECT 1 DROP TABLE t", "'DROP' is not allowed in a read")]
    [TestCase("SELECT 1 TRUNCATE TABLE t", "'TRUNCATE' is not allowed in a read")]
    [TestCase("SELECT 1 ALTER LOGIN sa ENABLE", "'ALTER' is not allowed in a read")]
    [TestCase("SELECT 1 CREATE TABLE t (a int)", "'CREATE' is not allowed in a read")]
    [TestCase("SELECT 1 BEGIN TRAN", "'BEGIN' is not allowed in a read")]
    [TestCase("SELECT 1 COMMIT", "'COMMIT' is not allowed in a read")]
    [TestCase("SELECT 1\nGO\nDELETE FROM t", "'GO' is not allowed in a read")]
    [TestCase("SELECT 1 KILL 52", "'KILL' is not allowed in a read")]
    [TestCase("SELECT 1 SHUTDOWN", "'SHUTDOWN' is not allowed in a read")]
    [TestCase("SELECT 1 DBCC CHECKDB", "'DBCC' is not allowed in a read")]
    [TestCase("SELECT 1 BACKUP DATABASE x TO DISK = 'c:\\x'", "'BACKUP' is not allowed in a read")]
    [TestCase("SELECT 1 IF 1 = 1 DELETE FROM t", "'IF' is not allowed in a read")]
    [TestCase("SELECT 1 THROW 50000, 'x', 1", "'THROW' is not allowed in a read")]
    [TestCase("SELECT 1 RECONFIGURE", "'RECONFIGURE' is not allowed in a read")]
    [TestCase("SELECT 1 REVERT", "'REVERT' is not allowed in a read")]
    [TestCase("SELECT 1 OUTPUT inserted.*", "'OUTPUT' is not allowed in a read")]
    [TestCase("SELECT 1 EXECUTE AS LOGIN = 'sa'", "'EXECUTE' is not allowed in a read")]
    [TestCase("SELECT 1 dbo.sp_executesql", "system procedure 'sp_executesql'")]
    [TestCase("SELECT * FROM master..xp_dirtree", "system procedure 'xp_dirtree'")]
    [TestCase("SELECT NEXT VALUE FOR dbo.OrderNumbers", "NEXT VALUE FOR advances a sequence")]
    [TestCase("SELECT {fn USER()}", "ODBC escape sequences are not allowed")]
    [TestCase("SELECT 'unterminated", "unterminated string")]
    [TestCase("SELECT 1 /* unterminated", "unterminated comment")]
    [TestCase("SELECT 1 /* /* nested */ unterminated", "unterminated comment")]
    [TestCase("SELECT [unterminated", "unterminated quoted identifier")]
    [TestCase("SELECT (1", "unbalanced parentheses")]
    [TestCase("SELECT 1)", "unbalanced parentheses")]
    [TestCase("SELECT 1) (SELECT 2", "unbalanced parentheses")]
    [TestCase("WITH x AS (SELECT 1)", "no top-level SELECT")]
    public void Anything_else_is_refused_with_the_reason(string sql, string reason) =>
        Assert.That(SqlReadClassifier.Classify(sql).Reason, Is.EqualTo(reason));

    [TestCase("SELECT 1 /**/DELETE FROM t")]
    [TestCase("SELECT 1--\nDELETE FROM t")]
    [TestCase("SELECT 1\u00a0DELETE FROM t")]
    [TestCase("SELECT 1 dElEtE FROM t")]
    [TestCase("SELECT 1 /* */ ; /* */ DELETE FROM t")]
    [TestCase("SELECT 'a'DELETE FROM t")]
    [TestCase("SELECT [a]DELETE FROM t")]
    public void Hiding_a_write_behind_comments_case_or_odd_whitespace_does_not_help(string sql) =>
        Assert.That(SqlReadClassifier.Classify(sql).IsRead, Is.False);

    [Test]
    public void A_string_after_a_word_character_is_not_mistaken_for_an_N_prefix()
    {
        // "selectN'..." would be a column alias quirk; what matters is that the quote still opens a string.
        Assert.That(SqlReadClassifier.Classify("SELECT colN'x; DELETE FROM t'").IsRead, Is.True);
    }
}
