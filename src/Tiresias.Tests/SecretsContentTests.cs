using System.Text.Json.Nodes;
using NUnit.Framework;
using Tiresias.UserSecrets;

namespace Tiresias.Tests;

public class SecretsContentTests
{
    [TestCase(null)]
    [TestCase("")]
    [TestCase("  \r\n ")]
    [TestCase("{}")]
    [TestCase("{ }")]
    [TestCase("// written by dotnet user-secrets init\n{\n}")]
    [TestCase("/* nothing yet */ { }")]
    public void A_file_with_no_keys_is_empty(string? text) =>
        Assert.That(SecretsContents.OfFile(text), Is.EqualTo(SecretsContent.Empty));

    [TestCase("""{"Feature:Enabled": true}""")]
    [TestCase("""{"Retries": 3, "Ratio": 0.5}""")]
    [TestCase("""{"Optional": null, "Blank": ""}""")]
    [TestCase("""{"Logging": {"LogLevel": {"Default": "Debug", "Microsoft": "Warning"}}}""")]
    [TestCase("""{"Api:BaseUrl": "https://api.example.com/v2/"}""")]
    [TestCase("""{"Hosts": ["http://localhost:5000", "https://example.com"], "Port": 443,}""")]
    public void A_file_of_values_that_cant_be_credentials_holds_settings(string text) =>
        Assert.That(SecretsContents.OfFile(text), Is.EqualTo(SecretsContent.Settings));

    [TestCase("""{"ConnectionStrings": {"Db": "Server=db;Database=x;Password=y"}}""")]
    [TestCase("""{"Api:BaseUrl": "https://user@example.com"}""")]
    [TestCase("""{"Api:BaseUrl": "https://user:pw@example.com"}""")]
    [TestCase("""{"Blob": "https://x.blob.core.windows.net/c?sig=abc"}""")]
    [TestCase("""{"Callback": "https://example.com/#access_token=abc"}""")]
    [TestCase("""{"Webhook": "https://hooks.example.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX"}""")]
    [TestCase("""{"Ftp": "ftp://example.com"}""")]
    [TestCase("""{"Default": "Debug"}""")]
    [TestCase("""{"Enabled": true, "ApiKey": "sk-1"}""")]
    [TestCase("""{"Name": "anything"}""")]
    public void A_value_that_may_be_a_credential_makes_the_file_hold_secrets(string text) =>
        Assert.That(SecretsContents.OfFile(text), Is.EqualTo(SecretsContent.Secrets));

    [Test]
    public void A_sealed_file_holds_secrets_until_it_is_opened() =>
        Assert.That(SecretsContents.OfFile("""{"$tiresias":{"v":1,"sealed":"AQ=="}}"""), Is.EqualTo(SecretsContent.Secrets));

    [Test]
    public void A_sealed_document_that_opens_with_no_keys_is_empty() =>
        Assert.That(SecretsContents.Of(new JsonObject()), Is.EqualTo(SecretsContent.Empty));

    [TestCase("{ not json")]
    [TestCase("""["array"]""")]
    public void A_file_that_isnt_a_json_object_is_invalid(string text) =>
        Assert.That(SecretsContents.OfFile(text), Is.EqualTo(SecretsContent.Invalid));
}
