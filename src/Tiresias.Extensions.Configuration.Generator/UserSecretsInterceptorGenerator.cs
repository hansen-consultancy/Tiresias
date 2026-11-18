using System.Collections.Immutable;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Tiresias.Extensions.Configuration.Generator;

/// <summary>
/// Reroutes user secrets through tir without changing a line of the app: every
/// <c>AddUserSecrets</c> call becomes <c>AddProtectedUserSecrets</c>, and every host builder
/// creation that adds user secrets by itself (<c>WebApplication.CreateBuilder</c>,
/// <c>Host.CreateApplicationBuilder</c>, <c>Host.CreateDefaultBuilder</c>) is followed by
/// <c>ProtectUserSecrets</c>, which swaps the stock source in place. Call sites in other assemblies
/// (the framework's own) can't be intercepted, which is why the sealed file stays valid JSON.
/// </summary>
[Generator(LanguageNames.CSharp)]
public sealed class UserSecretsInterceptorGenerator : IIncrementalGenerator
{
    const string Namespace = "Tiresias.Generated";

    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var sites = context.SyntaxProvider
            .CreateSyntaxProvider(
                static (node, _) => node is InvocationExpressionSyntax
                {
                    Expression: MemberAccessExpressionSyntax
                    {
                        Name.Identifier.ValueText: "AddUserSecrets" or "CreateBuilder" or "CreateApplicationBuilder" or "CreateDefaultBuilder",
                    },
                },
                static (ctx, ct) => Describe((InvocationExpressionSyntax)ctx.Node, ctx.SemanticModel, ct))
            .Where(static s => s is not null)
            .Select(static (s, _) => s!.Value)
            .Collect();

        context.RegisterSourceOutput(sites, static (spc, all) =>
        {
            if (!all.IsEmpty)
                spc.AddSource("Tiresias.UserSecretsInterceptors.g.cs", Emit(all));
        });
    }

    /// <summary>One intercepted call: the method's full text minus its name, plus where to attach it. Strings only, so the incremental cache compares by value.</summary>
    readonly record struct Site(string Key, string Signature, string Body, string Attribute);

    static Site? Describe(InvocationExpressionSyntax invocation, SemanticModel model, System.Threading.CancellationToken ct)
    {
        if (model.GetSymbolInfo(invocation, ct).Symbol is not IMethodSymbol called)
            return null;
        var method = (called.ReducedFrom ?? called).OriginalDefinition;
        var body = BodyFor(method);
        if (body is null)
            return null;
        var location = model.GetInterceptableLocation(invocation, ct);
        if (location is null)
            return null;

        var signature = Signature(method);
        return new Site(signature, signature, body, location.GetInterceptsLocationAttributeSyntax());
    }

    static string? BodyFor(IMethodSymbol m)
    {
        var type = m.ContainingType.ToDisplayString();
        var p = m.Parameters;
        string Arg(int i) => "@" + p[i].Name;

        switch (type, m.Name)
        {
            case ("Microsoft.Extensions.Configuration.UserSecretsConfigurationExtensions", "AddUserSecrets"):
            {
                var optional = p.FirstOrDefault(x => x.Name == "optional") is { } o ? "@" + o.Name : "false";
                var builder = "global::Tiresias.Extensions.Configuration.ProtectedUserSecretsExtensions";
                if (m.IsGenericMethod)
                    return $"return {builder}.AddProtectedUserSecrets(@{p[0].Name}, typeof({m.TypeParameters[0].Name}).Assembly, {optional});";
                if (p.Length > 1 && p[1].Type.ToDisplayString() == "System.Reflection.Assembly")
                    return $"return {builder}.AddProtectedUserSecrets({Arg(0)}, {Arg(1)}, {optional});";
                if (p.Length > 1 && p[1].Type.SpecialType == SpecialType.System_String)
                    return $"return {builder}.AddProtectedUserSecrets({Arg(0)}, {Arg(1)});";
                return null;
            }
            case ("Microsoft.AspNetCore.Builder.WebApplication", "CreateBuilder"):
            case ("Microsoft.Extensions.Hosting.Host", "CreateApplicationBuilder"):
                return $"var builder = global::{type}.{m.Name}({string.Join(", ", p.Select(x => "@" + x.Name))});\n"
                    + "        global::Tiresias.Extensions.Configuration.ProtectedUserSecretsExtensions.ProtectUserSecrets(builder.Configuration);\n"
                    + "        return builder;";
            case ("Microsoft.Extensions.Hosting.Host", "CreateDefaultBuilder"):
                // Defaults are registered first, so this callback sees their sources and runs before the build.
                return $"return global::Microsoft.Extensions.Hosting.HostingHostBuilderExtensions.ConfigureAppConfiguration(\n"
                    + $"            global::{type}.{m.Name}({string.Join(", ", p.Select(x => "@" + x.Name))}),\n"
                    + "            static (_, configuration) => global::Tiresias.Extensions.Configuration.ProtectedUserSecretsExtensions.ProtectUserSecrets(configuration));";
            default:
                return null;
        }
    }

    /// <summary><c>ReturnType Name&lt;T&gt;(this A a, B b) where T : class</c> with <c>Name</c> left as <c>{0}</c>.</summary>
    static string Signature(IMethodSymbol m)
    {
        var fq = SymbolDisplayFormat.FullyQualifiedFormat;
        var sb = new StringBuilder();
        sb.Append(m.ReturnType.ToDisplayString(fq)).Append(" {0}");
        if (m.IsGenericMethod)
            sb.Append('<').Append(string.Join(", ", m.TypeParameters.Select(t => t.Name))).Append('>');
        sb.Append('(');
        sb.Append(string.Join(", ", m.Parameters.Select((p, i) =>
            (i == 0 && m.IsExtensionMethod ? "this " : "") + (p.IsParams ? "params " : "") + p.Type.ToDisplayString(fq) + " @" + p.Name)));
        sb.Append(')');
        foreach (var t in m.TypeParameters)
        {
            var constraints = new System.Collections.Generic.List<string>();
            if (t.HasReferenceTypeConstraint) constraints.Add("class");
            if (t.HasValueTypeConstraint) constraints.Add("struct");
            constraints.AddRange(t.ConstraintTypes.Select(c => c.ToDisplayString(fq)));
            if (t.HasConstructorConstraint) constraints.Add("new()");
            if (constraints.Count > 0)
                sb.Append(" where ").Append(t.Name).Append(" : ").Append(string.Join(", ", constraints));
        }
        return sb.ToString();
    }

    static string Emit(ImmutableArray<Site> sites)
    {
        var sb = new StringBuilder();
        sb.AppendLine("// <auto-generated/> by Tiresias.Extensions.Configuration.Generator");
        sb.AppendLine("#nullable enable");
        sb.AppendLine();
        sb.AppendLine("namespace System.Runtime.CompilerServices");
        sb.AppendLine("{");
        sb.AppendLine("    [global::System.AttributeUsage(global::System.AttributeTargets.Method, AllowMultiple = true)]");
        // The compiler reads the arguments; the class never does. <auto-generated/> doesn't silence
        // compiler warnings, so CS9113 (unread primary constructor parameter) would show in every consumer build.
        sb.AppendLine("#pragma warning disable CS9113");
        sb.AppendLine("    file sealed class InterceptsLocationAttribute(int version, string data) : global::System.Attribute;");
        sb.AppendLine("#pragma warning restore CS9113");
        sb.AppendLine("}");
        sb.AppendLine();
        sb.AppendLine($"namespace {Namespace}");
        sb.AppendLine("{");
        sb.AppendLine("    file static class UserSecretsInterceptors");
        sb.AppendLine("    {");
        var n = 0;
        foreach (var group in sites.GroupBy(s => s.Key).OrderBy(g => g.Key, System.StringComparer.Ordinal))
        {
            foreach (var site in group.OrderBy(s => s.Attribute, System.StringComparer.Ordinal))
                sb.Append("        ").AppendLine(site.Attribute);
            var first = group.First();
            sb.Append("        public static ").AppendLine(string.Format(first.Signature, "Intercept" + n++));
            sb.AppendLine("        {");
            sb.Append("        ").AppendLine(first.Body);
            sb.AppendLine("        }");
            sb.AppendLine();
        }
        sb.AppendLine("    }");
        sb.AppendLine("}");
        return sb.ToString();
    }
}
