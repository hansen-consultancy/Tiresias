# Contributing

Issues and pull requests are welcome.

- Run `dotnet test src/Tiresias.Tests/Tiresias.Tests.csproj` before opening a PR.
- Prefer pure, tested planners for decisions (grants, trust, doctor checks) and keep I/O at the
  edges; that is how the existing code is laid out.
- Never commit a real secret, hostname, IP address or person's name, not even in a test. Use
  `example.com`, `203.0.113.x` (TEST-NET-3) and names like `alice`.
- Package versions live in `Directory.Packages.props` only (central package management).
