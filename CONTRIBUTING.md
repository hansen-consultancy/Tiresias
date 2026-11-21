# Contributing

Issues and pull requests are welcome.

- Run `dotnet test src/Tiresias.Tests/Tiresias.Tests.csproj` before opening a PR.
- Leave no build warnings: CI builds with warnings as errors, so one fails the PR. Fix it rather
  than suppress it; where a rule is wrong for one line, suppress that line with the reason.
- Prefer pure, tested planners for decisions (grants, trust, doctor checks) and keep I/O at the
  edges; that is how the existing code is laid out.
- Never commit a real secret, hostname, IP address or person's name, not even in a test. Use
  `example.com`, `203.0.113.x` (TEST-NET-3) and names like `alice`.
- Package versions live in `Directory.Packages.props` only (central package management).
- A change users will notice (a feature, a fix, a changed behaviour or message, a security fix)
  adds a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md), in the same PR. Write it
  for the people who use Tiresias: what they can now do or what no longer goes wrong, not how it
  was built. Refactors, tests and CI changes need no line. Releases turn that section into the
  release notes; see [docs/releasing.md](docs/releasing.md).
- A PR that finishes, starts or adds an item on the [roadmap](docs/roadmap.md) updates that item in
  the same PR.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary`.
  Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`. Scopes: `core`,
  `protocol`, `config` (Extensions.Configuration and its generator), `broker`, `forwarder`,
  `keyring`, `app`. Mark breaking changes with `!` and a `BREAKING CHANGE:` footer.
