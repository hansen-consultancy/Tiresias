# What do you need?

Status: **phase 3 built** (*What do you need?*, `tir advise`); phase 4 is design. Phases 3 and 4 of [guided setup](guided-setup.md) (#32). This page
designs the one way to add anything to Tiresias, and how Home shows only what this machine uses.

## The problem

Each feature arrived with its own button. The Services window has Add, Edit, How to use, Remove,
Set up a SQL Server and Set up a RavenDB; Home (`StatusWindow`) has Secrets, Services and
Environment variables; the tray menu repeats most of them. Someone who needs one has to know it
exists and which window holds it, and the buttons all look equal: nothing says that a per-lease SQL
login is stronger than a sealed connection string, or that a service may need no secret at all.

Phase 1 gave every finding a position on the two axes (`Position`, E1–E5 by C1–C3) and a fix
(`DoctorFix`). Phase 2 opens today's windows filled in from such a fix. This phase uses both from
the other end: the user says what they need, and Tiresias lists the ways to do it, strongest first.

## Decisions

- **The catalogue is data in Core, not screens.** A *need* ("An app needs a database") has
  phrases it answers to and a list of *options*; each option has a position and an action. The
  app, `tir advise` and the findings all read the same catalogue, so they give the same advice.
- **An option's action is a `DoctorFix`.** Phase 2 already turns a fix into a window opened
  filled in; the catalogue adds a few fix kinds (add a service of a known kind, the environment
  window, a guide) and reuses that plumbing. A finding and a catalogue option that lead to the same
  place are the same value.
- **Ranking is computed from positions, never hand-ordered.** Options sort by control first, then
  exposure: C1 before C2 before C3, and within a control, E1 before E5. So E3/C1 (a placeholder)
  ranks above E1/C3 (an identity any program can use unseen), as guided setup's principles ask. The
  first option this machine can use is the recommended one.
- **An option that depends on something Tiresias can't know asks, never probes.** Whether a SQL
  Server accepts Windows or Entra sign-in for this app is a question in the flow, not a login
  attempt made unasked.
- **The free-text match is local and deterministic.** Words typed into the search box never leave
  the machine, and the same words always give the same list. No language model is involved.
- **An E1 option is a guide, not a setup.** Tiresias holds nothing for it, so the action shows the
  steps to follow elsewhere and links the matching section of [need no secret at all](avoid-secrets.md).
- **Home never hides something that has content or a finding.** Phase 4 only removes areas with
  nothing in them; it never makes a sealed secret or a warning harder to reach.

## Design twice

| | **A. A question wizard** | **B. A catalogue of needs, ranked options and search (chosen)** |
|---|---|---|
| Shape | A tree of questions: what kind of thing, where it runs, which server, until one flow is left | A list of needs; picking one shows every option for it, strongest first, with what each gives up |
| Someone who knows what they want | Answers every question anyway | Types "sql" and picks the option |
| Weaker options | Hidden behind answers; the user never sees what they gave up | Listed below the recommended one, each saying what it gives up |
| Adding a feature | A new branch in the tree, and every path into it re-tested | A new option on an existing need, ranked by its position |
| Shared with `tir` | A wizard doesn't translate to a CLI | `tir advise "<words>"` prints the same ranked list |

B wins: it shows the trade-off instead of deciding it silently, it stays one step for people who
know what they want, and a new option needs no new screen.

## Shape

### The catalogue

The needs are those in guided setup's *What do you need?* table: a database for an app, an API key
for a program, a key for a command-line tool, a CLI that signs in as the user, protecting a
project's secrets, publishing packages from CI, signing in to git. Each option names:

- its **position**, which ranks it;
- what it **gives up** against the recommended one, in one line ("the program holds the real key
  and can send it anywhere");
- its **action**, a `DoctorFix`;
- whether it is **available** here, from facts the planner is given: unlocked or not, solo or with
  a broker, the SQL Server question answered. An unavailable option stays listed, greyed, with the
  reason.

The catalogue is a static table in Core, versioned with the code. Per-service knowledge the
findings also need (which upstreams accept `Authorization: Bearer`, which tools `tir exec`
supports) lives beside it, once.

### The free-text match

The search box scores each need against what was typed:

1. Lowercase, split on anything that isn't a letter or digit, drop a short list of stop words.
2. Each need lists phrases and each known service lists names and aliases ("azure sql",
   "sql server", "mssql", "openai", "gpt", "nuget", "ravendb", "ef core", "gh"). A token that
   equals one scores more than a token that starts one; a multi-word phrase scores only when all its
   words are present.
3. Needs with a score show, highest first; ties keep catalogue order. With nothing matched, the
   whole catalogue shows, so the box never leads to an empty screen.

A known service also preselects its option: "my EF Core app talks to Azure SQL" opens *An app needs
a database* with SQL Server expanded. A local model could later rank free text better; it isn't
needed for a catalogue of this size, and the deterministic match stays as the fallback either way.

### What moves where

| Today | After |
|---|---|
| Services: Add, Set up a SQL Server, Set up a RavenDB | One **Add...** opening *What do you need?*. Edit, How to use and Remove stay, since they act on a selected service |
| Home: Secrets, Services, Environment variables buttons | The areas in use (phase 4) |
| Tray: a line per window | Unlock/Lock, Home, Add..., Activity, Quit, and the findings badge |
| `SqlServerWindow`, `RavenServerWindow`, the Services add form, `EnvironmentWindow` | Unchanged; they are where options lead, opened filled in where the need gave inputs |

Existing windows keep doing the work. This changes how people get to them, not what they do.

### Phase 4: what is in use

Home lists an area when any of these holds:

| Area | In use when |
|---|---|
| Services | The vault has a service |
| User secrets | A sealed `secrets.json` is known, or a project folder is set in the secrets editor |
| Environment variables | A variable is sealed |
| Activity | The log has a record |
| Any area | A finding's fix opens it, or the user opened it from *What do you need?* this session |

The facts are names and counts the app can read while locked: no unlock is needed to decide what
Home shows. A fact that can't be read counts as in use, so a read error shows an area instead of
hiding it. Areas not in use are one step away, through the needs that lead to them. A pure planner
(`HomeAreas.Plan`) decides; the tray menu asks the same planner.

### Phase 2's plumbing

Phase 2 is being built now: a findings section on Home, a fix opening its window filled in, and
dismissals kept per finding. This design assumes a fix maps to exactly one window opener with its
inputs. If phase 2 lands with a different seam, this page adjusts to it; the catalogue's ranking,
matching and Home's rules don't depend on it.

## As built

The catalogue is `NeedCatalog` in Core (`Client/Needs.cs`), the window `NeedsWindow`. Where the
code settled what this page left open:

- **Positions.** Trusted publishing is E1/C1: its policy names the one repository and workflow
  allowed, and the registry records each key it issues. A CLI's own sign-in and Git Credential
  Manager are E5/C3 (a token any program running as the user can read); an SSH agent, managed
  identity and Windows / Entra sign-in are E1/C3. So, ranked by the rule above, a placeholder comes
  before the service's own identity, as the principles ask.
- **Sign in to git** offers a GitHub App token per run (`tir exec`), an SSH key in an agent, or Git
  Credential Manager. Tiresias has no git credential helper, so a token sealed for one isn't
  offered.
- **New fix kinds:** `AddService` (HTTP, SQL Server or RavenDB, an HTTP address filled in for a
  GitHub App), `SealVariable`, `SealUserSecrets`, and `FollowGuide`, whose topic is a row of
  [need no secret at all](avoid-secrets.md) (a test keeps them in step). A guide opens that page.
- **Availability** is one fact for now: a broker (solo or remote) for options that store a vault
  service. Locked or not doesn't grey anything out, since every window it leads to asks to unlock;
  the SQL Server sign-in question lives in the guide, which is always available.
- **Search:** an exact word scores 3, a start of a word (three letters or more) 1. The first need
  found opens; a named service marks its option "Matches what you typed" unless it is already
  recommended.
- **Findings badge** in the tray: not built.

## Tests

- `NeedCatalogTests`: every need has an option; every option's position ranks it where the list
  shows it; every action is a valid `DoctorFix`; no two needs claim the same exact phrase.
- `OptionRankingTests`: C1 before C3 whatever the exposure; within a control, E1 first; an
  unavailable option keeps its place and says why; the recommended option is the first available.
- `NeedMatcherTests`: phrases, aliases and partial words find the right need; a multi-word phrase
  needs all its words; nothing matched returns the whole catalogue; the same text gives the same
  order.
- `HomeAreasTests`: each area appears with content and disappears without; a finding keeps its
  area visible; an unreadable fact shows the area.

## Not in scope

- **New flows.** Every option leads to a window or guide that exists or is already designed. A need
  with no flow behind it isn't added.
- **A language model for the search box.** See *The free-text match*.
- **Team policy** that requires a minimum position for a kind of secret. It needs a policy model on
  the broker first.
- **Attack surface** (phase 5) and the further checks (phase 6).

## Phases

1. **Built. Core:** the catalogue, the ranking and the matcher as pure code; `tir advise "<words>"` prints
   the ranked options and their commands.
2. **Built. The window:** *What do you need?* in the app; Add, Set up a SQL Server and Set up a RavenDB move
   behind it; the tray menu shortens.
3. **Home shows what is in use** (guided setup phase 4): `HomeAreas.Plan`, Home and the tray built
   from it.
