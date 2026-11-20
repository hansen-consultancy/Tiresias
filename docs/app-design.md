# App design: show less, allow more

**Status:** built (#61, #63, #64, #65). A design pass over every window in `src/Tiresias.App`, using
*What do you need?* (`NeedsWindow`, the Add flow) as the model: one title, one search or summary,
a list of cards that open on demand, one footer.

## What the audit found

| Window | Size / place today | Scroll regions | Unexplained | Too much at once |
|---|---|---|---|---|
| Home (`StatusWindow`) | 720×600, centre screen | 4: findings (max 300), a group's members inside it (max 240), dismissed (max 200), checks list | `E5/C3 → E2/C1` on every finding; "Solo mode" | Status card carries headline, mode, build + folder, start-with-Windows and its note; then nav, findings and every passing check |
| Add (`NeedsWindow`) | 720×640, centre screen | 1 | `E3/C1` beside each option | — the model |
| Secrets | 820×600, centre screen | grid, plus a detail block that grows with the project | — | A project used by 28 worktrees prints 28 paths above the grid; the grid gets what is left |
| Services | 860×680, centre screen | grid, or the add form's own scroller | — | Four buttons on one grid (setups already moved to Add) |
| SQL Server / RavenDB setup | 720×760, centre *owner* | 1 | — | 760 tall: taller than a laptop's work area |
| Environment | 720×600 | 1 | — | Four sections always open |
| Activity | 960×620 | grid | — | — |
| About, Update, Recovery, First run | 560–620 wide, fixed heights | 1 each | — | Fixed heights clip or leave gaps |
| Consent, Incident, Problem, Ask, Usage | fit height, some topmost | Consent and Incident scroll inside a capped window | — | — |

Placement differs because heights differ (a centred 760-tall window starts higher than a 480 one),
two kinds of window centre on an owner, prompts are topmost, and a fixed height rarely matches the
content, so S. resizes most of them.

## 1. Placement and size: one rule

- **Every window fits its content's height**, capped at 85% of the work area of the monitor it
  opens on; past the cap the body scrolls (rule 2). The height is measured before the window
  shows, so it opens centred at its final size.
- **A window whose list loads after it opens** (Home, Activity, Secrets, Services, Environment)
  cannot know that height yet: it opens at **70% of the work area** (`WindowFit.Tall`) and its
  body scrolls. Fitting it to "Checking…" first made it open small and then grow down the screen.
- **Three widths**, chosen per window: **narrow 480** (short questions: Ask, Problem),
  **standard 720** (everything with cards, and the Consent and Incident prompts, which show paths), **wide 960** (grids: Activity, Secrets, Services).
- **Top-level windows open centred on the monitor holding the mouse** (where the tray was clicked);
  **windows opened from another window centre on it**: on their owner, or, for the peers Home
  opens (Secrets, Services, Environment, Activity, About), on the window that was active. One helper
  (`WindowFit`) applies this from `App.ShowWindow` and for owned windows, so no window sets
  `Width`/`Height`/`WindowStartupLocation` itself.
- After it opens the window keeps its size: content changing later (a list arriving, a card
  opening) scrolls in the body and never makes the window grow or jump. Resizing stays allowed
  for the non-prompt windows.

## 2. One scroll region

Every window is three rows: **header** (title, plus a search or one-line summary), **body**,
**footer** (the button row). Only the body scrolls. Inside it:

- no `ScrollViewer`, `ListView` or `MaxHeight` on a list; a long list shows its first few items and
  a **Show all (n)** link that opens the rest in place;
- a grid window (Activity, Secrets values, Services) makes the grid the body, and nothing else in
  that window scrolls.

Home's findings, a finding's members and the dismissed list all become plain lists in the one
body. The passing checks, today a second scroller, fold into one line (rule 3).

## 3. Summary first, details on demand

The Add flow's pattern, applied everywhere: a **card** shows a title, one line of summary and its
one main action. Everything else (members, reasons, paths, the second and third buttons) sits
behind the card's **Details** expander, closed by default.

- **Home:** the one-line state and Lock. Then the findings, each with its fix in view and one
  small **Details** toggle on its title line that opens the explanation, Dismiss and a group's
  members together; no full-width bars. Then one line "12 checks passed" that expands to the list. Navigation to
  Secrets, Services, Environment and Activity stays as today's row, only for areas in use.
- **Services:** left as it is: four buttons on one grid, the setups already reached through Add.
- **Environment:** each section a card; Sealed and Add new open, the others open when they list something to act on (or when a fix opens them).

## 4. Ratings in plain language

`E5/C3` stays in `tir`, the docs and Copy details. The app replaces it with two
short phrases taken from the axis definitions (`Position.cs`), and a tooltip with the full sentence:

| Code | Shown as | Tooltip |
|---|---|---|
| E1 | No secret | The service accepts an identity; there is no secret to copy. |
| E2 | Expires quickly | Made for this run and useless after it. |
| E3 | Stays in Tiresias | The program gets a stand-in that is useless anywhere else. |
| E4 | Sealed | Encrypted on disk, handed to the program as its value. |
| E5 | Readable | Anything running as you can read it. |
| C1 | Asks you | Each program needs your OK; every use is recorded. |
| C2 | Recorded | Every use is recorded, nothing asks. |
| C3 | Unchecked | Any program running as you can use it, unrecorded. |

A finding reads **"Readable, unchecked → Stays in Tiresias, asks you"**; an Add option shows its
pair the same way. Pointing at the words shows what each one means; the introduction above the
findings says so.

## 5. A compact banner

Home's top card shrinks to the state line and Lock. Mode, build and folder, and start with Windows
move to **About** (already the place for build facts). A development build keeps one visible
marker: **"(dev)"** in every window title, besides the tray icon's orange corner.

## 6. Worktrees, grouped

A user-secrets id used by many checkouts of one repository is one entry:
**"HC — 28 checkouts"**. The detail line under the picker shows the first path and
**Show all 28**, which opens the list in place (rule 2). Grouping is by the id, so nothing changes
in what is stored; the combo box lists one row per id as today, with the count in its label.

## 7. The approval prompt

The consent dialog asks on the left and shows the facts on the right. Each answer is a full-width
button with a line saying what it means ("It isn't asked again until Tiresias locks."), so the
choice doesn't depend on knowing the words. The first answer offered (Allow for this session, else
Allow once or Unlock) is the accent button, but none is the default and focus starts on Deny:
the accent says which answer is usual, never which one Enter gives. The button labels themselves
stay as before, since the docs name them. The right-hand card holds what it gets, who is asking
(file name first, folder under it) and the command line, so the left column stays the same height
whatever is asked.

## Slices

1. `WindowFit` and the size rule applied to every window; "(dev)" in titles; compact Home banner.
2. One scroll region: Home's lists, Consent, Incident, Secrets' detail; worktree grouping.
3. Plain-language ratings (`PositionWords` in the app; `tir` keeps the codes).
4. Cards with Details on Home, Services and Environment.

Each slice is a PR with its CHANGELOG line and `/argus review`.
