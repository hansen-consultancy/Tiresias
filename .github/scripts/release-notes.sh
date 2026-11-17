#!/usr/bin/env sh
# Prints the CHANGELOG.md section for one version: the lines after "## [<version>]" up to the next
# "## [" heading. Both release workflows publish it as the GitHub release notes, and the app
# release also packs it, so the app shows the same text before it restarts into an update.
# Fails, naming the version, when the section is missing or empty: a release needs its notes.
set -eu
version="${1:?usage: release-notes.sh <version> [changelog]}"
changelog="${2:-CHANGELOG.md}"
notes=$(awk -v heading="## [$version]" '
  index($0, heading) == 1 { found = 1; next }
  found && /^## \[/ { exit }
  found { print }
' "$changelog" | sed -e '/./,$!d')
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "CHANGELOG.md has no notes under '## [$version]'. Move the Unreleased lines under that heading first." >&2
  exit 1
fi
printf '%s\n' "$notes"
