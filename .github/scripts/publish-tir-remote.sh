#!/bin/sh
# tir-remote for Linux containers, self-contained and trimmed: one file per architecture and C
# library, named as the devcontainer feature downloads it (tir-remote-<rid>), with a SHA-256 list.
# Used by ci.yml (so a break shows on the PR) and app-release.yml.
#   sh .github/scripts/publish-tir-remote.sh <version> <output folder>
set -eu
version="$1"
out="$2"
mkdir -p "$out"
for rid in linux-x64 linux-arm64 linux-musl-x64 linux-musl-arm64; do
  dotnet publish src/Tiresias.Remote -c Release -r "$rid" --self-contained \
    -p:PublishSingleFile=true -p:PublishTrimmed=true -p:Version="$version" -o "publish/tir-remote/$rid"
  cp "publish/tir-remote/$rid/tir-remote" "$out/tir-remote-$rid"
done
(cd "$out" && sha256sum tir-remote-* > tir-remote.sha256)
cat "$out/tir-remote.sha256"
