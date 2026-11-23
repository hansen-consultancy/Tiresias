#!/bin/sh
# Installs tir-remote (docs/devcontainers.md). app-release.yml publishes this feature with the
# app's version in tir-remote.version and the release's SHA-256 list in tir-remote.sha256, so the
# binary downloaded here must match what that release built, byte for byte.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
if [ ! -f "$here/tir-remote.version" ] || [ ! -f "$here/tir-remote.sha256" ]; then
  echo "tiresias feature: not a published copy (no tir-remote.version or tir-remote.sha256). Use ghcr.io/hansen-consultancy/devcontainer-features/tiresias." >&2
  exit 1
fi
version="$(cat "$here/tir-remote.version")"

case "$(uname -m)" in
  x86_64 | amd64) arch=x64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "tiresias feature: no tir-remote for $(uname -m)." >&2; exit 1 ;;
esac
libc=""
if ls /lib/ld-musl-* >/dev/null 2>&1; then libc="musl-"; fi
file="tir-remote-linux-$libc$arch"

expected="$(grep " $file\$" "$here/tir-remote.sha256" | cut -d' ' -f1)"
if [ -z "$expected" ]; then
  echo "tiresias feature: $file isn't in this release's checksums." >&2
  exit 1
fi

url="https://github.com/hansen-consultancy/Tiresias/releases/download/app-v$version/$file"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --proto '=https' -o "$tmp" "$url"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$tmp" "$url"
else
  echo "tiresias feature: needs curl or wget to download tir-remote." >&2
  exit 1
fi

actual="$(sha256sum "$tmp" | cut -d' ' -f1)"
if [ "$actual" != "$expected" ]; then
  echo "tiresias feature: $file from $url doesn't match the release's checksum; not installed." >&2
  exit 1
fi
install -m 0755 "$tmp" /usr/local/bin/tir-remote

if [ "${GITCREDENTIALHELPER:-true}" = "true" ]; then
  # System-wide, so git asks tir-remote before any helper a user's own config adds.
  helper="/usr/local/bin/tir-remote git-credential"
  if command -v git >/dev/null 2>&1; then
    git config --system --get-all credential.helper | grep -qxF "$helper" || git config --system --add credential.helper "$helper"
  else
    printf '[credential]\n\thelper = %s\n' "$helper" >> /etc/gitconfig
  fi
fi

echo "tir-remote $version installed. Add \"TIRESIAS_TICKET\": \"\${localEnv:TIRESIAS_TICKET}\" to remoteEnv and start VS Code with tir run -- code <folder>."
