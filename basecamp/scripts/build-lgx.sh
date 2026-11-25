#!/usr/bin/env bash
# The two Logos packages for linux-amd64, built with Nix from this checkout the way Ferrata's Basecamp release builds
# its modules (logos-module-builder 5f74cdb, `nix build .#lgx-portable`):
#
#   basecamp/scripts/build-lgx.sh OUT            (Linux x86-64 with Nix and flakes)
#
# ESCAPEMENT_COMMIT: the staged crates' commit (stage.py's default: the last commit that changed them). SOURCE_TREES: the
# git trees of basecamp/escapement_core_module, basecamp/escapement_ui and basecamp/scripts as JSON (default: read with
# git from HEAD); build.json records them, so the packages can be matched to any commit that holds those trees
# (`git rev-parse <commit>:basecamp/escapement_core_module`).
#
# Each module is copied to OUT/src/<module> (without target/ and links), escapement-core and escapement-sdk are staged
# into the core module's copy (stage.py), and its flake is built from that copy (path:). Output: OUT/linux-amd64/
# <module>-<version>.lgx (unsigned), OUT/build.json (each package's size, SHA-256, store path, seconds), SHA256SUMS,
# OUT/log/. Nothing is signed here (sign-test.sh).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
[ $# = 1 ] || { sed -n '2,12p' "$0" >&2; exit 2; }
mkdir -p "$1" && out=$(cd "$1" && pwd)
LGX_PACKAGE=github:logos-co/logos-package/4bdd9041ebfbd06c2b22134afdcd27fce8a43f3c
MODULES=${MODULES:-"escapement_core_module escapement_ui"}
commit=${ESCAPEMENT_COMMIT:-$(git -C "$repo" log -1 --format=%H -- crates/escapement-core crates/escapement-sdk 2> /dev/null || echo unknown)}
if [ -z "${SOURCE_TREES:-}" ]; then
  SOURCE_TREES=$(for d in escapement_core_module escapement_ui scripts; do
    printf '{"basecamp/%s":"%s"}\n' "$d" "$(git -C "$repo" rev-parse "HEAD:basecamp/$d" 2> /dev/null || echo unknown)"
  done | jq -s -c add)
fi
case "$(uname -s)-$(uname -m)" in Linux-x86_64) platform=linux-amd64 ;; *) echo "build-lgx.sh: linux-amd64 only" >&2; exit 2 ;; esac
if [ "$(ulimit -s)" = unlimited ]; then ulimit -s 1048576; else ulimit -s 65536 2> /dev/null || ulimit -s hard; fi
rm -rf "$out/src" "$out/$platform" "$out/log" "$out/build.json"
mkdir -p "$out/src" "$out/$platform" "$out/log"
sha() { sha256sum "$1" | cut -d' ' -f1; }

# nix build, retried on the two transient failures of a gVisor build box (Ferrata's basecamp-release.sh).
nixb() {
  local attempt log="$out/log/nix-attempt.log"
  for attempt in 1 2 3 4 5 6; do
    if [ "$(id -u)" = 0 ] && [ -d /homeless-shelter ]; then rm -rf /homeless-shelter; fi
    if nix build "$@" > "$log" 2>&1; then cat "$log"; return 0; fi
    grep -q -E 'reading a line: Input/output error|unexpected EOF reading a line|/homeless-shelter. exists' "$log" || { cat "$log"; return 1; }
    echo "build-lgx.sh: nix build stopped on a build-box error (attempt $attempt); retrying" >&2
  done
  cat "$log"; return 1
}

nixb "$LGX_PACKAGE#lgx" -o "$out/lgx-tool" > "$out/log/lgx-tool.log" 2>&1 || { tail -n 20 "$out/log/lgx-tool.log" >&2; exit 1; }
export PATH="$out/lgx-tool/bin:$PATH"
{ nix --version; uname -srm; echo "source $commit"; echo "lgx $LGX_PACKAGE"; } > "$out/log/versions.txt"
entries=""
for m in $MODULES; do
  t0=$(date +%s)
  tar -C "$repo/basecamp" --exclude=target --exclude=logos-rust-sdk-src --exclude='result*' --exclude=staged -cf - "$m" | tar -C "$out/src" -xf -
  if [ "$m" = escapement_core_module ]; then
    ESCAPEMENT_COMMIT=$commit python3 -I "$here/stage.py" "$out/src/$m" > "$out/log/stage.txt"
  fi
  (cd "$out/src/$m" && nixb "path:$out/src/$m#lgx-portable" --print-out-paths --no-link) > "$out/log/build-$m.log" 2>&1 \
    || { echo "build-lgx.sh: $m failed (log/build-$m.log):" >&2; tail -n 40 "$out/log/build-$m.log" >&2; exit 1; }
  store=$(grep -E '^/nix/store/[^ ]+$' "$out/log/build-$m.log" | tail -n 1)
  built=$(find "$store/" -maxdepth 2 -name '*.lgx' | head -n 1)
  [ -n "$built" ] || { echo "build-lgx.sh: no .lgx in $store" >&2; exit 1; }
  version=$(jq -r .version "$out/src/$m/metadata.json")
  file="$platform/$m-$version.lgx"
  cp "$built" "$out/$file" && chmod 644 "$out/$file"
  lgx verify "$out/$file" > "$out/log/verify-$m.txt" 2>&1 || true
  manifest=$(lgx manifest "$out/$file" --json)
  [ "$(jq -r .name <<< "$manifest")" = "$m" ] || { echo "build-lgx.sh: $file's manifest names another module" >&2; exit 1; }
  entries="$entries$(jq -cn --arg name "$m" --arg version "$version" --arg file "$file" --argjson size "$(wc -c < "$out/$file")" \
    --arg sha256 "$(sha "$out/$file")" --argjson manifest "$manifest" --arg store "$store" --argjson seconds "$(( $(date +%s) - t0 ))" \
    '{name: $name, version: $version, file: $file, size: $size, sha256: $sha256, rootHash: ($manifest.hashes.root // ""),
      type: ($manifest.type // ""), variants: ($manifest.main // {} | keys), nix_out: $store, seconds: $seconds}')
"
  echo "build-lgx.sh: $file $(wc -c < "$out/$file") bytes, sha256 $(sha "$out/$file"), $(( $(date +%s) - t0 )) s"
done
printf '%s' "$entries" | jq -s --arg commit "$commit" --argjson trees "$SOURCE_TREES" --arg platform "$platform" --arg lgx "$LGX_PACKAGE" \
  --arg nix "$(nix --version)" \
  '{source: {trees: $trees, staged_crates_commit: $commit, note: "the git trees the packages were built from: compare with git rev-parse <commit>:<path>"},
    platform: $platform, lgx_package: $lgx, nix: $nix, signed: false, packages: .}' > "$out/build.json"
(cd "$out/$platform" && sha256sum ./*.lgx | sed 's| \./| |') > "$out/$platform/SHA256SUMS"
echo "build-lgx.sh: $(jq '.packages | length' "$out/build.json") packages from $commit in $out/$platform"
