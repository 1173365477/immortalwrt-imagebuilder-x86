#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_INPUT="${BUILD_INPUT:-}"
TRUSTED_REPOSITORY="${TRUSTED_REPOSITORY:-}"
TRUSTED_COMMIT="${TRUSTED_COMMIT:-}"
RUN_ID="${GITHUB_RUN_ID:-1}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"

[[ -n "$BUILD_INPUT" && -n "$TRUSTED_REPOSITORY" && -n "$TRUSTED_COMMIT" ]] || {
  echo "Immutable BUILD_INPUT, TRUSTED_REPOSITORY, and TRUSTED_COMMIT are required; legacy analysis inputs cannot build." >&2
  exit 2
}

cd "$REPO_ROOT"
mkdir -p generated work
STAGE="$(mktemp -d "$REPO_ROOT/work/verified-build.XXXXXX")"
BUILD_DIR="$(mktemp -d "$REPO_ROOT/work/imagebuilder.XXXXXX")"
trap 'rm -rf "$STAGE" "$BUILD_DIR"' EXIT

python3 scripts/verify-build-input.py \
  --input "$BUILD_INPUT" --repo-root "$REPO_ROOT" \
  --repository "$TRUSTED_REPOSITORY" --commit "$TRUSTED_COMMIT" \
  --stage "$STAGE" --output "$STAGE/context.json"
chmod -R a-w "$STAGE"

CONTEXT="$STAGE/context.json"
VERSION="$(jq -r '.target.version' "$CONTEXT")"
PROFILE="$(jq -r '.target.profile' "$CONTEXT")"
ROOTFS_SIZE="$(jq -r '.build.rootfs_size_mib' "$CONTEXT")"
ARCHIVE="$(jq -r '.release.imagebuilder_filename' "$CONTEXT")"
IMAGEBUILDER_URL="$(jq -r '.release.imagebuilder_url' "$CONTEXT")"
EXPECTED_ARCHIVE_SHA="$(jq -r '.release.imagebuilder_sha256' "$CONTEXT")"
EXPECTED_IMAGE="$(jq -r '.target.expected_image_name' "$CONTEXT")"
TARGET="$(jq -r '.target.target' "$CONTEXT")"
SUBTARGET="$(jq -r '.target.subtarget' "$CONTEXT")"
FILESYSTEM="$(jq -r '.target.filesystem' "$CONTEXT")"
IMAGE_TYPE="$(jq -r '.target.image_type' "$CONTEXT")"
EXPECTED_APK_TOOLS="$(jq -r '.build.apk_tools_version' "$CONTEXT")"

if command -v apk >/dev/null 2>&1; then
  ACTUAL_APK_TOOLS="$(apk --version 2>&1 | head -1)"
  [[ "$ACTUAL_APK_TOOLS" == *"$EXPECTED_APK_TOOLS"* ]] || {
    echo "apk-tools version does not match frozen build input" >&2
    exit 2
  }
else
  echo "apk-tools is required to reproduce target version comparison" >&2
  exit 2
fi

echo "Downloading frozen ImageBuilder: $IMAGEBUILDER_URL"
curl -fL --retry 3 --connect-timeout 20 --proto '=https' -o "$BUILD_DIR/$ARCHIVE" "$IMAGEBUILDER_URL"
printf '%s  %s\n' "$EXPECTED_ARCHIVE_SHA" "$BUILD_DIR/$ARCHIVE" | sha256sum -c -

case "$ARCHIVE" in
  *.tar.zst|*.tar.xz|*.tar.gz) tar -xf "$BUILD_DIR/$ARCHIVE" -C "$BUILD_DIR" ;;
  *) echo "Unsupported ImageBuilder archive format: $ARCHIVE" >&2; exit 2 ;;
esac
mapfile -t IMAGEBUILDER_DIRS < <(find "$BUILD_DIR" -mindepth 1 -maxdepth 1 -type d -name '*imagebuilder-*' -print)
(( ${#IMAGEBUILDER_DIRS[@]} == 1 )) || { echo "Expected exactly one extracted ImageBuilder directory" >&2; exit 1; }
IMAGEBUILDER_DIR="${IMAGEBUILDER_DIRS[0]}"

[[ "$(sha256sum "$STAGE/final-packages.txt" | awk '{print $1}')" == "$(jq -r '.staged_packages_sha256' "$CONTEXT")" ]] || {
  echo "Verified package stage changed before build" >&2; exit 2;
}
python3 - "$STAGE/files" "$CONTEXT" <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, "scripts")
from build_evidence import tree_digest
context = json.loads(Path(sys.argv[2]).read_text())
if tree_digest(Path(sys.argv[1])) != context["staged_files_digest"]:
    raise SystemExit("Verified files stage changed before build")
PY

PACKAGES="$(xargs < "$STAGE/final-packages.txt")"
echo "Immutable target: $VERSION / $TARGET/$SUBTARGET / $PROFILE / $FILESYSTEM-$IMAGE_TYPE"
make -C "$IMAGEBUILDER_DIR" image \
  PROFILE="$PROFILE" PACKAGES="$PACKAGES" FILES="$STAGE/files" ROOTFS_PARTSIZE="$ROOTFS_SIZE"

OUTPUT_DIR="$IMAGEBUILDER_DIR/bin/targets/$TARGET/$SUBTARGET"
PRIMARY="$OUTPUT_DIR/$EXPECTED_IMAGE"
[[ -f "$PRIMARY" ]] || { echo "Frozen primary image was not produced: $EXPECTED_IMAGE" >&2; exit 1; }
rm -rf "$REPO_ROOT/generated/firmware"
mkdir -p "$REPO_ROOT/generated/firmware"
cp "$PRIMARY" "$REPO_ROOT/generated/firmware/"

python3 scripts/generate-build-provenance.py \
  --input "$BUILD_INPUT" --repo-root "$REPO_ROOT" \
  --repository "$TRUSTED_REPOSITORY" --commit "$TRUSTED_COMMIT" \
  --run-id "$RUN_ID" --run-attempt "$RUN_ATTEMPT" \
  --firmware "$REPO_ROOT/generated/firmware/$EXPECTED_IMAGE" \
  --output "$REPO_ROOT/generated/firmware/build-provenance-v1.json"
(
  cd "$REPO_ROOT/generated/firmware"
  sha256sum "$EXPECTED_IMAGE" > sha256sums
)

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Immutable firmware build"
    echo
    echo "- Request: \`$(jq -r '.request_id' "$CONTEXT")\`"
    echo "- Build input: \`$(jq -r '.build_input_digest' "$CONTEXT")\`"
    echo "- Migration plan: \`$(jq -r '.plan_digest' "$CONTEXT")\`"
    echo "- Firmware: \`$EXPECTED_IMAGE\`"
    echo "- flash_ready: \`false\`"
  } >> "$GITHUB_STEP_SUMMARY"
fi
