#!/usr/bin/env bash
set -euo pipefail

VERSION="${IMMORTALWRT_VERSION:-25.12.2}"
PROFILE="${PROFILE:-generic}"
ROOTFS_SIZE="${ROOTFS_SIZE:-8192}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPABILITIES="$REPO_ROOT/generated/release-capabilities.json"

cd "$REPO_ROOT"
python3 -c 'import sys; sys.path.insert(0, "scripts"); from release_utils import parse_version; parse_version(sys.argv[1])' "$VERSION"
if [[ ! "$ROOTFS_SIZE" =~ ^[0-9]+$ ]] || (( ROOTFS_SIZE <= 0 )); then
  echo "ROOTFS_SIZE must be a positive integer MiB value" >&2
  exit 2
fi
[[ -f "$CAPABILITIES" ]] || { echo "Missing release capability file: $CAPABILITIES" >&2; exit 2; }
[[ "$PROFILE" == "$(jq -r '.profile' "$CAPABILITIES")" ]] || {
  echo "Requested PROFILE does not match the validated release capability" >&2
  exit 2
}
[[ "$VERSION" == "$(jq -r '.target_version' "$CAPABILITIES")" ]] || {
  echo "Requested version does not match the validated release capability" >&2
  exit 2
}
PACKAGE_MANAGER="$(jq -r '.package_manager' "$CAPABILITIES")"
[[ "$PACKAGE_MANAGER" == "apk" ]] || {
  echo "Unsupported target package manager: $PACKAGE_MANAGER. This project currently supports APK targets only." >&2
  exit 2
}

SUMS_URL="$(jq -r '.sha256sums_url' "$CAPABILITIES")"
ARCHIVE="$(jq -r '.imagebuilder_filename' "$CAPABILITIES")"
EXPECTED_ARCHIVE_SHA="$(jq -r '.imagebuilder_sha256' "$CAPABILITIES")"
IMAGEBUILDER_URL="$(jq -r '.imagebuilder_url' "$CAPABILITIES")"
EXPECTED_IMAGE="$(jq -r '.expected_image_name' "$CAPABILITIES")"
TARGET="$(jq -r '.target' "$CAPABILITIES")"
FILESYSTEM="$(jq -r '.filesystem' "$CAPABILITIES")"
IMAGE_TYPE="$(jq -r '.image_type' "$CAPABILITIES")"

mkdir -p "$REPO_ROOT/work" "$REPO_ROOT/generated/firmware"
BUILD_DIR="$(mktemp -d "$REPO_ROOT/work/imagebuilder.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "ImageBuilder URL: $IMAGEBUILDER_URL"
curl -fL --retry 3 --connect-timeout 20 -o "$BUILD_DIR/sha256sums" "$SUMS_URL"
curl -fL --retry 3 --connect-timeout 20 -o "$BUILD_DIR/$ARCHIVE" "$IMAGEBUILDER_URL"

OFFICIAL_SHA="$(awk -v file="$ARCHIVE" '$2 == "*" file || $2 == file {print $1; exit}' "$BUILD_DIR/sha256sums")"
[[ "$OFFICIAL_SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "ImageBuilder checksum not found in official sha256sums" >&2; exit 1; }
[[ "$OFFICIAL_SHA" == "$EXPECTED_ARCHIVE_SHA" ]] || {
  echo "ImageBuilder checksum changed after validation; refusing the download" >&2
  exit 1
}
printf '%s  %s\n' "$OFFICIAL_SHA" "$BUILD_DIR/$ARCHIVE" | sha256sum -c -

case "$ARCHIVE" in
  *.tar.zst|*.tar.xz|*.tar.gz) tar -xf "$BUILD_DIR/$ARCHIVE" -C "$BUILD_DIR" ;;
  *) echo "Unsupported ImageBuilder archive format: $ARCHIVE" >&2; exit 2 ;;
esac
mapfile -t IMAGEBUILDER_DIRS < <(find "$BUILD_DIR" -mindepth 1 -maxdepth 1 -type d -name 'immortalwrt-imagebuilder-*' -print)
(( ${#IMAGEBUILDER_DIRS[@]} == 1 )) || { echo "Expected exactly one extracted ImageBuilder directory" >&2; exit 1; }
IMAGEBUILDER_DIR="${IMAGEBUILDER_DIRS[0]}"

PACKAGES="$(xargs < "$REPO_ROOT/generated/final-packages.txt")"
echo "Source version: $(jq -r '.source_version // "unknown"' "$REPO_ROOT/generated/system-analysis.json")"
echo "Target version: $VERSION"
echo "Target/profile/rootfs/image: $TARGET / $PROFILE / $FILESYSTEM / $IMAGE_TYPE, ${ROOTFS_SIZE} MiB"
echo "Package manager: $PACKAGE_MANAGER"
echo "Base package list:"
sed 's/^/  /' "$REPO_ROOT/config/base-packages.txt"
echo "Dynamically resolved official packages:"
sed 's/^/  /' "$REPO_ROOT/generated/packages-official.txt"
echo "Third-party packages:"
sed 's/^/  /' "$REPO_ROOT/generated/packages-thirdparty.txt"
echo "Missing packages:"
sed 's/^/  /' "$REPO_ROOT/generated/packages-missing.txt"
echo "Skipped packages:"
sed 's/^/  /' "$REPO_ROOT/generated/packages-skipped.txt"
echo "Replacements:"
sed 's/^/  /' "$REPO_ROOT/generated/packages-replaced.txt"
echo "Downgrade warnings:"
jq -r '.packages | to_entries[] | select(.value.status == "downgrade") | "  \(.key): \(.value.from) -> \(.value.to)"' "$REPO_ROOT/generated/system-analysis.json"
echo "Third-party compatibility:"
if [[ -f "$REPO_ROOT/generated/thirdparty-status.json" ]]; then
  jq -r 'to_entries[] | "  \(.key): \(.value.status) - \(.value.reason // .value.release // "")"' "$REPO_ROOT/generated/thirdparty-status.json"
fi
echo "Bundled APK files:"
find "$REPO_ROOT/files/root/thirdparty" -maxdepth 1 -type f -name '*.apk' -print 2>/dev/null | sed 's/^/  /' || true

make -C "$IMAGEBUILDER_DIR" image \
  PROFILE="$PROFILE" \
  PACKAGES="$PACKAGES" \
  FILES="$REPO_ROOT/files" \
  ROOTFS_PARTSIZE="$ROOTFS_SIZE"

OUTPUT_DIR="$IMAGEBUILDER_DIR/bin/targets/x86/64"
echo "ImageBuilder output in bin/targets/x86/64/:"
find "$OUTPUT_DIR" -maxdepth 1 -type f -printf '  %f\t%s bytes\n' | sort

PRIMARY="$OUTPUT_DIR/$EXPECTED_IMAGE"
[[ -f "$PRIMARY" ]] || {
  echo "Validated primary image was not produced: $EXPECTED_IMAGE" >&2
  echo "Available files:" >&2
  find "$OUTPUT_DIR" -maxdepth 1 -type f -printf '  %f\n' >&2
  exit 1
}
find "$REPO_ROOT/generated/firmware" -mindepth 1 -maxdepth 1 -type f -delete
cp "$PRIMARY" "$REPO_ROOT/generated/firmware/"
find "$OUTPUT_DIR" -maxdepth 1 -type f \( -name '*.manifest' -o -name '*.bom.cdx.json' \) -exec cp {} "$REPO_ROOT/generated/firmware/" \;
for evidence in \
  migration-report.md compatibility-report.md system-analysis.json release-capabilities.json \
  thirdparty-assets.json thirdparty-status.json thirdparty-sha256sums final-packages.txt; do
  [[ -f "$REPO_ROOT/generated/$evidence" ]] && cp "$REPO_ROOT/generated/$evidence" "$REPO_ROOT/generated/firmware/"
done

(
  cd "$REPO_ROOT/generated/firmware"
  sha256sum "$EXPECTED_IMAGE" > sha256sums
  echo "Primary image:"
  ls -lh "$EXPECTED_IMAGE"
  cat sha256sums
)

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  OFFICIAL_COUNT="$(grep -cve '^\s*$' "$REPO_ROOT/generated/packages-official.txt" || true)"
  THIRD_COUNT="$(find "$REPO_ROOT/files/root/thirdparty" -maxdepth 1 -name '*.apk' -type f | wc -l | xargs)"
  MISSING_COUNT="$(grep -cve '^\s*$' "$REPO_ROOT/generated/packages-missing.txt" || true)"
  DOWNGRADE_COUNT="$(jq '[.packages[] | select(.status == "downgrade")] | length' "$REPO_ROOT/generated/system-analysis.json")"
  IMAGE_SIZE="$(stat -c '%s' "$PRIMARY")"
  IMAGE_SHA="$(sha256sum "$PRIMARY" | awk '{print $1}')"
  REPORT_SOURCE="$(jq -r '.source_version // "unknown"' "$REPO_ROOT/generated/system-analysis.json")"
  BUILD_LABEL="SUCCESS"
  if [[ -f "$REPO_ROOT/generated/thirdparty-status.json" ]] && \
    jq -e 'to_entries | any(.value.status == "unresolved" or .value.status == "incompatible")' \
      "$REPO_ROOT/generated/thirdparty-status.json" >/dev/null; then
    BUILD_LABEL="SUCCESS WITH WARNINGS"
  fi
  {
    echo "## ImmortalWrt build summary"
    echo
    echo "- Target: \`$VERSION\` / \`$TARGET\` / \`$PROFILE\` / \`$FILESYSTEM-$IMAGE_TYPE\`"
    echo "- Report source version: \`$REPORT_SOURCE\`"
    echo "- Strict mode: \`${STRICT_MODE:-unknown}\`"
    echo "- Build: **$BUILD_LABEL**"
    echo "- ImageBuilder: \`$ARCHIVE\`"
    echo "- Official package tokens: $OFFICIAL_COUNT"
    echo "- Bundled third-party APKs: $THIRD_COUNT"
    echo "- Unresolved packages: $MISSING_COUNT"
    echo "- Downgrade warnings: $DOWNGRADE_COUNT"
    echo "- Firmware: \`$EXPECTED_IMAGE\` ($IMAGE_SIZE bytes)"
    echo "- SHA256: \`$IMAGE_SHA\`"
    if [[ -f "$REPO_ROOT/generated/thirdparty-status.json" ]]; then
      echo
      echo "### Third-party providers"
      jq -r 'to_entries[] | "- **\(.key)**: \(.value.status) — \(.value.reason // .value.release // "")"' "$REPO_ROOT/generated/thirdparty-status.json"
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi
