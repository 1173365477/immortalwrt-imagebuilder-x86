#!/usr/bin/env bash
set -euo pipefail

VERSION="${IMMORTALWRT_VERSION:-25.12.2}"
PROFILE="${PROFILE:-generic}"
ROOTFS_SIZE="${ROOTFS_SIZE:-8192}"
TARGET_DIR="x86/64"
BASE_URL="https://downloads.immortalwrt.org/releases/${VERSION}/targets/${TARGET_DIR}"
ARCHIVE="immortalwrt-imagebuilder-${VERSION}-x86-64.Linux-x86_64.tar.zst"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$VERSION" in
  25.12.*) ;;
  *) echo "Refusing unsupported version outside 25.12.x: $VERSION" >&2; exit 2 ;;
esac
[[ "$ROOTFS_SIZE" =~ ^[0-9]+$ ]] || { echo "ROOTFS_SIZE must be an integer MiB value" >&2; exit 2; }
[[ "$PROFILE" == "generic" ]] || { echo "Only PROFILE=generic is supported" >&2; exit 2; }

mkdir -p "$REPO_ROOT/work" "$REPO_ROOT/generated/firmware"
BUILD_DIR="$(mktemp -d "$REPO_ROOT/work/imagebuilder.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

echo "ImageBuilder URL: ${BASE_URL}/${ARCHIVE}"
curl -fL --retry 3 --connect-timeout 20 -o "$BUILD_DIR/sha256sums" "${BASE_URL}/sha256sums"
curl -fL --retry 3 --connect-timeout 20 -o "$BUILD_DIR/$ARCHIVE" "${BASE_URL}/${ARCHIVE}"

EXPECTED="$(awk -v file="$ARCHIVE" '$2 == "*" file || $2 == file {print $1; exit}' "$BUILD_DIR/sha256sums")"
[[ "$EXPECTED" =~ ^[0-9a-f]{64}$ ]] || { echo "ImageBuilder checksum not found in official sha256sums" >&2; exit 1; }
printf '%s  %s\n' "$EXPECTED" "$BUILD_DIR/$ARCHIVE" | sha256sum -c -

tar --zstd -xf "$BUILD_DIR/$ARCHIVE" -C "$BUILD_DIR"
IMAGEBUILDER_DIR="$(find "$BUILD_DIR" -mindepth 1 -maxdepth 1 -type d -name 'immortalwrt-imagebuilder-*' -print -quit)"
[[ -n "$IMAGEBUILDER_DIR" ]] || { echo "Extracted ImageBuilder directory not found" >&2; exit 1; }

PACKAGES="$(tr '\n' ' ' < "$REPO_ROOT/generated/final-packages.txt" | xargs)"
echo "Source version: $(jq -r '.source_version // "unknown"' "$REPO_ROOT/generated/system-analysis.json")"
echo "Target version: $VERSION"
echo "Target/profile/rootfs: x86/64 / $PROFILE / ext4 (EFI), ${ROOTFS_SIZE} MiB"
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

PRIMARY="$(find "$OUTPUT_DIR" -maxdepth 1 -type f -name "immortalwrt-${VERSION}-x86-64-generic-ext4-combined-efi.img.gz" -print -quit)"
[[ -n "$PRIMARY" ]] || { echo "Primary generic ext4 combined EFI image was not produced" >&2; exit 1; }
rm -f "$REPO_ROOT/generated/firmware/"*
cp "$PRIMARY" "$REPO_ROOT/generated/firmware/"
find "$OUTPUT_DIR" -maxdepth 1 -type f \( -name '*.manifest' -o -name '*.bom.cdx.json' \) -exec cp {} "$REPO_ROOT/generated/firmware/" \;
cp "$REPO_ROOT/generated/migration-report.md" "$REPO_ROOT/generated/system-analysis.json" \
  "$REPO_ROOT/generated/final-packages.txt" "$REPO_ROOT/generated/firmware/"
if [[ -f "$REPO_ROOT/generated/thirdparty-assets.json" ]]; then
  cp "$REPO_ROOT/generated/thirdparty-assets.json" "$REPO_ROOT/generated/thirdparty-sha256sums" "$REPO_ROOT/generated/firmware/"
fi

(
  cd "$REPO_ROOT/generated/firmware"
  sha256sum immortalwrt-*.img.gz > sha256sums
  echo "Primary image:"
  ls -lh immortalwrt-*-generic-ext4-combined-efi.img.gz
  cat sha256sums
)

