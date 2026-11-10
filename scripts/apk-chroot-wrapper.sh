#!/usr/bin/env bash
set -euo pipefail

ROOT="${APK_CHROOT_ROOT:?APK_CHROOT_ROOT is required}"
ALLOWED_ROOTS="${APK_CHROOT_ALLOWED_ROOTS:?APK_CHROOT_ALLOWED_ROOTS is required}"
[[ -d "$ROOT" && ! -L "$ROOT" ]] || { echo "invalid APK chroot root" >&2; exit 2; }
ROOT="$(realpath "$ROOT")"

case "${1:-}" in
  --version)
    (( $# == 1 )) || { echo "unsupported apk command" >&2; exit 2; }
    exec sudo chroot "$ROOT" /sbin/apk --version
    ;;
  version)
    if (( $# != 4 )) || [[ "${2:-}" != "-t" ]]; then
      echo "unsupported apk version command" >&2
      exit 2
    fi
    [[ "$3" =~ ^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,255}$ && "$4" =~ ^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,255}$ ]] || {
      echo "invalid apk version operand" >&2; exit 2;
    }
    exec sudo chroot "$ROOT" /sbin/apk version -t "$3" "$4"
    ;;
  adbdump)
    if (( $# != 4 )) || [[ "${2:-}" != "--format" || "${3:-}" != "json" ]]; then
      echo "unsupported apk adbdump command" >&2
      exit 2
    fi
    SOURCE="$4"
    [[ -f "$SOURCE" && ! -L "$SOURCE" ]] || { echo "APK input must be a regular non-symlink file" >&2; exit 2; }
    SOURCE="$(realpath "$SOURCE")"
    permitted=false
    IFS=: read -r -a roots <<< "$ALLOWED_ROOTS"
    for allowed in "${roots[@]}"; do
      [[ -n "$allowed" && -d "$allowed" && ! -L "$allowed" ]] || continue
      allowed="$(realpath "$allowed")"
      if [[ "$SOURCE" == "$allowed" || "$SOURCE" == "$allowed/"* ]]; then
        permitted=true
        break
      fi
    done
    [[ "$permitted" == true ]] || { echo "APK input is outside allowed roots" >&2; exit 2; }
    SIZE="$(wc -c < "$SOURCE" | tr -d '[:space:]')"
    (( SIZE > 0 && SIZE <= 536870912 )) || { echo "APK input size is invalid" >&2; exit 2; }
    INGRESS_ROOT="$ROOT/host-apk"
    [[ -d "$INGRESS_ROOT" && ! -L "$INGRESS_ROOT" ]] || { echo "APK ingress is unavailable" >&2; exit 2; }
    INGRESS="$(mktemp -d "$INGRESS_ROOT/request.XXXXXX")"
    trap 'rm -rf -- "$INGRESS"' EXIT
    cp -- "$SOURCE" "$INGRESS/package.apk"
    chmod 0444 "$INGRESS/package.apk"
    CHROOT_PATH="${INGRESS#"$ROOT"}/package.apk"
    sudo chroot "$ROOT" /sbin/apk adbdump --format json "$CHROOT_PATH"
    ;;
  *)
    echo "unsupported apk command" >&2
    exit 2
    ;;
esac
