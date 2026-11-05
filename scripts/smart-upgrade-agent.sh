#!/bin/sh
# Smart Upgrade device probe. Read-only, BusyBox ash/awk compatible.
# Usage: sh scripts/smart-upgrade-agent.sh [--root DIR] [--privacy local|redacted]
set -eu
LC_ALL=C
export LC_ALL
ROOT=/
PRIVACY=redacted
FIXTURE_DIR=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) [ "$#" -ge 2 ] || exit 2; ROOT=$2; shift 2 ;;
    --privacy) [ "$#" -ge 2 ] || exit 2; PRIVACY=$2; shift 2 ;;
    --fixture-dir) [ "$#" -ge 2 ] || exit 2; FIXTURE_DIR=$2; shift 2 ;;
    *) echo "unknown option" >&2; exit 2 ;;
  esac
done
case "$PRIVACY" in local|redacted) ;; *) exit 2 ;; esac
[ -d "$ROOT" ] || { echo "root does not exist" >&2; exit 2; }
if [ -n "$FIXTURE_DIR" ] && [ ! -d "$FIXTURE_DIR" ]; then
  echo "fixture directory does not exist" >&2
  exit 2
fi
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
export ROOT PRIVACY FIXTURE_DIR
SOURCE_DIGEST=$(
  for evidence_file in \
    "$ROOT/etc/openwrt_release" "$ROOT/etc/os-release" \
    "$ROOT/usr/lib/opkg/status" "$ROOT/lib/apk/db/installed" \
    "$ROOT/etc/apk/world" "$ROOT/proc/self/mountinfo"; do
    [ -r "$evidence_file" ] && sha256sum "$evidence_file" | awk '{print $1}'
  done | sha256sum | awk '{print $1}'
)
UBUS_BOARD=""; UNAME_M=""; PACKAGE_ARCH=""; BOOT_OVERRIDE=""
if [ -n "$FIXTURE_DIR" ]; then
  [ ! -r "$FIXTURE_DIR/ubus-system-board.json" ] || UBUS_BOARD=$(sed -n '1,80p' "$FIXTURE_DIR/ubus-system-board.json")
  [ ! -r "$FIXTURE_DIR/uname.txt" ] || IFS= read -r UNAME_M < "$FIXTURE_DIR/uname.txt" || true
  [ ! -r "$FIXTURE_DIR/package-arch.txt" ] || IFS= read -r PACKAGE_ARCH < "$FIXTURE_DIR/package-arch.txt" || true
  [ ! -r "$FIXTURE_DIR/boot-mode.txt" ] || IFS= read -r BOOT_OVERRIDE < "$FIXTURE_DIR/boot-mode.txt" || true
elif [ "$ROOT" = / ]; then
  UNAME_M=$(uname -m 2>/dev/null || true)
  command -v ubus >/dev/null 2>&1 && UBUS_BOARD=$(timeout 2 ubus call system board 2>/dev/null || true)
  if command -v apk >/dev/null 2>&1; then PACKAGE_ARCH=$(apk --print-arch 2>/dev/null || true)
  elif command -v opkg >/dev/null 2>&1; then PACKAGE_ARCH=$(opkg print-architecture 2>/dev/null | awk 'END{print $2}' || true)
  fi
fi
STORAGE_JSON=$(sh "$SCRIPT_DIR/smart-upgrade-storage.sh") || {
  echo "storage analysis failed" >&2
  exit 1
}
SERVICE_ROWS=""
if [ -n "$FIXTURE_DIR" ] && [ -r "$FIXTURE_DIR/service-status.tsv" ]; then
  SERVICE_ROWS=$(sed -n '1,16p' "$FIXTURE_DIR/service-status.tsv")
elif [ "$ROOT" = / ] && command -v ubus >/dev/null 2>&1; then
  for service_name in openclash lucky adguardhome dockerd; do
    state=unknown
    output=$(timeout 2 ubus call service list "{\"name\":\"$service_name\"}" 2>/dev/null || true)
    case "$output" in *'"running": true'*) state=running ;; *'"running": false'*) state=stopped ;; esac
    SERVICE_ROWS="${SERVICE_ROWS}${SERVICE_ROWS:+
}${service_name}	${state}"
  done
fi
# Only reads explicitly enumerated OS and package database paths; never shells out to
# data from those files, contacts the Docker socket, or sources device config.
awk -v root="$ROOT" -v privacy="$PRIVACY" -v storage_json="$STORAGE_JSON" -v service_rows="$SERVICE_ROWS" \
  -v source_digest="$SOURCE_DIGEST" -v ubus_board="$UBUS_BOARD" -v uname_m="$UNAME_M" \
  -v package_arch="$PACKAGE_ARCH" -v boot_override="$BOOT_OVERRIDE" '
function esc(s,   x) {
  gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s)
  gsub(/\r/, "", s); gsub(/\t/, " ", s); gsub(/\n/, " ", s)
  gsub(/[^[:print:]]/, "?", s)
  if(length(s)>8192)s=substr(s,1,8192)
  return s
}
function q(s) { return "\"" esc(s) "\"" }
function field(k,v,  z) { z=v; sub(/^[^=]*=/,"",z); gsub(/^[ "\047]+|[ "\047]+$/,"",z); return z }
function get_release(  line,a,k,v,fn) {
 fn=root "/etc/openwrt_release"
 while ((getline line < fn)>0) {
   split(line,a,"="); k=a[1]; v=field(k,line)
   if(k=="DISTRIB_ID") distro=v
   if(k=="DISTRIB_RELEASE") version=v
   if(k=="DISTRIB_TARGET") target=v
   if(k=="DISTRIB_ARCH") arch=v
   if(k=="DISTRIB_IMAGE_TYPE") image_type=v
 }
 close(fn)
 fn=root "/etc/os-release"
 while ((getline line < fn)>0) {
   split(line,a,"=");k=a[1];v=field(k,line)
   if(version=="" && k=="VERSION_ID")version=v
   if(target=="" && k=="OPENWRT_BOARD")target=v
   if(arch=="" && k=="OPENWRT_ARCH")arch=v
 }
 close(fn)
 if(profile=="" && match(ubus_board,/"board_name"[[:space:]]*:[[:space:]]*"[^"]+"/)){
   v=substr(ubus_board,RSTART,RLENGTH);sub(/^.*"board_name"[[:space:]]*:[[:space:]]*"/,"",v);sub(/"$/,"",v);profile=v
 }
 if (distro=="") distro="unknown"
}
function identity(  fn,line,a,dash) {
 rootfs="unknown";fn=root "/proc/self/mountinfo"
 while((getline line < fn)>0){n=split(line,a," ");if(a[5]=="/"){for(i=7;i<=n;i++)if(a[i]=="-"){rootfs=a[i+1];break}}}
 close(fn)
 boot="unknown"
 if(boot_override~/^(efi|bios|unknown)$/)boot=boot_override
 else if(exists(root "/sys/firmware/efi/systab"))boot="efi"
 else if((target~/^x86\//||uname_m~/^(x86_64|i[3-6]86)$/) && exists(root "/sys/class/dmi/id/bios_vendor"))boot="bios"
 if(image_type=="")image_type="unknown"
 identity_ok=1;identity_errors=""
 if(target~/^x86\/64$/ && uname_m!="" && uname_m!="x86_64"){identity_ok=0;identity_errors="target_uname_arch_mismatch"}
 if(arch!=""&&package_arch!=""&&arch!=package_arch){identity_ok=0;identity_errors=identity_errors (identity_errors!=""?",":"") "release_package_arch_mismatch"}
}
function read_provenance(  fn,line,p) {
 fn=root "/etc/apk/world"
 while ((getline line < fn)>0) {
   sub(/[[:space:]<>=~].*$/, "", line)
   if (line ~ /^[A-Za-z0-9][A-Za-z0-9+_.@-]*$/) world[line]=1
 }
 close(fn)
 fn=root "/rom/usr/lib/opkg/status"
 while ((getline line < fn)>0) if(line~/^Package: /)rom[substr(line,10)]=1
 close(fn)
 fn=root "/rom/lib/apk/db/installed"
 while ((getline line < fn)>0) if(line~/^P:/)rom[substr(line,3)]=1
 close(fn)
}
function emit_package(  name,origin,reason,confidence,dep,raw,j,installed) {
 if(pkg=="") return
 if(pkg !~ /^[A-Za-z0-9][A-Za-z0-9+_.@-]*$/) {pkg="";return}
 installed=(manager=="apk" || status=="" || tolower(status) ~ /(^|[[:space:]])installed($|[[:space:]])/)
 if(!installed){pkg=ver=auto=deps=status=provides="";return}
 if(count>=4096){package_truncated=1;pkg=ver=auto=deps=status=provides="";return}
 name=pkg; names[count+1]=name; origin="unknown";reason="unknown";confidence="low"
 if(rom[name]) {origin="official";reason="system_default";confidence="high";proof="firmware-rom-baseline"}
 else if(manager=="opkg" && auto ~ /^(yes|true|1)$/) {reason="dependency";confidence="high";proof="opkg-auto-installed:true"}
 else if(manager=="opkg" && auto ~ /^(no|false|0)$/) {reason="manual";confidence="medium";proof="opkg-auto-installed:false";top[++top_count]=name}
 else if(manager=="apk" && world[name]) {proof="apk-world-candidate";confidence="low";intent[++intent_count]=name}
 else proof=(manager=="apk"?"apk-installed-db":"opkg-status-installed")
 if(count>0) printf ","
 printf "{\"name\":%s,\"version\":%s,\"origin\":%s,\"install_reason\":%s,\"confidence\":%s,\"evidence\":[%s],\"dependencies_raw\":%s,\"depends\":[",q(name),ver==""?"null":q(ver),q(origin),q(reason),q(confidence),q(proof),deps==""?"null":q(deps)
 raw=deps;n=split(raw,ds,manager=="apk"?/[[:space:]]+/:",")
 for(i=1;i<=n&&j<256;i++){dep=ds[i];gsub(/^[ \t]+|[ \t]+$/,"",dep);if(dep!=""){if(j++>0)printf ",";printf "{\"raw\":%s",q(substr(dep,1,1024));if(match(dep,/^[A-Za-z0-9][A-Za-z0-9+_.@-]*/))printf ",\"name\":%s",q(substr(dep,RSTART,RLENGTH));else printf ",\"name\":null,\"parse_error\":\"unrecognized-dependency-expression\"";printf "}"}}
 printf "],\"provides_raw\":%s}",provides==""?"null":q(provides)
 pkg=ver=auto=deps=status=provides="";j=0;count++
}
function opkg(  line,kv) {
 fn=root "/usr/lib/opkg/status"
 while ((getline line < fn)>0) {
   if(line==""){emit_package();continue}
   if(line~/^Package: /) pkg=substr(line,10)
   else if(line~/^Version: /) ver=substr(line,10)
   else if(line~/^Depends: /) deps=substr(line,10)
   else if(line~/^Auto-Installed: /) auto=substr(line,17)
   else if(line~/^Status: /) status=substr(line,9)
   else if(line~/^Provides: /) provides=substr(line,11)
 }
 emit_package();close(fn)
}
function apk(  line) {
 fn=root "/lib/apk/db/installed"
 while ((getline line < fn)>0) {
   if(line==""){emit_package();continue}
   if(line~/^P:/)pkg=substr(line,3)
   else if(line~/^V:/)ver=substr(line,3)
   else if(line~/^D:/) deps=substr(line,3)
   else if(line~/^p:/) provides=substr(line,3)
 }
 emit_package();close(fn)
}
function exists(path,  line,x){x=(getline line < path);close(path);return x>=0}
function file_present(path, line,x) {x=(getline line < path);close(path);return x>=0}
function service(name,pattern,exe,init,   detected,running,z) {
 detected=0
 if(manager=="unknown")detected=-1
 else for(z=1;z<=count;z++)if(names[z]~pattern)detected=1
 running=svc_state[name];if(running=="")running="unknown"
 return "{\"package_detected\":" (detected<0?"null":(detected?"true":"false")) ",\"executable_exists\":" (file_present(root exe)?"true":"false") ",\"service_definition_exists\":" (file_present(root init)?"true":"false") ",\"running\":" q(running) "}"
}
function load_storage(  fn,line,parts,val) {
 docker_root=""; docker_source="unknown"; mount_count=0; mounts_available=0
 fn=root "/etc/config/dockerd"
 while ((getline line < fn)>0) {
   if (line ~ /^[[:space:]]*option[[:space:]]+data_root[[:space:]]+/) {
     val=line
     sub(/^[[:space:]]*option[[:space:]]+data_root[[:space:]]+/, "", val)
     gsub(/^[[:space:]]*["\047]|["\047][[:space:]]*$/, "", val)
     if(val ~ /^\// && length(val)<=256) {docker_root=val;docker_source="uci-config"}
   }
 }
 close(fn)
 # JSON daemon data-root may be specified on a single line, but UCI setting
 # and command-line overrides can still change the effective daemon root.
 fn=root "/etc/docker/daemon.json"
 while ((getline line < fn)>0) {
   if (line ~ /"data-root"[[:space:]]*:/) {
     val=line
     sub(/^.*"data-root"[[:space:]]*:[[:space:]]*"/, "", val)
     sub(/".*$/, "", val)
     if(val ~ /^\// && length(val)<=256) {docker_root=val;docker_source="daemon-json"}
   }
 }
 close(fn)
 fn=root "/proc/mounts"
 while ((getline line < fn)>0) {
   mounts_available=1
   split(line,parts,/[[:space:]]+/)
   if(mount_count<128 && parts[2] ~ /^\//) {
     mount_source[++mount_count]=parts[1]
     mount_path[mount_count]=parts[2]
     mount_type[mount_count]=parts[3]
   }
 }
 close(fn)
}
function render_storage(  i) {
 printf "\"storage\":{\"docker_root\":%s,",privacy=="local" && docker_root!=""?q(docker_root):"null"
 printf "\"docker_root_source\":%s,\"docker_root_verified\":false,",q(docker_source)
 printf "\"mounts\":["
 for(i=1;i<=mount_count;i++) {
   if(i>1)printf ","
   printf "{\"source\":%s,\"mountpoint\":%s,\"filesystem\":%s}",privacy=="local"?q(mount_source[i]):"null",privacy=="local"?q(mount_path[i]):"null",q(mount_type[i])
 }
 printf "],\"warnings\":[\"Docker Root Dir is configured only, not runtime verified; check Docker daemon and persistent volume mounts manually\""
 if(!mounts_available)printf ",\"/proc/mounts unavailable\""
 if(mount_count>=128)printf ",\"mount list truncated at 128 entries\""
 printf "]},"
}
BEGIN {
 get_release()
 identity()
 read_provenance()
 sn=split(service_rows,srows,"\n");for(si=1;si<=sn;si++){split(srows[si],sf,"\t");if(sf[1]~/^[a-zA-Z0-9_-]+$/&&sf[2]~/^(running|stopped|unknown)$/)svc_state[sf[1]]=sf[2]}
 manager="unknown"
 if(exists(root "/usr/lib/opkg/status"))manager="opkg"
 else if(exists(root "/lib/apk/db/installed"))manager="apk"
 printf "{\"schema_version\":\"1.0.0\",\"snapshot_id\":%s,\"digest\":{\"algorithm\":\"sha256\",\"canonicalization\":\"evidence-sha256-v1\",\"value\":%s},\"status\":\"partial\",\"privacy_mode\":%s,",q("urn:sha256:" source_digest),q(source_digest),q(privacy)
 printf "\"system\":{\"distribution\":%s,\"version\":%s,\"target\":%s,\"profile\":%s,\"architecture\":%s,\"package_architecture\":%s,\"kernel_architecture\":%s,\"boot_mode\":%s,\"rootfs_type\":%s,\"firmware_image_type\":%s,\"package_manager\":%s,\"identity_status\":%s,\"identity_errors\":[",q(distro),version==""?"null":q(version),target==""?"null":q(target),profile==""?"null":q(profile),arch==""?"null":q(arch),package_arch==""?"null":q(package_arch),uname_m==""?"null":q(uname_m),q(boot),q(rootfs),q(image_type),q(manager),q(identity_ok?"consistent":"conflict")
 ne=split(identity_errors,ie,",");for(i=1;i<=ne;i++)if(ie[i]!=""){if(i>1)printf ",";printf "%s",q(ie[i])}printf "]},"
 printf "\"packages\":{\"installed\":["
 if(manager=="opkg")opkg()
 else if(manager=="apk")apk()
 printf "],\"top_level\":["
 for(i=1;i<=top_count;i++){if(i>1)printf ",";printf "%s",q(top[i])}
 printf "],\"intent_candidates\":["
 for(i=1;i<=intent_count;i++){if(i>1)printf ",";printf "%s",q(intent[i])}
 printf "],\"classification_status\":%s,\"truncated\":%s},",q(package_truncated?"partial":(top_count>0?"partial":"unknown")),package_truncated?"true":"false"
 # No service commands, no Docker socket and no config/environment secrets.
 printf "\"services\":{"
 printf "\"openclash\":%s,",service("openclash","^luci-app-openclash$","/usr/share/openclash/openclash","/etc/init.d/openclash")
 printf "\"lucky\":%s,",service("lucky","^(lucky|luci-app-lucky)$","/usr/bin/lucky","/etc/init.d/lucky")
 printf "\"adguardhome\":%s,",service("adguardhome","^(adguardhome|AdGuardHome)$","/usr/bin/AdGuardHome","/etc/init.d/AdGuardHome")
 printf "\"docker\":%s},",service("dockerd","^(docker|dockerd)$","/usr/bin/dockerd","/etc/init.d/dockerd")
 printf "\"storage\":%s,",storage_json
 printf "\"warnings\":[\"top-level provenance is not authoritative; retain unknown packages for manual review\",\"boot/profile and mount inspection may be incomplete\""
 if(manager=="unknown")printf ",\"package database unavailable; services cannot be classified\""
 if(package_truncated)printf ",\"package inventory truncated at 4096 records\""
 printf "],\"errors\":[]}"
}
' /dev/null
