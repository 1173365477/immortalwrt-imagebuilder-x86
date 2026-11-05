#!/bin/sh
# Smart Upgrade device probe. Read-only, BusyBox ash/awk compatible.
# Usage: sh scripts/smart-upgrade-agent.sh [--root DIR] [--privacy local|redacted]
set -eu
ROOT=/
PRIVACY=redacted
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) [ "$#" -ge 2 ] || exit 2; ROOT=$2; shift 2 ;;
    --privacy) [ "$#" -ge 2 ] || exit 2; PRIVACY=$2; shift 2 ;;
    *) echo "unknown option" >&2; exit 2 ;;
  esac
done
case "$PRIVACY" in local|redacted) ;; *) exit 2 ;; esac
[ -d "$ROOT" ] || { echo "root does not exist" >&2; exit 2; }
# Only reads explicitly enumerated OS and package database paths; never shells out to
# data from those files, contacts the Docker socket, or sources device config.
awk -v root="$ROOT" -v privacy="$PRIVACY" '
function esc(s,   x) {
  gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s)
  gsub(/\r/, "", s); gsub(/\t/, " ", s); gsub(/\n/, " ", s)
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
 }
 close(fn)
 fn=root "/etc/board.json"
 # Board.json may contain sensitive device details; do not read the file.
 if (distro=="") distro="unknown"
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
function emit_package(  name,src,dep) {
 if(pkg=="") return
 if(pkg !~ /^[A-Za-z0-9][A-Za-z0-9+_.@-]*$/) {pkg="";return}
 name=pkg; names[count+1]=name; src="unknown"
 if(rom[name]) src="default"
 else if(auto ~ /^(yes|true|1)$/) src="dependency"
 else if(auto ~ /^(no|false|0)$/) src="manual"
 if(world[name] || (manager=="opkg" && auto ~ /^(no|false|0)$/)) top[++top_count]=name
 if(count>0) printf ","
 printf "{\"name\":%s,\"version\":%s,\"source\":%s,\"depends\":[",q(name),ver==""?"null":q(ver),q(src)
 n=split(deps,ds,",")
 for(i=1;i<=n;i++){dep=ds[i];gsub(/^[ \t]+|[ \t]+$/,"",dep);sub(/ .*/,"",dep);if(dep~/^[A-Za-z0-9][A-Za-z0-9+_.@-]*$/){if(j++>0)printf ",";printf "%s",q(dep)}}
 printf "]}"
 pkg=ver=auto=deps="";j=0;count++
}
function opkg(  line,kv) {
 fn=root "/usr/lib/opkg/status"
 while ((getline line < fn)>0) {
   if(line==""){emit_package();continue}
   if(line~/^Package: /) pkg=substr(line,10)
   else if(line~/^Version: /) ver=substr(line,10)
   else if(line~/^Depends: /) deps=substr(line,10)
   else if(line~/^Auto-Installed: /) auto=substr(line,17)
 }
 emit_package();close(fn)
}
function apk(  line) {
 fn=root "/lib/apk/db/installed"
 while ((getline line < fn)>0) {
   if(line==""){emit_package();continue}
   if(line~/^P:/)pkg=substr(line,3)
   else if(line~/^V:/)ver=substr(line,3)
   else if(line~/^D:/) {deps=substr(line,3);gsub(/ +/,",",deps)}
 }
 emit_package();close(fn)
}
function exists(path,  line,x){x=(getline line < path);close(path);return x>=0}
function service(name,pattern,   result) {
 result="not_detected"
 for(z=1;z<=count;z++) if(names[z]~pattern)result="detected"
 return q(result)
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
 load_storage()
 read_provenance()
 manager="unknown"
 if(exists(root "/usr/lib/opkg/status"))manager="opkg"
 else if(exists(root "/lib/apk/db/installed"))manager="apk"
 boot="unknown"
 if(exists(root "/sys/firmware/efi/systab"))boot="efi"
 printf "{\"schema_version\":\"1.0.0\",\"status\":\"partial\",\"privacy_mode\":%s,",q(privacy)
 printf "\"system\":{\"distribution\":%s,\"version\":%s,\"target\":%s,\"profile\":null,\"architecture\":%s,\"boot_mode\":%s,\"package_manager\":%s},",q(distro),version==""?"null":q(version),target==""?"null":q(target),arch==""?"null":q(arch),q(boot),q(manager)
 printf "\"packages\":{\"installed\":["
 if(manager=="opkg")opkg()
 else if(manager=="apk")apk()
 printf "],\"top_level\":["
 for(i=1;i<=top_count;i++){if(i>1)printf ",";printf "%s",q(top[i])}
 printf "],\"classification_status\":%s},",q(top_count>0?"partial":"unknown")
 # No service commands, no Docker socket and no config/environment secrets.
 printf "\"services\":{"
 printf "\"openclash\":%s,",service("openclash","^luci-app-openclash$")
 printf "\"lucky\":%s,",service("lucky","^(lucky|luci-app-lucky)$")
 printf "\"adguardhome\":%s,",service("adguardhome","^adguardhome$")
 printf "\"docker\":%s},",service("docker","^(docker|dockerd)$")
 render_storage()
 printf "\"warnings\":[\"top-level provenance is not authoritative; retain unknown packages for manual review\",\"boot/profile and mount inspection may be incomplete\"],\"errors\":[]}"
}
' /dev/null
