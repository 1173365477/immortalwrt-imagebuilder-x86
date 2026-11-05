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
function emit_package(  name,src,dep) {
 if(pkg=="") return
 if(pkg !~ /^[A-Za-z0-9][A-Za-z0-9+_.@-]*$/) {pkg="";return}
 name=pkg; names[count+1]=name; src="unknown"
 if(auto ~ /^(yes|true|1)$/) src="dependency"
 else if(auto ~ /^(no|false|0)$/) src="manual"
 if(first==0) printf ","
 first=0
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
BEGIN {
 get_release()
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
 printf "],\"top_level\":[],\"classification_status\":\"unknown\"},"
 # No service commands, no Docker socket and no config/environment secrets.
 printf "\"services\":{"
 printf "\"openclash\":%s,",service("openclash","^luci-app-openclash$")
 printf "\"lucky\":%s,",service("lucky","^(lucky|luci-app-lucky)$")
 printf "\"adguardhome\":%s,",service("adguardhome","^adguardhome$")
 printf "\"docker\":%s},",service("docker","^(docker|dockerd)$")
 printf "\"storage\":{\"docker_root\":null,\"mounts\":[],\"warnings\":[\"Docker Root Dir and persistent mounts not verified; do not assume rootfs persistence\"]},"
 printf "\"warnings\":[\"top-level provenance is not authoritative; retain unknown packages for manual review\",\"boot/profile and mount inspection may be incomplete\"],\"errors\":[]}"
}
' /dev/null
