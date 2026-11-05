#!/bin/sh
# Read-only Docker/storage analyzer used by smart-upgrade-agent.sh.
# Inputs are paths or fixed-format command results; no input is evaluated.
set -eu
LC_ALL=C
export LC_ALL

ROOT=${ROOT:-/}
PRIVACY=${PRIVACY:-redacted}
FIXTURE_DIR=${FIXTURE_DIR:-}
MAX_MOUNTS=${SMART_UPGRADE_MAX_MOUNTS:-256}
DOCKER_RUNTIME=""
DOCKER_RUNTIME_STATE=unavailable
DOCKER_MOUNTS=""
DOCKER_MOUNTS_STATE=unavailable

if [ -n "$FIXTURE_DIR" ]; then
  if [ -r "$FIXTURE_DIR/docker-info.txt" ]; then
    IFS= read -r DOCKER_RUNTIME < "$FIXTURE_DIR/docker-info.txt" || true
    DOCKER_RUNTIME_STATE=verified
  elif [ -e "$FIXTURE_DIR/docker-info.denied" ]; then
    DOCKER_RUNTIME_STATE=permission_denied
  fi
  if [ -r "$FIXTURE_DIR/docker-mounts.tsv" ]; then
    DOCKER_MOUNTS=$(sed -n "1,128p" "$FIXTURE_DIR/docker-mounts.tsv")
    DOCKER_MOUNTS_STATE=verified
  fi
elif [ "$ROOT" = / ] && command -v docker >/dev/null 2>&1; then
  # Fixed templates request only the daemon root and mount path metadata.
  # Never request Config.Env, secrets, labels, or the complete inspect object.
  if DOCKER_RUNTIME=$(timeout 3 docker info --format '{{.DockerRootDir}}' 2>/dev/null); then
    DOCKER_RUNTIME_STATE=verified
  else
    DOCKER_RUNTIME_STATE=unknown
  fi
  ids=$(timeout 3 docker ps -q 2>/dev/null | sed -n '1,64p' || true)
  rows=""
  for id in $ids; do
    case "$id" in *[!0-9a-fA-F]*|'') continue ;; esac
    value=$(timeout 3 docker inspect --format '{{range .Mounts}}{{printf "%s\t%s\t%s\t%s\n" .Type .Source .Destination .Name}}{{end}}' "$id" 2>/dev/null || true)
    [ -z "$value" ] || rows="${rows}${rows:+
}${value}"
  done
  DOCKER_MOUNTS=$rows
  DOCKER_MOUNTS_STATE=verified
fi

# Resolve fixture-root symlinks without following links outside the supplied
# filesystem tree. Real-device Docker paths are already absolute device paths.
if [ "$ROOT" != / ] && [ -n "$DOCKER_RUNTIME" ]; then
  resolved=$(readlink -f "$ROOT$DOCKER_RUNTIME" 2>/dev/null || true)
  case "$resolved" in "$ROOT"/*) DOCKER_RUNTIME=${resolved#"$ROOT"} ;; esac
fi

MOUNTINFO="$ROOT/proc/self/mountinfo"
[ -r "$MOUNTINFO" ] || MOUNTINFO="$ROOT/proc/1/mountinfo"
UCI="$ROOT/etc/config/dockerd"
DAEMON_JSON="$ROOT/etc/docker/daemon.json"

awk -v privacy="$PRIVACY" -v runtime="$DOCKER_RUNTIME" \
  -v runtime_state="$DOCKER_RUNTIME_STATE" -v mount_rows="$DOCKER_MOUNTS" \
  -v docker_mounts_state="$DOCKER_MOUNTS_STATE" -v max_mounts="$MAX_MOUNTS" \
  -v mountinfo="$MOUNTINFO" -v uci="$UCI" -v daemon_json="$DAEMON_JSON" -v root_prefix="$ROOT" '
function esc(s) { gsub(/\\/,"\\\\",s);gsub(/"/,"\\\"",s);gsub(/[\r\n\t]/," ",s);gsub(/[^[:print:]]/,"?",s);if(length(s)>1024)s=substr(s,1,1024);return s }
function q(s) { return "\"" esc(s) "\"" }
function clean_mount(s) { gsub(/\\040/," ",s);gsub(/\\011/,"\t",s);gsub(/\\134/,"\\",s);return s }
function anon_path(path,  i,best) {
  best=0
  for(i=1;i<=mc;i++) if(prefix(path,mp[i]) && length(mp[i])>length(mp[best]))best=i
  return best ? "mount-" best : "unresolved"
}
function prefix(path,base) { return base=="/" || path==base || index(path,base "/")==1 }
function classify(i) {
  if(i<1)return "unknown"
  if(fs[i]~/^(proc|sysfs|tmpfs|devtmpfs|cgroup2?|squashfs)$/)return "special_mount"
  if(mp[i]=="/" || fs[i]~/^(overlay|rootfs)$/ || dev[i]=="/dev/root")return "rootfs_or_overlay"
  if(dev[i]~/^\/dev\// && mp[i]!="/")return "external_persistent"
  return "unknown"
}
function block_metadata(i,  fn,line,sectors) {
  block_state[i]="unknown";size_bytes[i]=""
  if(majmin[i]!~/^[0-9]+:[0-9]+$/)return
  fn=root_prefix "/sys/dev/block/" majmin[i] "/size"
  if((getline line < fn)>0 && line~/^[0-9]+$/){sectors=line+0;size_bytes[i]=sectors*512;block_state[i]="resolved"}
  close(fn)
}
function best_mount(path,  i,best) {
  best=0
  for(i=1;i<=mc;i++)if(prefix(path,mp[i])&&length(mp[i])>length(mp[best]))best=i
  return best
}
function add_target(kind,source,dest,name,verified,  i,risk) {
  if(source=="")return
  i=best_mount(source);risk=classify(i);tc++
  tk[tc]=kind;ts[tc]=source;td[tc]=dest;tn[tc]=name;tm[tc]=i;tr[tc]=risk;tv[tc]=verified
  if(i==0 || risk=="unknown")unknown=1
}
BEGIN {
  mc=0; truncated=0; mount_ok=0
  while((getline line < mountinfo)>0) {
    mount_ok=1
    if(mc>=max_mounts){truncated=1;continue}
    n=split(line,a," ");dash=0
    for(i=7;i<=n;i++)if(a[i]=="-"){dash=i;break}
    if(!dash || dash+2>n){parse_error=1;continue}
    mc++;majmin[mc]=a[3];mp[mc]=clean_mount(a[5]);fs[mc]=a[dash+1];dev[mc]=clean_mount(a[dash+2]);rootpath[mc]=clean_mount(a[4]);block_metadata(mc)
  }
  close(mountinfo)
  configured="";config_source="none"
  while((getline line < uci)>0)if(line~/^[[:space:]]*option[[:space:]]+data_root[[:space:]]+/){
    v=line;sub(/^[[:space:]]*option[[:space:]]+data_root[[:space:]]+/,"",v);gsub(/^[[:space:]"\047]+|[[:space:]"\047]+$/,"",v)
    if(v~/^\//&&length(v)<=512){configured=v;config_source="uci"}
  }
  close(uci)
  while((getline line < daemon_json)>0)if(line~/"data-root"[[:space:]]*:/){
    v=line;sub(/^.*"data-root"[[:space:]]*:[[:space:]]*"/,"",v);sub(/".*$/, "",v)
    if(v~/^\//&&length(v)<=512){configured=v;config_source="daemon_json"}
  }
  close(daemon_json)
  effective=(runtime_state=="verified"&&runtime~/^\//)?runtime:configured
  source=(runtime_state=="verified"?"docker_daemon":config_source)
  verified=(runtime_state=="verified")
  if(effective!="")add_target("docker_root",effective,"","",verified)
  rn=split(mount_rows,rows,"\n")
  for(r=1;r<=rn;r++)if(rows[r]!=""){
    nf=split(rows[r],f,"\t")
    if(nf>=3 && (f[1]=="bind"||f[1]=="volume"))add_target(f[1],f[2],f[3],nf>=4?f[4]:"",docker_mounts_state=="verified")
  }
  if(!mount_ok||truncated||parse_error)unknown=1
  printf "{\"status\":%s,",q(unknown?"partial":"ok")
  printf "\"docker\":{\"installed\":%s,\"daemon_state\":%s,",runtime_state=="unavailable"&&configured==""?"false":"true",q(runtime_state)
  printf "\"root\":%s,\"configured_root\":%s,\"root_source\":%s,\"verified\":%s,\"config_mismatch\":%s},",privacy=="local"&&effective!=""?q(effective):"null",privacy=="local"&&configured!=""?q(configured):"null",q(source),verified?"true":"false",verified&&configured!=""&&configured!=effective?"true":"false"
  printf "\"mount_inventory\":{\"state\":%s,\"truncated\":%s,\"entries\":[",q(!mount_ok?"missing":(truncated||parse_error?"partial":"complete")),truncated?"true":"false"
  for(i=1;i<=mc;i++){if(i>1)printf ",";printf "{\"id\":%s,\"mountpoint\":%s,\"device\":%s,\"device_major_minor\":%s,\"filesystem\":%s,\"root\":%s,\"block_resolution\":%s,\"size_bytes\":%s,\"risk\":%s}",q("mount-" i),privacy=="local"?q(mp[i]):"null",privacy=="local"?q(dev[i]):"null",privacy=="local"?q(majmin[i]):"null",q(fs[i]),privacy=="local"?q(rootpath[i]):"null",q(block_state[i]),size_bytes[i]==""?"null":sprintf("%.0f",size_bytes[i]),q(classify(i))}
  printf "]},\"targets\":["
  for(i=1;i<=tc;i++){if(i>1)printf ",";printf "{\"kind\":%s,\"source\":%s,\"destination\":%s,\"name\":%s,\"mount_id\":%s,\"risk\":%s,\"verified\":%s}",q(tk[i]),privacy=="local"?q(ts[i]):"null",privacy=="local"&&td[i]!=""?q(td[i]):"null",privacy=="local"&&tn[i]!=""?q(tn[i]):"null",tm[i]?q("mount-" tm[i]):"null",q(tr[i]),tv[i]?"true":"false"}
  printf "],\"errors\":["
  comma=0
  if(!mount_ok){printf "%s",q("mountinfo_missing");comma=1}
  if(truncated){if(comma)printf ",";printf "%s",q("mountinfo_truncated");comma=1}
  if(parse_error){if(comma)printf ",";printf "%s",q("mountinfo_parse_error");comma=1}
  if(runtime_state=="permission_denied"){if(comma)printf ",";printf "%s",q("docker_daemon_permission_denied")}
  printf "]}"
}'
