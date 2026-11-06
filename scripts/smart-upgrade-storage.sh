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
MAX_CONTAINERS=${SMART_UPGRADE_MAX_CONTAINERS:-64}
MAX_VOLUMES=${SMART_UPGRADE_MAX_VOLUMES:-256}
DOCKER_RUNTIME=""
DOCKER_RUNTIME_STATE=unavailable
DOCKER_MOUNTS=""
DOCKER_MOUNTS_STATE=unavailable
DOCKER_CONTAINERS_STATE=unavailable
DOCKER_VOLUMES_STATE=unavailable
DOCKER_SCAN_ERRORS=""

add_scan_error() {
  if [ -n "$DOCKER_SCAN_ERRORS" ]; then
    DOCKER_SCAN_ERRORS="$DOCKER_SCAN_ERRORS
$1"
  else
    DOCKER_SCAN_ERRORS=$1
  fi
}

if [ -n "$FIXTURE_DIR" ]; then
  if [ -r "$FIXTURE_DIR/docker-info.txt" ]; then
    IFS= read -r DOCKER_RUNTIME < "$FIXTURE_DIR/docker-info.txt" || true
    DOCKER_RUNTIME_STATE=verified
  elif [ -e "$FIXTURE_DIR/docker-info.denied" ]; then
    DOCKER_RUNTIME_STATE=permission_denied
  fi
  if [ -r "$FIXTURE_DIR/docker-container-mounts.tsv" ]; then
    DOCKER_MOUNTS=$(sed -n '1,512p' "$FIXTURE_DIR/docker-container-mounts.tsv")
    DOCKER_CONTAINERS_STATE=verified
    DOCKER_MOUNTS_STATE=verified
  elif [ -r "$FIXTURE_DIR/docker-mounts.tsv" ]; then
    DOCKER_MOUNTS=$(sed -n '1,512p' "$FIXTURE_DIR/docker-mounts.tsv")
    DOCKER_CONTAINERS_STATE=verified
    DOCKER_MOUNTS_STATE=verified
  fi
  if [ -r "$FIXTURE_DIR/docker-volumes.tsv" ]; then
    while IFS="$(printf '\t')" read -r volume_name volume_path; do
      if [ -z "$volume_name" ] || [ -z "$volume_path" ]; then
        continue
      fi
      row=$(printf 'volume\t%s\t\t%s' "$volume_path" "$volume_name")
      if [ -n "$DOCKER_MOUNTS" ]; then DOCKER_MOUNTS="$DOCKER_MOUNTS
$row"; else DOCKER_MOUNTS=$row; fi
    done < "$FIXTURE_DIR/docker-volumes.tsv"
    DOCKER_VOLUMES_STATE=verified
    DOCKER_MOUNTS_STATE=verified
  fi
  for fixture_error in containers_truncated container_query_failed container_inspect_failed volumes_truncated volume_query_failed volume_inspect_failed; do
    if [ -e "$FIXTURE_DIR/docker-$fixture_error" ]; then
      add_scan_error "docker_$fixture_error"
      case "$fixture_error" in containers_*|container_*) DOCKER_CONTAINERS_STATE=partial ;; volumes_*|volume_*) DOCKER_VOLUMES_STATE=partial ;; esac
      DOCKER_MOUNTS_STATE=partial
    fi
  done
elif [ "$ROOT" = / ] && command -v docker >/dev/null 2>&1; then
  # Fixed templates request only the daemon root and mount path metadata.
  # Never request Config.Env, secrets, labels, or the complete inspect object.
  if DOCKER_RUNTIME=$(timeout 3 docker info --format '{{.DockerRootDir}}' 2>/dev/null); then
    DOCKER_RUNTIME_STATE=verified
  else
    DOCKER_RUNTIME_STATE=unknown
  fi
  if ids_all=$(timeout 3 docker ps -aq 2>/dev/null); then
    DOCKER_CONTAINERS_STATE=verified
  else
    ids_all=""; DOCKER_CONTAINERS_STATE=partial; add_scan_error docker_container_query_failed
  fi
  ids=$(printf '%s\n' "$ids_all" | sed -n "1,${MAX_CONTAINERS}p")
  container_count=$(printf '%s\n' "$ids_all" | awk 'NF{n++} END{print n+0}')
  if [ "$container_count" -gt "$MAX_CONTAINERS" ]; then
    DOCKER_CONTAINERS_STATE=partial; add_scan_error docker_containers_truncated
  fi
  rows=""
  for id in $ids; do
    case "$id" in *[!0-9a-fA-F]*|'') continue ;; esac
    if ! value=$(timeout 3 docker inspect --format '{{range .Mounts}}{{printf "%s\t%s\t%s\t%s\n" .Type .Source .Destination .Name}}{{end}}' "$id" 2>/dev/null); then
      DOCKER_CONTAINERS_STATE=partial; add_scan_error docker_container_inspect_failed; continue
    fi
    [ -z "$value" ] || rows="${rows}${rows:+
}${value}"
  done
  if volume_names_all=$(timeout 3 docker volume ls -q 2>/dev/null); then
    DOCKER_VOLUMES_STATE=verified
  else
    volume_names_all=""; DOCKER_VOLUMES_STATE=partial; add_scan_error docker_volume_query_failed
  fi
  volume_names=$(printf '%s\n' "$volume_names_all" | sed -n "1,${MAX_VOLUMES}p")
  volume_count=$(printf '%s\n' "$volume_names_all" | awk 'NF{n++} END{print n+0}')
  if [ "$volume_count" -gt "$MAX_VOLUMES" ]; then
    DOCKER_VOLUMES_STATE=partial; add_scan_error docker_volumes_truncated
  fi
  for volume_name in $volume_names; do
    case "$volume_name" in *[!A-Za-z0-9_.@-]*|'') DOCKER_VOLUMES_STATE=partial; add_scan_error docker_volume_name_invalid; continue ;; esac
    if ! volume_path=$(timeout 3 docker volume inspect --format '{{.Mountpoint}}' "$volume_name" 2>/dev/null); then
      DOCKER_VOLUMES_STATE=partial; add_scan_error docker_volume_inspect_failed; continue
    fi
    case "$volume_path" in /*) ;; *) DOCKER_VOLUMES_STATE=partial; add_scan_error docker_volume_mountpoint_invalid; continue ;; esac
    row=$(printf 'volume\t%s\t\t%s' "$volume_path" "$volume_name")
    rows="${rows}${rows:+
}${row}"
  done
  DOCKER_MOUNTS=$rows
  if [ "$DOCKER_CONTAINERS_STATE" = verified ] && [ "$DOCKER_VOLUMES_STATE" = verified ]; then
    DOCKER_MOUNTS_STATE=verified
  else
    DOCKER_MOUNTS_STATE=partial
  fi
fi

# Resolve Docker and bind/volume paths to the path actually seen by mountinfo.
# Fixture resolution is confined to ROOT; real-device resolution is read-only.
resolve_device_path() {
  input_path=$1
  [ -n "$input_path" ] || return 0
  if [ "$ROOT" = / ]; then
    readlink -f -- "$input_path" 2>/dev/null || printf '%s\n' "$input_path"
  else
    resolved_path=$(readlink -f -- "$ROOT$input_path" 2>/dev/null || true)
    case "$resolved_path" in "$ROOT"/*) printf '%s\n' "${resolved_path#"$ROOT"}" ;; *) printf '%s\n' "$input_path" ;; esac
  fi
}
if [ -n "$DOCKER_RUNTIME" ]; then DOCKER_RUNTIME=$(resolve_device_path "$DOCKER_RUNTIME"); fi
if [ -n "$DOCKER_MOUNTS" ]; then
  normalized_rows=$(printf '%s\n' "$DOCKER_MOUNTS" | sed 's/\t\t/\t-\t/g' | while IFS="$(printf '\t')" read -r mount_kind mount_source mount_destination mount_name; do
    mount_source=$(resolve_device_path "$mount_source")
    [ "$mount_destination" != - ] || mount_destination=""
    printf '%s\t%s\t%s\t%s\n' "$mount_kind" "$mount_source" "$mount_destination" "$mount_name"
  done)
  DOCKER_MOUNTS=$normalized_rows
fi

MOUNTINFO="$ROOT/proc/self/mountinfo"
[ -r "$MOUNTINFO" ] || MOUNTINFO="$ROOT/proc/1/mountinfo"
UCI="$ROOT/etc/config/dockerd"
DAEMON_JSON="$ROOT/etc/docker/daemon.json"
BLOCK_TOPOLOGY=""

# Print: resolution-state<TAB>comma-separated-physical-disks<TAB>partition.
# Virtual devices are complete only when every slave recursively resolves to a
# physical leaf.  The depth and visited-major:minor guards make malformed sysfs
# topology fail closed without following an unbounded chain.
resolve_block_topology() {
  major_minor=$1
  depth=$2
  visited=$3
  case "$major_minor" in *[!0-9:]*|*:*:*|'') printf 'unknown\t-\t-\n'; return ;; esac
  if [ "$depth" -gt 8 ]; then printf 'unknown\t-\t-\n'; return; fi
  case ",$visited," in *",$major_minor,"*) printf 'unknown\t-\t-\n'; return ;; esac

  node="$ROOT/sys/dev/block/$major_minor"
  sys_path=$(readlink -f -- "$node" 2>/dev/null || true)
  [ -n "$sys_path" ] || { printf 'unknown\t-\t-\n'; return; }
  next_visited=${visited:+$visited,}$major_minor
  slave_disks=""
  slave_count=0
  if [ -d "$node/slaves" ]; then
    for slave_path in "$node"/slaves/*; do
      [ -e "$slave_path" ] || continue
      slave_count=$((slave_count + 1))
      slave_major_minor=""
      if [ -r "$slave_path/dev" ]; then
        IFS= read -r slave_major_minor < "$slave_path/dev" || true
      fi
      child=$(resolve_block_topology "$slave_major_minor" $((depth + 1)) "$next_visited")
      child_state=${child%%	*}
      child_rest=${child#*	}
      child_disks=${child_rest%%	*}
      if [ "$child_state" != complete ] || [ "$child_disks" = - ] || [ -z "$child_disks" ]; then
        printf 'unknown\t-\t-\n'
        return
      fi
      slave_disks=${slave_disks:+$slave_disks,}$child_disks
    done
  fi
  if [ "$slave_count" -gt 0 ]; then
    disks=$(printf '%s\n' "$slave_disks" | tr ',' '\n' | awk '/^[A-Za-z0-9._-]+$/{seen[$0]=1} END{for(v in seen)print v}' | sort | awk 'BEGIN{s=""}{s=s (s?",":"") $0}END{print s}')
    [ -n "$disks" ] || { printf 'unknown\t-\t-\n'; return; }
    printf 'complete\t%s\t-\n' "$disks"
    return
  fi

  case "$sys_path" in
    */devices/virtual/block/*) printf 'unknown\t-\t-\n'; return ;;
    */block/*) block_tail=${sys_path#*/block/}; physical_disk=${block_tail%%/*} ;;
    *) printf 'unknown\t-\t-\n'; return ;;
  esac
  case "$physical_disk" in *[!A-Za-z0-9._-]*|'') printf 'unknown\t-\t-\n'; return ;; esac
  partition="-"
  if [ -r "$node/partition" ]; then
    IFS= read -r partition < "$node/partition" || true
    case "$partition" in *[!0-9]*|'') partition="-" ;; esac
  fi
  printf 'complete\t%s\t%s\n' "$physical_disk" "$partition"
}

if [ -n "$FIXTURE_DIR" ] && [ -r "$FIXTURE_DIR/block-topology.tsv" ]; then
  BLOCK_TOPOLOGY=$(sed -n "1,${MAX_MOUNTS}p" "$FIXTURE_DIR/block-topology.tsv")
elif [ -r "$MOUNTINFO" ]; then
  major_minors=$(awk '{if($3~/^[0-9]+:[0-9]+$/)seen[$3]=1} END{for(v in seen)print v}' "$MOUNTINFO" | sort)
  for major_minor in $major_minors; do
    resolved=$(resolve_block_topology "$major_minor" 0 "")
    resolution=${resolved%%	*}
    resolved_rest=${resolved#*	}
    physical_disks=${resolved_rest%%	*}
    partition=${resolved_rest#*	}
    topology_row=$(printf '%s\t%s\t%s\t%s' "$major_minor" "$physical_disks" "$partition" "$resolution")
    if [ -n "$BLOCK_TOPOLOGY" ]; then BLOCK_TOPOLOGY="$BLOCK_TOPOLOGY
$topology_row"; else BLOCK_TOPOLOGY=$topology_row; fi
  done
fi

STORAGE_EVIDENCE_DIGEST=$(
  {
    printf 'runtime_state:%s\nruntime:%s\n' "$DOCKER_RUNTIME_STATE" "$DOCKER_RUNTIME"
    printf 'containers_state:%s\nvolumes_state:%s\nmounts_state:%s\n' "$DOCKER_CONTAINERS_STATE" "$DOCKER_VOLUMES_STATE" "$DOCKER_MOUNTS_STATE"
    printf 'scan_errors:\n%s\nmount_rows:\n%s\ntopology:\n%s\n' "$DOCKER_SCAN_ERRORS" "$DOCKER_MOUNTS" "$BLOCK_TOPOLOGY"
    for evidence_spec in "mountinfo|$MOUNTINFO" "dockerd_uci|$UCI" "daemon_json|$DAEMON_JSON"; do
      evidence_label=${evidence_spec%%|*}; evidence_file=${evidence_spec#*|}
      if [ -r "$evidence_file" ]; then
        evidence_hash=$(sha256sum "$evidence_file" | awk '{print $1}')
        printf '%s:%s\n' "$evidence_label" "$evidence_hash"
      else
        printf '%s:missing\n' "$evidence_label"
      fi
    done
  } | sha256sum | awk '{print $1}'
)

awk -v privacy="$PRIVACY" -v runtime="$DOCKER_RUNTIME" \
  -v runtime_state="$DOCKER_RUNTIME_STATE" -v mount_rows="$DOCKER_MOUNTS" \
  -v docker_mounts_state="$DOCKER_MOUNTS_STATE" -v containers_state="$DOCKER_CONTAINERS_STATE" \
  -v volumes_state="$DOCKER_VOLUMES_STATE" -v scan_errors="$DOCKER_SCAN_ERRORS" \
  -v topology_rows="$BLOCK_TOPOLOGY" -v evidence_digest="$STORAGE_EVIDENCE_DIGEST" \
  -v max_mounts="$MAX_MOUNTS" -v mountinfo="$MOUNTINFO" -v uci="$UCI" \
  -v daemon_json="$DAEMON_JSON" -v root_prefix="$ROOT" '
function esc(s) { gsub(/\\/,"\\\\",s);gsub(/"/,"\\\"",s);gsub(/[\r\n\t]/," ",s);gsub(/[^[:print:]]/,"?",s);if(length(s)>1024)s=substr(s,1,1024);return s }
function q(s) { return "\"" esc(s) "\"" }
function clean_mount(s) { gsub(/\\040/," ",s);gsub(/\\011/,"\t",s);gsub(/\\134/,"\\",s);return s }
function prefix(path,base) { return base=="/" || path==base || index(path,base "/")==1 }
function physical_set_valid(s,  n,a,j) {
  n=split(s,a,",");if(n<1)return 0
  for(j=1;j<=n;j++)if(a[j]!~/^[A-Za-z0-9._-]+$/ || a[j]~/^(dm-|md[0-9]|loop[0-9]|zram[0-9]|ram[0-9]|nbd[0-9])/)return 0
  return 1
}
function classify(i) {
  if(i<1)return "unknown"
  if(fs[i]~/^(proc|sysfs|tmpfs|devtmpfs|cgroup2?|squashfs)$/)return "special_mount"
  if(mp[i]=="/" || fs[i]~/^(overlay|rootfs)$/ || dev[i]=="/dev/root")return "rootfs_or_overlay"
  if(dev[i]~/^\/dev\// && mp[i]!="/")return "external_persistent"
  return "unknown"
}
function persistence(i) {
  if(i<1)return "unknown"
  if(fs[i]~/^(proc|sysfs|tmpfs|devtmpfs|cgroup2?|squashfs)$/)return "special_mount"
  if(mp[i]=="/" || mp[i]=="/overlay" || fs[i]~/^(overlay|rootfs)$/ || dev[i]=="/dev/root")return "rootfs_bound"
  if(dev[i]~/^\/dev\// && mp[i]!="/")return "separate_mount"
  return "unknown"
}
function overwrite_risk(i,  d,disk) {
  if(i<1)return "unknown"
  if(topology_state[i]!="complete" || firmware_disk_count==0 || !firmware_topology_complete)return "unknown"
  for(d=1;d<=disk_count;d++){disk=disk_name_by_number[d];if(mount_disk[i,disk] && firmware_disk[disk])return "same_physical_disk"}
  return "different_physical_disk"
}
function block_metadata(i,  fn,line,sectors,n,disks,d,disk) {
  block_state[i]="unknown";size_bytes[i]="";physical_disk[i]="";partition_no[i]="";topology_state[i]="unknown";physical_disk_count[i]=0
  if(majmin[i]!~/^[0-9]+:[0-9]+$/)return
  if(topology_state_by_mm[majmin[i]]=="complete" && parents_by_mm[majmin[i]]!=""){
    topology_state[i]="complete";block_state[i]="resolved";partition_no[i]=partition_by_mm[majmin[i]]
    n=split(parents_by_mm[majmin[i]],disks,",")
    for(d=1;d<=n;d++)if(disks[d]~/^[A-Za-z0-9._-]+$/ && !mount_disk[i,disks[d]]){
      disk=disks[d];mount_disk[i,disk]=1;physical_disk_count[i]++
      if(disk_id[disk]==""){disk_count++;disk_id[disk]="disk-" disk_count;disk_name_by_number[disk_count]=disk}
      if(physical_disk[i]=="")physical_disk[i]=disk
    }
    if(physical_disk_count[i]!=1)physical_disk[i]=""
  } else if(dev[i]~/^\/dev\//) {
    topology_unknown=1
  }
  fn=root_prefix "/sys/dev/block/" majmin[i] "/size"
  if((getline line < fn)>0 && line~/^[0-9]+$/){sectors=line+0;size_bytes[i]=sectors*512}
  close(fn)
}
function disk_ids_json(i,  d,disk,s,comma) {
  s="[";comma=0
  for(d=1;d<=disk_count;d++){disk=disk_name_by_number[d];if(mount_disk[i,disk]){s=s (comma?",":"") q(disk_id[disk]);comma=1}}
  return s "]"
}
function disk_names_json(i,  d,disk,s,comma) {
  if(privacy!="local")return "null"
  s="[";comma=0
  for(d=1;d<=disk_count;d++){disk=disk_name_by_number[d];if(mount_disk[i,disk]){s=s (comma?",":"") q(disk);comma=1}}
  return s "]"
}
function best_mount(path,  i,best) {
  best=0
  for(i=1;i<=mc;i++)if(prefix(path,mp[i])&&length(mp[i])>length(mp[best]))best=i
  return best
}
function add_target(kind,source,dest,name,verified,  i,risk,key) {
  if(source=="")return
  key=kind SUBSEP source SUBSEP dest SUBSEP name
  if(target_seen[key])return
  target_seen[key]=1;i=best_mount(source);risk=classify(i);tc++
  tk[tc]=kind;ts[tc]=source;td[tc]=dest;tn[tc]=name;tm[tc]=i;tr[tc]=risk;tv[tc]=verified
  tp[tc]=persistence(i);to[tc]=overwrite_risk(i)
  if(i==0 || risk=="unknown" || tp[tc]=="unknown" || to[tc]=="unknown")unknown=1
}
BEGIN {
  topology_count=split(topology_rows,topology_lines,"\n")
  for(ti=1;ti<=topology_count;ti++)if(topology_lines[ti]!=""){
    nt=split(topology_lines[ti],tf,"\t")
    state=nt>=4?tf[4]:"complete"
    if(nt>=2 && tf[1]~/^[0-9]+:[0-9]+$/ && physical_set_valid(tf[2]) && state=="complete"){
      parents_by_mm[tf[1]]=tf[2];partition_by_mm[tf[1]]=(nt>=3&&tf[3]!="-")?tf[3]:"";topology_state_by_mm[tf[1]]="complete"
    } else if(nt>=1 && tf[1]~/^[0-9]+:[0-9]+$/)topology_state_by_mm[tf[1]]="unknown"
  }
  mc=0;truncated=0;mount_ok=0
  while((getline line < mountinfo)>0) {
    mount_ok=1
    if(mc>=max_mounts){truncated=1;continue}
    n=split(line,a," ");dash=0
    for(i=7;i<=n;i++)if(a[i]=="-"){dash=i;break}
    if(!dash || dash+2>n){parse_error=1;continue}
    mc++;majmin[mc]=a[3];mp[mc]=clean_mount(a[5]);fs[mc]=a[dash+1];dev[mc]=clean_mount(a[dash+2]);rootpath[mc]=clean_mount(a[4]);block_metadata(mc)
  }
  close(mountinfo)
  firmware_topology_complete=1
  for(i=1;i<=mc;i++)if(mp[i]=="/"||mp[i]=="/overlay"||mp[i]=="/rom"||mp[i]=="/boot"||mp[i]=="/boot/efi"){
    if(dev[i]~/^\/dev\// && topology_state[i]!="complete")firmware_topology_complete=0
    for(d=1;d<=disk_count;d++){disk=disk_name_by_number[d];if(mount_disk[i,disk]){if(!firmware_disk[disk])firmware_disk_count++;firmware_disk[disk]=1}}
  }
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
  docker_present=!(runtime_state=="unavailable"&&configured=="")
  if(!mount_ok||truncated||parse_error)unknown=1
  if(docker_present && (containers_state!="verified" || volumes_state!="verified" || docker_mounts_state!="verified"))unknown=1
  printf "{\"status\":%s,\"evidence_digest\":%s,",q(unknown?"partial":"ok"),q(evidence_digest)
  printf "\"scan_completeness\":{\"containers\":%s,\"volumes\":%s,\"mounts\":%s,\"container_scope\":%s,\"volume_scope\":%s},",q(containers_state),q(volumes_state),q(docker_mounts_state),q(containers_state=="verified"?"all":"unknown"),q(volumes_state=="verified"?"all":"unknown")
  printf "\"docker\":{\"installed\":%s,\"daemon_state\":%s,",docker_present?"true":"false",q(runtime_state)
  printf "\"root\":%s,\"configured_root\":%s,\"root_source\":%s,\"verified\":%s,\"config_mismatch\":%s},",privacy=="local"&&effective!=""?q(effective):"null",privacy=="local"&&configured!=""?q(configured):"null",q(source),verified?"true":"false",verified&&configured!=""&&configured!=effective?"true":"false"
  printf "\"mount_inventory\":{\"state\":%s,\"truncated\":%s,\"entries\":[",q(!mount_ok?"missing":(truncated||parse_error?"partial":"complete")),truncated?"true":"false"
  for(i=1;i<=mc;i++){if(i>1)printf ",";printf "{\"id\":%s,\"mountpoint\":%s,\"device\":%s,\"device_major_minor\":%s,\"filesystem\":%s,\"root\":%s,\"block_resolution\":%s,\"size_bytes\":%s,\"risk\":%s,\"physical_disk_id\":%s,\"physical_disk_ids\":%s,\"physical_disk\":%s,\"physical_disks\":%s,\"partition\":%s}",q("mount-" i),privacy=="local"?q(mp[i]):"null",privacy=="local"?q(dev[i]):"null",privacy=="local"?q(majmin[i]):"null",q(fs[i]),privacy=="local"?q(rootpath[i]):"null",q(block_state[i]),size_bytes[i]==""?"null":sprintf("%.0f",size_bytes[i]),q(classify(i)),physical_disk[i]!=""?q(disk_id[physical_disk[i]]):"null",disk_ids_json(i),privacy=="local"&&physical_disk[i]!=""?q(physical_disk[i]):"null",disk_names_json(i),privacy=="local"&&partition_no[i]!=""?q(partition_no[i]):"null"}
  printf "]},\"targets\":["
  for(i=1;i<=tc;i++){if(i>1)printf ",";printf "{\"kind\":%s,\"source\":%s,\"destination\":%s,\"name\":%s,\"mount_id\":%s,\"risk\":%s,\"persistence\":%s,\"firmware_overwrite_risk\":%s,\"verified\":%s}",q(tk[i]),privacy=="local"?q(ts[i]):"null",privacy=="local"&&td[i]!=""?q(td[i]):"null",privacy=="local"&&tn[i]!=""?q(tn[i]):"null",tm[i]?q("mount-" tm[i]):"null",q(tr[i]),q(tp[i]),q(to[i]),tv[i]?"true":"false"}
  printf "],\"errors\":["
  comma=0
  if(!mount_ok){printf "%s",q("mountinfo_missing");comma=1}
  if(truncated){if(comma)printf ",";printf "%s",q("mountinfo_truncated");comma=1}
  if(parse_error){if(comma)printf ",";printf "%s",q("mountinfo_parse_error");comma=1}
  if(topology_unknown){if(comma)printf ",";printf "%s",q("block_topology_unknown");comma=1}
  if(runtime_state=="permission_denied"){if(comma)printf ",";printf "%s",q("docker_daemon_permission_denied");comma=1}
  error_count=split(scan_errors,error_lines,"\n")
  for(ei=1;ei<=error_count;ei++)if(error_lines[ei]!=""){if(comma)printf ",";printf "%s",q(error_lines[ei]);comma=1}
  printf "]}"
}'
