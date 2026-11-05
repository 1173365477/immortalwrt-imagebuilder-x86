# ImmortalWrt x86_64 migration ImageBuilder

这个仓库不是固定 `packages.txt` 的固件配方。它以当前路由器的 `owut check --verbose` 输出为主证据，解析旧系统的顶层/用户安装包、缺失包、降级、替代和构建错误，再为用户指定的 ImmortalWrt release 动态生成 x86/64 `generic` ImageBuilder manifest。

默认值仍是已实际验证的 25.12.2，但实现不把 `25.12` 当作允许列表。每次构建都读取指定 release 的官方 `profiles.json` 和 `sha256sums`，只有同时具备以下能力才继续：

- Target `x86/64`、Profile `generic`；
- `ext4` + `combined-efi` 的 `.img.gz` 镜像；
- 可唯一识别且受支持格式的 x86_64 ImageBuilder；
- 可识别的官方 feed 和 package index；
- APK 包管理器。当前项目只实现 APK 的第三方首次启动安装；发现 opkg 或未知包管理器会明确失败。

`25.12.2` 是回归基线，不是未来版本兼容承诺。未来 26/27/29 等版本只有在真实上游发布并通过上述能力检查、报告目标版本完全一致、所有所选第三方 provider 兼容性明确时才会构建。

> **磁盘安全警告**：`combined-efi.img.gz` 是完整磁盘镜像，主要用于全新安装、救援或完整写盘。本仓库不会刷写磁盘，也不声称它能安全保留你手工扩展后的 GPT、p3、p4 或未分配空间。不要在未单独验证 x86 sysupgrade 对现有 GPT 的处理前，直接 `dd` 到当前 NVMe。

## 工作流

```text
当前 ImmortalWrt
  └─ owut/opkg 报告
       └─ Analyze：健壮解析为 system-analysis.json
            └─ Resolve：规则引擎选择功能包、替代和第三方 provider
                 └─ Validate：报告版本一致性 + 官方 release 能力/索引检查
                      └─ Fetch：逐 provider 判断 compatible/unresolved/incompatible
                           └─ Build：校验 ImageBuilder → make image → evidence/artifact
```

`Analyze migration report` 只分析并上传 `migration-analysis` artifact。`Build ImmortalWrt x86_64 firmware` 会重新执行 Analyze → Resolve → Validate → Build，避免使用过期分析结果。

## 第一次使用

### 1. 在当前路由器生成报告

首选、也是最重要的输入：

```sh
owut check --verbose --version-to 25.12 > current-system.txt 2>&1
```

额外导出当前安装列表：

```sh
opkg list-installed > installed-packages.txt
```

优先再导出 owut 认定的用户顶层包（官方 owut 源码支持此格式）：

```sh
owut list --format fs-user > top-level-packages.txt
```

如果希望尝试保留 `user-installed` 信息，也可以另存：

```sh
cat /usr/lib/opkg/status > installed-packages.txt
```

不同 opkg/ImmortalWrt 版本的 status 字段并不完全一致。本项目只把 `Package`、`Version`、`Status` 以及可识别的 user-installed 标记当作补充；`owut` 输出仍是主要迁移判断依据。

将完整文件放到：

```text
reports/current-system.txt
reports/installed-packages.txt   # 可选
reports/top-level-packages.txt   # 推荐，owut 用户顶层包
```

不要只复制错误附近的几行。解析器不依赖固定行号，能识别元数据、列表、版本变化、`missing to-version`、`downgrade`、replacement、warning 和 ERROR。

### 2. 先运行 Analyze

在 GitHub 的 Actions 页面运行 **Analyze migration report**。默认：

- `immortalwrt_version`: `25.12.2`（必须与报告的 `Version-to` 完全一致）
- `report_path`: `reports/current-system.txt`
- `installed_packages_path`: `reports/installed-packages.txt`
- `top_level_packages_path`: `reports/top-level-packages.txt`
- `strict_mode`: `true`

下载 `migration-analysis`，重点查看：

- `migration-report.md`
- `packages-missing.txt`
- `packages-skipped.txt`
- `packages-replaced.txt`
- `packages-thirdparty.txt`

任何无法映射的包都会写入 `packages-missing.txt`，不会静默丢弃。

### 3. 运行 Build

确认分析后运行 **Build ImmortalWrt x86_64 firmware**：

| 输入 | 默认值 | 说明 |
|---|---:|---|
| `immortalwrt_version` | `25.12.2` | 精确 release；严格语法校验并读取官方能力元数据 |
| `report_path` | `reports/current-system.txt` | 完整 owut 报告 |
| `include_openclash` | `true` | 报告触发 OpenClash 时启用 provider |
| `openclash_version` | `0.48.002` | GitHub Release tag 版本 |
| `include_nikki` | `true` | 报告触发 Nikki 时启用 provider |
| `include_lucky` | `true` | 报告触发 Lucky 时启用 provider |
| `rootfs_size` | `8192` | ext4 根分区大小，MiB |
| `create_release` | `false` | 是否创建 GitHub Release |
| `strict_mode` | `true` | 有 unresolved 就停止 |

开关不会无条件把插件塞进固件：对应包必须先在迁移报告中被检测到。关闭已被报告触发的 provider 会把该包列为 unresolved。

`strict_mode=false` 会允许跳过 unresolved/incompatible 的第三方 provider 并继续构建，同时产生醒目的 `DEGRADED MIGRATION` 标记；缺失包和兼容性报告仍在 artifact 中。它不是“自动认为缺失包不重要”。`strict_mode=true` 对 unresolved package 或已请求但无法确认兼容的 provider 都会失败。

### Release 能力发现与失败方式

版本只接受 `major.minor`、`major.minor.patch` 和 `major.minor.patch-rcN/betaN/alphaN`，例如 `25.12.2`、`29.0.1`、`29.0.0-rc1`；`latest`、路径、空格和 shell 字符会在联网前被拒绝。验证阶段会：

1. 要求报告 `Version-to` 与 workflow 输入完全一致；
2. 从官方 `profiles.json` 确认 target/profile/rootfs/image type 和包管理器；
3. 从官方 target `sha256sums` 动态发现 ImageBuilder 文件名、压缩格式和 SHA-256；
4. 从 release package `sha256sums` 动态发现 feed 名称，再检查目标包；
5. 把结论写入 `generated/release-capabilities.json`。

如果缺少所需镜像，错误会列出该 profile 实际可用的镜像；如果 ImageBuilder 不存在或匹配不唯一，会列出明确原因，而不是猜 URL。

## 包选择策略

基础清单故意很小，只含 LuCI、证书/下载工具、dnsmasq-full、firewall4 和透明代理基础 kmod。其余选择优先级：

1. owut 报告中的顶层包；
2. 可识别的 user-installed 包；
3. 报告触发的 Docker、AdGuardHome、存储、USB storage 功能组；
4. `package-rules.yml` 的 `always_keep`；
5. 显式 kernel/hardware allowlist 中、并且报告实际出现的驱动。

不会盲目复制所有 `lib*`、所有 `kmod-*`、旧版兼容包或自动依赖。ImageBuilder 会重新解依赖。

### 状态处理

- **官方目标版本存在**：加入 `packages-official.txt`。
- **missing**：先查第三方映射；没有匹配就加入 `packages-missing.txt`。
- **downgrade**：默认不接受。已知 provider（如 OpenClash）走 provider；未知降级作为 unresolved，要求人工确认。
- **replacement**：优先采用 owut 报告元数据；仅在报告没有信息时才使用 `version_rules.<target_series>.replacements` 回退规则。例如 25.12 的 `opkg -> apk-openssl` 不会自动套用到未来版本。
- **旧 kmod**：只有功能/硬件 allowlist 匹配的包才保留；依赖模块交给目标 release 的 ImageBuilder 重新解析，kmod 索引路径由 `profiles.json` 的 kernel version/release/vermagic 动态生成。

### Docker

检测到 `docker`、`dockerd`、`docker-compose` 或 `luci-app-dockerman` 时，规则组加入 Docker 栈及 `kmod-veth`、`kmod-br-netfilter`。2026-10-28 的 25.12.2 官方索引实际为 Docker `29.6.1-r1`、containerd `2.2.5-r1`；从 Docker 27/containerd 1.7 跨越了大版本。`/opt/docker` 和任何 volume 都不会进入固件，恢复容器数据必须单独验证。

### AdGuardHome

检测到 `adguardhome` 时使用目标官方包。`AdGuardHome.yaml`、密码和私有过滤设置不会进入仓库或固件。

### 存储、USB 与 NIC

存储包只保留报告中确实存在的工具/文件系统；USB storage 功能被检测到时加入核心 storage 模块组。NIC kmod 只允许 `package-rules.yml` 中的常见 x86 驱动正则；如果实际网卡驱动不在列表，先确认目标 release 的包名，再添加精确规则。

## 第三方 APK 策略

构建时，每个 provider 先检查目标 series、架构、包管理器、官方依赖、Release 声明和 asset 唯一匹配。只有状态为 `compatible` 的 APK 才会进入 `files/root/thirdparty/`；每个 GitHub asset 都按 Release API 的 SHA-256 `digest` 校验。结果写入 `thirdparty-status.json` 和 `compatibility-report.md`。ImageBuilder 将通过检查的 APK 带入 `/root/thirdparty/`。首次启动时 `files/etc/uci-defaults/99-install-thirdparty` 执行：

```sh
apk add --allow-untrusted /root/thirdparty/*.apk
```

全部成功才删除 APK 目录；失败返回非 0，并保留 APK 和 uci-defaults 脚本供排查。OpenClash 的官方依赖（包括 `ruby`、`ruby-yaml`）在 ImageBuilder 阶段预装；Nikki 所需 `mihomo-meta` 随官方归档离线带入，首次启动不应依赖网络拉取这些包。

### 已核实 provider（2026-10-28）

#### OpenClash

- 官方仓库：<https://github.com/vernesong/OpenClash>
- Release：`v0.48.002`
- 资产：`luci-app-openclash-0.48.002.apk`
- GitHub digest：`f7ebbd43f9be15c5e6df26e5d0c03d50d0bb8f7fa4cc0d2c2bf048b08c0b155b`
- 不使用 ImmortalWrt feed 中较旧的 0.47.156

#### Nikki

- 官方仓库：<https://github.com/nikkinikki-org/OpenWrt-nikki>
- 核验时 latest：`v1.26.2`
- 资产：`nikki_x86_64-openwrt-25.12.tar.gz`
- GitHub digest：`510c4dd3204842ccf41f567198bf95c03bd407173dcdcee0a259af6d5b43fa05`
- 实际归档中选择：`mihomo-meta-1.19.32.apk`、`nikki-2026.10.10-r1.apk`、`luci-app-nikki-1.26.2-r1.apk`、中文语言包

文件名不是写死版本号；下载器通过 GitHub API 匹配 `x86_64 + openwrt-25.12`，再验证归档内每个必需 APK 正则。

#### Lucky

- 上游构建仓库：<https://github.com/leesonaa/build_luci-app-lucky>
- 核验时 latest tag：`main`
- Release notes 明确标注 `ImmortalWrt 25.12`，并提供 x86/64/x86_64 表格
- 实际选择：`lucky-2.27.2-r1_x86_64.apk`、`luci-app-lucky-2.2.2-r1_x86_64.apk`、`luci-i18n-lucky-zh-cn-25.051.13443.e78d498_x86_64.apk`
- 下载器同时要求 Release 正文兼容性正则、x86_64 APK 资产正则和 GitHub digest；任一不满足都会失败，不会猜 URL

这三项确认的是 **25.12 + x86_64 APK 发布资产存在且 digest 可验证**，不是对所有组合、未来 release、配置和运行时行为的保证。OpenClash 是架构无关 APK，但仍会校验官方依赖；Nikki/Lucky 使用严格 target-series 规则。未来 29.0 不会复用 Nikki 的 25.12 tarball，也不会因为 GitHub 上“有 APK”就推断兼容。

### 尚未解析

Bandix、Homebox、netspeedtest 没有默认 provider。报告出现且目标 release 缺失时会进入 `packages-missing.txt`。不要为了通过 strict mode 删除它们；应添加经过核实的 provider 或明确从迁移目标移除。

### 添加新 provider

1. 在 `config/thirdparty.yml` 的 `providers` 下新增 provider：
   - 官方 GitHub `repository`；
   - `latest` 或 tag 策略；
   - 用模板锁定目标 series、架构、APK 的 `asset_patterns`；可用变量为 `{target_version}`、`{target_series}`、`{target_major}`、`{arch}`、`{profile}`；
   - 若是 tar.gz，添加每个必需 APK 的 `archive_member_patterns`；
   - `require_digest: true`；
   - 必要的 `official_dependencies`；
   - 如果兼容性只在 Release notes 中声明，添加 `compatibility_body_regex`。
2. 在 `config/package-rules.yml` 的 `thirdparty` 中把旧包名映射到 provider。
3. 如果希望有 workflow 开关，再给 `resolve-packages.py` 和 `build.yml` 增加对应 `include_*` 参数。
4. 用 `fetch-thirdparty.py --version <release>` 实际下载，确认每个 asset 只有一个匹配、digest 通过、归档成员齐全；为未来版本增加 synthetic fixture，但不要伪造“上游已支持”。

## 修改 package-rules.yml

- `replacements`：仅放跨版本都成立的回退规则；通常留空。
- `version_rules.<target_series>.replacements`：release series 专属回退规则，例如 25.12 的 `opkg: apk-openssl`。owut 报告中的 replacement 始终优先。
- `ignore` / `ignore_prefixes`：让 ImageBuilder 重新解析的库/依赖。
- `never_downgrade`：绝不自动接受目标低版本的包。
- `always_keep`：极少量明确功能包；不要把完整 installed list 填到这里。
- `remove_if_present`：与替代包冲突的旧包，例如 dnsmasq。
- `thirdparty`：旧包 → provider。
- `kernel_keep_patterns`：允许从报告保留的功能/NIC kmod。
- `feature_groups`：以 `when_any` 触发，使用 `add` 或 `preserve_present`。

改规则后先跑 Analyze，检查差异，再跑 Build。

## 用新 owut 报告重新生成 manifest

覆盖 `reports/current-system.txt`（以及推荐的 `reports/top-level-packages.txt`、可选的 `reports/installed-packages.txt`），重新运行 Analyze/Build 即可。Actions 不复用旧 `generated/`；仓库中的 `generated/` 只保留 `.gitkeep`。

本地只做分析（需 Python 3.12+）：

```sh
python -m pip install -r requirements.txt
python scripts/parse-owut-report.py \
  --report reports/current-system.txt \
  --installed reports/installed-packages.txt \
  --top-level reports/top-level-packages.txt
python scripts/resolve-packages.py
python scripts/validate-manifest.py --version 25.12.2 --strict --online
python scripts/fetch-thirdparty.py --version 25.12.2 --strict
```

换到新 release 时，先在路由器上用对应 `--version-to` 重新生成报告，再把 Analyze/Build 的 `immortalwrt_version` 改成报告中的精确 `Version-to`。不要拿 25.12 报告构建 29.0；版本不一致会在下载 ImageBuilder 前失败。

### 假设未来 29.0.1 发布后的操作示例

这只是未来操作流程示例，不表示 29.0.1 现在真实存在或已验证。届时先以新版 owut 的实际参数为准生成报告：

```sh
owut check --verbose --version-to 29.0 > reports/current-system.txt 2>&1
# 如果未来 owut 要求精确 patch，则改用 --version-to 29.0.1
```

提交经脱敏检查的报告后，在 Build workflow 输入：

```text
immortalwrt_version = 29.0.1
report_path = reports/current-system.txt
```

Actions 会验证 29.0.1 官方 release、ImageBuilder、报告目标、官方包和三个 provider。若 Nikki/Lucky 尚无 29.0 明确资产，strict 模式会停止；非 strict 模式会跳过它们，以 `-degraded` artifact 和 `SUCCESS WITH WARNINGS` 摘要交付核心固件。无需把源码中的 `25.12` 改成 `29.0`。

## 构建前后日志

构建前会打印 source/target、target/profile/rootfs、ImageBuilder URL、基础包、动态官方包、第三方包、missing、skipped、replacement、降级警告和 APK 文件名。

构建后会列出 `bin/targets/x86/64/` 的全部文件，重点检查：

- `*generic-ext4-combined-efi.img.gz` 是否存在；
- 文件大小是否合理；
- `generated/firmware/sha256sums`；
- ImageBuilder manifest/BOM（若生成）；
- `migration-report.md` 和 `system-analysis.json` 是否随 artifact 上传。

第一次运行最应观察：

1. Analyze 的 `Version-from/Version-to/Target/Profile` 是否正确；
2. `packages-missing.txt` 是否为空，缺失原因是否合理；
3. `Downgrade warnings` 是否包含 OpenClash 且第三方清单使用 0.48.002；
4. 在线 validation 是否确认所有官方包名存在；
5. GitHub Release asset/digest 是否匹配；
6. ImageBuilder SHA-256 是否通过；
7. `make image` 是否报告 package conflict/unsatisfied dependency；
8. 首次启动串口/SSH 日志中的 `thirdparty-bootstrap` 是否成功；
9. Docker 29/containerd 2.2 的 daemon、网络和旧 volume 恢复是否另行验证。

## Artifact

成功构建至少上传：

- `generic-ext4-combined-efi.img.gz`
- `sha256sums`
- `migration-report.md`
- `system-analysis.json`
- `final-packages.txt`
- ImageBuilder manifest/BOM（如果生成）
- 第三方资产元数据和 SHA-256
- `release-capabilities.json`、`thirdparty-status.json`、`compatibility-report.md`

不会自动上传任何路由器配置。

## 安全与隐私

禁止把以下内容放进仓库或固件：

- `/etc/openclash`、OpenClash YAML、订阅 URL、proxy providers；
- Lucky token；
- AdGuardHome 密码和私有配置；
- Docker volumes、`/opt/docker`；
- SSH 私钥、API key、Token、个人域名凭据。

owut 输出本身也可能泄露自定义源 URL、主机名或错误中的凭据。提交 public repository 前必须人工审查 `reports/`。解析器会对明显 token/password/private-key 模式报警并避免把原行复制进生成报告，但这不能替代人工审查。

## 实际上游验证记录

2026-10-28 已实际完成：

- 下载 `sha256sums` 与 51.6 MiB 官方 ImageBuilder，SHA-256 为 `b9b290f5ef60a22bccd5bdca9c1e7523b8fc84e60462afbf550e20db94acf2c6`；
- 解压并运行 `make info PROFILE=generic`，返回 `Current Target: x86/64`、`Current Architecture: x86_64`、`generic: Generic x86/64`；
- `profiles.json` 确认 25.12.2、kernel `6.12.103`、`generic`、ext4 combined-efi 主镜像；
- 下载器实际下载并校验 OpenClash、Nikki、Lucky，共得到 8 个所需 APK；
- 读取 target、kmods、base、luci、packages、routing、telephony 的官方 `index.json`，示例动态 manifest 的每个官方包名均存在；
- Python 语法、YAML、ShellCheck、actionlint、路径与示例 Analyze/Resolve/Validate 链路均由交付前检查执行（见最终交付说明）。
- 28 个 pytest 用例通过，覆盖安全版本语法、报告版本不一致、缺失 EFI/ext4 能力、缺少 ImageBuilder、未知包管理器、feed 自动发现和 synthetic 29.0 fixture；synthetic fixture 只证明代码路径不依赖 25.12，不代表 29.0 已发布。

本地 macOS/ARM 只用于元数据、归档和 `make info` 核验；完整 ImageBuilder 构建依赖 GitHub 的 Ubuntu x86_64 runner，首次完整固件结果应以 Actions 为准。

## 已知限制

- owut 输出格式可能继续演化；未知格式不会按固定行号误切，但顶层包列表完全无法识别时，解析器会退回“仅功能触发 + always_keep”，并在 `parser_notes` 提醒。
- `opkg status` 的 user-installed 标记不是所有版本都可靠，因此只作补充。
- 第三方 APK 使用 `--allow-untrusted`，安全边界是固定官方 GitHub 仓库、Release API、兼容性/文件名规则和 SHA-256 digest；它不是官方 ImmortalWrt feed 信任链。
- Lucky 的 upstream 是构建仓库，确认到 25.12/x86_64 APK 层面；升级到新的 25.12 patch 后仍应查看首次启动安装日志。
- 未来 release 的官方包名、包管理器、镜像布局和第三方资产均可能变化；能力检查会尽量早失败，但不会把“metadata 结构可解析”等同于运行时兼容。
- 8 GiB `ROOTFS_PARTSIZE` 会生成大 ext4 分区；这不代表适合覆盖当前 NVMe 的人工分区布局。
- 本仓库不自动执行 sysupgrade、`dd`、GPT 修改或配置迁移。

## 目录结构

```text
.
├── .github/workflows/
│   ├── analyze.yml
│   └── build.yml
├── config/
│   ├── base-packages.txt
│   ├── package-rules.yml
│   └── thirdparty.yml
├── files/etc/uci-defaults/99-install-thirdparty
├── generated/.gitkeep
├── reports/
│   ├── current-system.txt.example
│   ├── installed-packages.txt.example
│   └── top-level-packages.txt.example
├── scripts/
│   ├── build-image.sh
│   ├── fetch-thirdparty.py
│   ├── parse-owut-report.py
│   ├── release_utils.py
│   ├── resolve-packages.py
│   └── validate-manifest.py
├── tests/
│   ├── fixtures/
│   └── test_*.py
├── .gitignore
├── README.md
├── requirements-dev.txt
└── requirements.txt
```

