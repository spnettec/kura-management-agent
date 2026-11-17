# Native transport endpoint configuration v1

2026-11-18；代码 `3e28a441d2e50969768a8732d80b7e8b050be32b`。为已登记的同一 native 身份提供独立、显式的 Root gRPC 连接地址。首次登记材料、私钥、证书、原结果、环境、权限及远程决策不重写。当前仅支持首个配置及同号发布补全，不代表完整连接配置更新、图形入口或平台矩阵完成。

## 地址与身份

中心现有 HTTPS API 与 gRPC 监听可使用不同端口。原登记材料的 `endpoint` 保留为原字节；连接地址从固定 `/etc/kura-management-runtime/transport-endpoint.json` 读取。缺文件时保留既有地址行为；有文件但验证失败时拒绝，不退回环境变量或旧地址。

公开文件须 Root `0:0/0644`、普通单链接，并遵循现有保护目录要求。恰 15 字段绑定初始化、原 peer 授权 ID/结果 SHA、native UID/control GID、网关、原地址、连接地址、原身份回执 SHA 和最低 generation。`unitStarted=false`、`remoteEnabled=false` 表示配置动作不启动服务或开启通道，不是以后运行状态的声明。

两地址只能为无用户信息、路径、query、fragment 的 HTTPS 地址，同 host、不同地址。显式端口须数字且在 1–65535；空端口、0 和 65536 拒绝。Rust 不将 URI 库把越界端口解释为“未指定”的结果当成默认端口。Root schema 和 Rust 均拒绝额外/重复字段、bool 冒充整数、角色/安装/网关/回执错配。

同 generation 绑定原回执字节；后续只有 Enrollment 原有密码学及业务准入独立验证通过的续期可沿用同一网关与中心范围的连接地址。续期的当前 remote target 比较使用已解析的运行连接配置。此改动不签发证书、不改变登记历史，也没有重放已闭环续期验收。

## Root 控制与中断

三个固定动作都要求原 `--request-id`、`--initialization-id`，配置另需 `--endpoint`：

- `configure-native-transport-endpoint`
- `complete-native-transport-endpoint`
- `native-transport-endpoint-status`

先核验本机安装 namespace，再打开保存的请求路径。配置要求原 Root 代码/peer/material/source 配对、Core/native/两材料 socket 停止排空、远程决策为 OFF、业务 0，以及完整首次身份盘点。没有放宽 `.data`、Root 配对、非空 WAL、未知文件或已有业务状态准入。

全局 pending 意图先写入，封存当时 descriptor/source pointer、初始化回执 SHA、完整保留态指纹及身份摘要。私有记录位于 `/var/lib/kura-management-agent-admin/transport-endpoint/`，目录 `0700`、文件 `0600`；原 intent/result/published ACK 与 current pointer 和公开配置哈希匹配。独立证明资产共 7 项。

补全只能沿同一原 intent、同一代码 epoch 和仍精确的保留状态完成缺失发布；不重做外部写入。最早私有索引缺失仅可从完整原全局意图补齐，不能事后构造历史。孤立配置、丢 pointer、错 ACK、另一请求或错误安装均拒绝。原 APPLIED 与现行 READY/REFUSED 分开；已有配置不被新 ID 替换。

## 当前验证

Python 全集 266 selected，264 通过、2 个既有导出夹具排除；包含本模块 16 个测试方法。干净 Git 自包含导出后的 Rust 身份 15/15；enrollment/renewal 30 通过、4 个显式 Root/cross-UID 夹具忽略。计数互有覆盖，不作累计或整体进度。实际 native 首次 FD/密码学验收见前次检查点，不将本次忽略场景算通过。

同 E、同初始化 `24560864-f974-46aa-940a-0a97ad926118`，source `a12f9c21-c02c-4c7a-a63e-99cbfc4a6c8f` 一次准备/安装 APPLIED。`0.1.0~native202611171817.3e28a44-1` arm64 包 SHA `bb3230eb083139d5ea0546531960444a31c85de4e0926a5ef3fd396b15033c13`，源码清单 SHA `0cfe4cdf9d7b3e41c0c09dce84d157ef578feb44f568e23343ea4d26d6472135`。当前协议从声明 Git 重新打包，bridge 只读当前 Root 配对安装，不用旧 ELF/crate。

独立配置 `2031e3d3-a90b-4ad8-8445-f5a5138ecb0f` 一次 APPLIED/READY，将实际连接选为 `https://192.168.215.3:18444`，原材料 `https://192.168.215.3:18443` 不动。65 停止态保留资产精确，原开关授权 9 项、连接配置 7 项证明在启动后精确；原身份 20/材料 32、Core 私有 6/local 7/material 5 保持。

随后由原 GWT 单次开启、HTTP200/`//OK`；原 revision `148047bd-0da7-4b65-86a8-e75893f701ee` 到 `c693589f-03e5-4dc1-be19-56bd87363ea8`，actor `kura-uid:996`。本机与中心均在线，原叶证书 `3681eb86…79f1a`、同网关/generation1，真实心跳 epoch `4b8e3040-33d7-47b6-b8a4-62f160fceaa9`。agent UID/GID997、五 capability 集 0、NNP1；Core 11/13 capabilities、NNP0 仍待办。业务/任务尚为 0。

完整 Root GUI、跨刷新开关 UNKNOWN 原请求留存、受限实际任务、保留业务/续期/TLS/UNKNOWN 的安装升级、typed broker/Core 最小权限和完整发行矩阵仍内部 pending。详细公开记录在 console `docs/reviews/native-first-mtls-review-20261118.md`；目标保持 active。
