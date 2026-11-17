# Native Kura local switch delegation v1

2026-11-18；代码 `a7e5d3c`。这是独立的本机 Kura 开关权限，授权本身保持远程通道关闭。当前仅交付首个本机授权及原记录补全，不代表全部权限撤销、旧态迁移、业务数据维护或发行矩阵完成。

## 权限与代码边界

前提是已安装并核验 `native-nonroot-v1`、原 Kura peer 授权及其完整 source 链。Core、native agent 及两材料 socket 须显式停止并排空；legacy agent 须停止。首次授权仍要求受支持的初始空业务状态；保留首次身份使用完整材料盘点，不重建或认领已有数据。

授权只将 Root 私有 `agent.env` 中 `AGENT_KURA_REMOTE_MANAGEMENT=0` 原行原子替换为 `=1`。`AGENT_REMOTE_ENABLED=0`、其他开关、接口范围、UID/GID、组成员及所有身份/材料保持。控制器不启停服务，不连接中心，不重新生成 CSR、签发、暂存或绑定身份。

独立公开证明 `/etc/kura-management-runtime/kura-remote-switch.json` 为 Root `0:0/0644`，恰含 13 字段：版本/profile、原 request ID、初始化 ID、原 peer 授权 ID/结果 SHA、native UID/control GID、Kura UID/GID，以及 `canControl=true/unitStarted=false/remoteEnabled=false`。Rust 启动时验证同一权限和原身份。证明缺失、额外字段、错误类型、角色错配或环境标志与证明矛盾均拒绝；环境变量单独不能授予能力。

授权绑定稳定初始化及原 peer 结果，授权时另封存当时 descriptor/source pointer。Root 现行代码配对仍由 `RuntimeSetup/KuraPeer/SourceUpdate` 完整检查；没有将暂时未发布的新代码指针当成授权范围，也没有放宽原 Root 检查。后续受支持 source 演进保留原授权证明，仍检查代码链与其准入状态。

## 原请求与补全

Root 全局 pending 意图先持久化；私有目录 `/var/lib/kura-management-agent-admin/kura-remote-switch/` 为 `0700`，原意图、前后环境字节、结果及发布 ACK 为 `0600`。结果和公开证明有不可变 ACK 哈希；独立 current pointer 选择原结果。孤立目录、丢失 pointer、变更字节或另一个原号不会成为新授权机会。

`UNKNOWN` 保留原号，只能只读观察或用同号补全原持久化发布。补全检查原 intent、环境前后字节、完整状态指纹、初始化/代码 epoch、停服状态和其他维护 pending；不重做外部操作。若最早的原索引尚未写完，只在原全局 intent 存在、环境及完整指纹仍原样时建立缺失索引，不能事后捏造旧环境。

`APPLIED` 是原授权事实；现行 readiness 另外核验。原结果存在但当前证明损坏时可以保留 `APPLIED/REFUSED`，不能据此启动或重授权。

## 固定控制入口

`kura-agent-setup inspect` 不接受旧请求号，只核验当前安装的代码、原初始化、generation/plan-key 连续性，返回公开安装 ID/source 指纹、角色、权限状态和本机原授权号，不返回环境内容、密钥或凭据。

以下新动作均必需 `--initialization-id` 和 `--request-id`：

- `authorize-kura-remote-switch`
- `complete-kura-remote-switch`
- `kura-remote-switch-status`

入口在打开保存的请求路径前核验当前安装身份。另一 Root/安装的请求不得在此查询、补全或换号。旧 source、peer、material 动作的既有范围保留。

主机页在独立管理中心 installer 工具中实现公开原号留存、明确确认、状态读取和原记录补全；通过已有 Cockpit `superuser=require` 通道调用固定 Root bridge。它不把 GWT 管理员变成 OS Root，不提供任意路径/命令或启停服务接口。当前真实 PAM/Cockpit 入口仍待实机验收，不能用浏览器夹具代替。

## 当前验证

250 个 Python 用例中 248 通过、2 个历史导出夹具排除，含本模块 23 个新方法；当前 Git 干净导出后的 Rust 身份测试 10/10。中心打包/控制 129/129，主机页及原安装流程浏览器 60/60，其中本模块 13 个场景；双语 390px 截图已检查。这些数字互有覆盖，不作累计或整体完成率。

实际 E 仅原 source `a8226dd5-fe5e-4631-a9ea-76bb89ee3130` 一次升级为 `0.1.0~native202611171716.a7e5d3c-1`。首次独立授权 `49e58164-08a1-4511-8b61-ab0e585c2467` 由已配对固定 Root 控制器一次完成，`APPLIED/READY`；未使用图形 PAM 入口。授权前 58 个对象中 57 个指纹原样，唯一环境文件恰改一行；9 个授权证明资产在启动后精确。native cap 全 0、NNP=1，Core 仍有 11/13 capabilities、NNP=0 的内部待办；Root key/recovery/NM 原进程保留。原身份、Core 私有、peer/material 证明及原回执保持；实际 GWT 可明确确认，但未勾选或开启通道，remote 原 revision 仍 OFF。

观察器曾错误固定资产数为 56；新增的是产品准入原已支持的空 WAL 和 32KiB SHM，原私有普通文件不变。另有换行转义、目录误用文件指纹函数、独立 snapshot 缺材料 context 的只读核验失败；均保留，改为完整 enrolled context 后核验通过，未改变产品准入、重发授权或修补数据。详细公开检查点在 console `docs/reviews/native-kura-switch-review-20261118.md`。
