# 固定 Kura 服务重启与网关主机重启

2026-11-07：已完成新 IDEA 完整运行集/原 GWT、Orb 一次固定 Kura restart、现有 Parallels 一次实际 reboot 与完整 Kura 选定业务验证。完整证据见 console/docs/reviews/restart-reboot-system-20261107.md（4230b9b8）；不是正式发行或全组件恢复验收。

agent 保持运行，Kura 不依赖 agent 启动。此功能是可选的本机 root 授权，默认不配置；远程开关仍独立控制中心通道。保留 NetworkManager，禁止远端传 unit、shell、可执行路径或 reboot 参数。服务重启仅作用于安装时核定的 Kura unit/cgroup；不重启 agent，也不使用 `killall java`。

协议追加操作 23 `service.status`、24 `service.restart.prepare`、25 `service.restart`、26 `system.reboot.prepare`、27 `system.reboot`、28 `system.control.cancel`。仅 25/27/28 接受严格类型 `systemControlAction={transactionId,confirmationToken}`；transactionId 为 `system-UUID`。原 1–22 及字段编号保持。`ReadCommand` 的字段 14 是此 action。

安装管理员准备私有 JSON：schema=1，unit、unitFile、files 中每个固定文件的 path/SHA256，unitDefinitionSha256（封存时由实际 systemd 重算），allowRestart/allowReboot 分别显式授权；confirmationSeconds 60–600，observationSeconds 10–180，restartTimeoutSeconds 5–180。unit、drop-in、EnvironmentFile 均须固定文件校验；有效声明须为 `system.slice`、`KillMode=control-group` 且有限 `TimeoutStopSec` 不超过 180 秒。目标名限定 Kura，禁止管理中心/agent。需要业务核验时同时给 ordinaryProfile（既有固定 ordinary profile）和 snapshotDirectory；二者不得只给其一。没有业务 profile 就只报告进程结果。

使用包内入口（agent 需先正常停止以改变安装授权；不会更改其他服务）：

模板在包内 `/usr/share/doc/kura-management-agent/system-control.json.example`。模板的两个动作均关闭，文件 SHA 是占位值，不能直接授权；管理员必须明确选择动作、填入实际文件 SHA 和实际有效 unit 路径，封存工具只重算 systemd 声明 SHA，不替代这些审核值。

```sh
sudo kura-agent-setup configure-system-control \
  --request /etc/kura-management-agent/reviewed-system-control-request.json \
  --remote-disabled --operator installation-admin
```

`--remote-enabled` 是独立且必须明确选择的替代参数；它不会自动打开 `AGENT_REMOTE_ENABLED` 或持久远程通道。入口调用 Rust `seal-system-control`，只读实际 systemd 声明和固定文件并创建全新的私有授权文件。旧授权、旧 env 和安装审计保留。env 切换前落 `.system-control-installing`；中断时启动和维护均拒绝，现场保留供明确处理。入口不启动/启用任何目标；配置更新后由管理员在合适时机恢复 agent。底层环境项为 `AGENT_SYSTEM_CONTROL_CONFIG` 和默认 0 的 `AGENT_SYSTEM_CONTROL_REMOTE`。配置错误使该功能挡写，不能使 agent 或独立 Kura 成为彼此的启动依赖。

本地 UDS 仅允许 root/admin 身份，已注册 Kura 连接即使 UID 与 admin 相同也不能调用。远程仅限已认证当前归属的中心 admin，受首次密码设置、CSRF、任务加密、本机授权、当前会话新鲜 capability 和系统变更协调保护。重启服务/主机分别广告 `service.restart.v1`/`system.reboot.v1`，并要求 `system.control.v1`。新写操作绑定准入时的连接 epoch；换连接后未投递的旧队列过期，已投递任务 UNKNOWN，只查询原命令。

prepare 捕获实际 boot ID、unit InvocationID、PID/cgroup、固定声明/授权 SHA 和选定快照/业务检查，返回短时 token。用户需审阅并明确勾选；执行前全部复核，先持久化 issued binding 再执行一次固定动作。服务 restart 有界等待新 InvocationID；主机 reboot 只安排一个固定 systemd timer（5 秒后执行），持久化调度确认后返回 UNKNOWN，不能将断连或“已受理”当成功。后台恢复只读观察实际新 boot ID 和固定服务，不重新调度/重启。

native 状态为 PREPARED → ISSUING → AWAITING_BOOT（主机）/VERIFYING_APPLICATION → COMPLETED；未执行 PREPARED 可 CANCELLED，任何不确定现场保持 RECOVERY_REQUIRED。过期未执行计划也只能显式取消；已执行计划不能取消。网络等未决事务及其他 UNKNOWN/RUNNING 写操作挡新系统动作；取消只结清自身未执行计划，不清除其他模块的 RR。观察器获得 OS 锁后重读 journal，避免将并发完成的事务回写成旧 ISSUING。

结果分别列出 requestAccepted、processRestartVerified、hostRebootVerified、applicationVerificationConfigured/applicationVerified。可选业务核验使用真实只读 ordinary provider：schema 2、固定 profile/nonce/快照、当前 PID、start level 5、选定 DS 组件、唯一可用 provider 和选定检查。已 ready 的失败检查立即形成 FAILED，不重复业务检查或系统动作。尚未 ready 可在有界时间内只读等待。`system-process-only` 不代表业务恢复；`administrator-selected-checks` 也只涵盖选定项。`kuraRecoveryVerified`、`normalBootVerified` 均保持 false。

每个原命令决定、原授权及完成回执为私有 create-only 文件；完整 protobuf wire SHA 绑定 ID、operation、幂等 key、TTL 和 token。只读 query 仅核对原命令/current-or-history/决定/回执，不调用 systemctl、业务 observer、修复或执行动作。原命令已过 TTL 仍可核定已完成事实，SQLite resolution 和中心审计各一次。缺失、孤儿、漂移或不匹配继续 UNKNOWN，现场挡写。后续合法计划先归档已结清 journal。agent 包维护与 Core preinst/postinst 无需运行 agent 即检查相同证据；未结清或损坏则拒绝，purge 不删除保留的系统任务记录。

中心中英文界面只在已安装并广告此能力时显示，独立于 `kuraAvailable`。浏览器仅保存意图 key/operation/task ID，不保存确认 token。丢失 POST 响应或刷新后，通过同用户/网关的只读 intent 查回原 ID，404 仍挡写，不补发 POST。UNKNOWN 有界只 GET 原任务；进程、主机和业务状态分别呈现。

2026-11-07 实证补充：空 ExecStop 可被 systemd 255 省略，按空值规范化仍严格固定 ExecStart 和其余有效声明。COMPLETED 的 service.status 展示持久提交的完整 outcome，刷新/agent 重开保持原进程、主机与选定业务证明，不重新执行动作或业务检查。默认未配置时本地相关方法返回 UNSUPPORTED，中心不显示能力入口。普通 profile 安装封存要求目标停止；system request 的 unitDefinitionSha256 为必填占位摘要，由 sealer 读取实际有效声明重算。Parallels 本轮私有 Java/284 bundle 的472固定文件和真实 sandbox/UNKNOWN 原任务核定通过，不表示 Core deb 安装升级或全部业务恢复已完成。
