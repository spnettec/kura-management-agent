# Netplan capability scope v1

2026-11-18；实现 `5f95a7e`、测试修正 `24552f6`。仅修正 Netplan 能力宣告与现有接口授权范围的一致性，完整所有后端/readiness/发行矩阵仍待完成。

`transport::connect` 的 Hello 能力清单统一从 `transport::capabilities::advertised` 生成。无 network 后端时不宣告 `network.*`；已构造后端但固定接口 allowlist 为空时，只宣告 `network.inspect`、`network.transaction`、`network.takeover.plan`。只有配置了非空允许接口范围，才宣告既有 `network.prepare`、`network.confirm`、`network.rollback`、`network.takeover.prepare`。

判断复用同一不可变接口范围，和既有 inspect 的 `writeEnabled` 含义一致，不通过探测/写网络来生成清单。能力宣告本身不授予接口、Root 权限或任意操作；实际执行门禁、旧记录及结果核定能力保持。configuration update/snapshot 等独立开关仍独立处理。本轮不代表全部能力 readiness 已审计，也不新增或默认开启 NM/Netplan/防火墙授权。

四项新测试覆盖无后端、空范围只读、显式范围保留事务协议、configuration/snapshot 开关互不授权。当前干净 Git source 的 transport 18 通过/5 个显式系统故障夹具 ignored，network 35 通过/0 ignored。首轮错误使用未引入的 `tempfile` 测试依赖，编译失败保留；改为项目现有临时目录方式，没有增加依赖。Python/Root 安装源码与 `3e28a44` 逐字节未变，既有 266 selected/264 通过/2 历史夹具排除的适用证据保留，本轮未重跑或累计。

实际 E 当前安装 `0.1.0~native202611171836.24552f6-1` arm64，包 SHA `239eac991d5444f64ab3053c7f1babe8a6a7d4ce15af79b07358b1226a41f0fc`；source 操作 `8a93b64a-0c41-4816-b092-29eb683f783e` 一次准备/安装 APPLIED。已有开关授权 `49e58164…`、连接配置 `2031e3d3…`、身份和证书保留，72 个停止态资产精确。

明确确认的维护 OFF 与恢复 ON 各单次成功；当前 ON revision `bc29b319-608b-4920-bef3-9a161b0f5a11`，实际中心 Hello 从15项变11项，四项未授权网络写能力消失，既有只读/核定能力保留。同网关/generation1、原叶证书，native UID997、capability全0、NNP1。

中心单次状态任务 `7e30af94-6bcd-40cb-a0e4-af475360cab6`、原 idempotency key `4f46051a-eeff-4aef-ae9d-f8debfd82a51` 已 SUCCEEDED，agentAvailable/kuraAvailable=true。网关现行 `executions` 表存原 SUCCEEDED admission、加密 plan/result；旧 `results` 表仍0。本次实际业务状态为 executions1、WAL12,392字节，必须保留；不能清空或 checkpoint 凑既有 source 的空业务准入。完整保留业务/续期/TLS/UNKNOWN 的安装升级仍内部 pending。

详情及失败观察器更正见 console `docs/reviews/native-capability-status-review-20261118.md`。目标 active；全部12父项仍待最终验收，不推送。
