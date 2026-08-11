# Dynamic Private Proof of Assets

Rust 原型，实现论文中的动态隐私资产证明流程。当前仓库包含两条路径：

- `nizk-fixed-set`：基于集合多项式、KZG、Pedersen commitment、ZKOpen、
  salted witness commitment 和 Bulletproofs 的固定集合 NIZK；
- `smt` + `sp1-host`：Sparse Merkle Tree 与 SP1 guest/host 的更新和插入路径；
- `eth-sync`：把执行完成且已最终确认的 Ethereum state diff 转换为协议需要的
  地址向量和余额变化向量。

本仓库目前是研究原型，不应直接用于托管真实资产或生产证明。

## 快速开始

所有命令都从仓库根目录运行。新设备推荐只执行一个入口：

```bash
./poa bootstrap
```

该命令会检查或安装 Rust、固定版本 SP1 toolchain、Docker，断点续传并校验 SP1
Groth16 circuit artifacts，然后构建项目、生成开发 KZG SRS 和三个协议 guest 的 SP1
setup。macOS 自动安装 Docker 需要 Homebrew；Docker Desktop 首次启动仍可能弹出系统授权。
Linux 自动安装可能请求 `sudo`，首次加入 `docker` group 后如果当前 shell 尚未取得权限，
需要重新登录一次。

如果只想先运行不依赖 BN254 wrapper 的 compressed proof，可完全跳过 Docker 和大型
Groth16 artifacts：

```bash
POA_SP1_PROOF_MODE=compressed ./poa bootstrap
```

任何时候都可以运行环境诊断：

```bash
./poa doctor
```

这里有三种容易混淆的 artifact：

1. SP1 guest ELF：由 `cargo +succinct` 从仓库源码编译；
2. `params/sp1/*.bin`：本项目 guest 对应的 verification-key setup，由
   `./poa sp1-setup` 生成；
3. `~/.sp1/circuits/{groth16,plonk}/v6.1.0/`：SP1 官方 BN254 wrapper circuit、PK、VK，
   仅 Groth16/Plonk 需要。下载中断后只剩 `artifacts.tar.gz` 会触发
   `artifact not found`，`./poa bootstrap` 会识别并原子重装。

Docker **不参与 guest 编译和 `sp1-setup`**；当前 SP1 依赖配置只在最终
Groth16/Plonk gnark wrapping/verification 时调用 Docker。compressed 模式不需要 Docker。

SP1 v6.2.4 使用的官方 gnark wrapper 镜像
`ghcr.io/succinctlabs/sp1-gnark:v6.1.0` 目前只提供 `linux/amd64`。仓库入口和
benchmark 脚本会在 Apple Silicon（M1/M2/M3/M4）上自动设置
`DOCKER_DEFAULT_PLATFORM=linux/amd64`，由 Docker Desktop 模拟运行；第一次执行会先拉取
该镜像，时间不计入 benchmark。若绕过脚本直接运行 Rust binary，需要在同一个 shell 中先执行：

```bash
export DOCKER_DEFAULT_PLATFORM=linux/amd64
```

如果 Docker Desktop 报 x86_64/Rosetta 相关错误，请在 Docker Desktop 设置中启用
Rosetta 的 amd64 模拟；追求 wrapper 阶段的最高性能则应在 Linux x86_64 机器上运行。
日志末尾在 Docker panic 后出现的 `artifact not found` 只是上游证明线程失败的连带错误，
不表示 mock fixture、KZG SRS 或 `params/sp1` 丢失。

手动安装时要求 Rust stable，并确保 `~/.cargo/bin` 与 `~/.sp1/bin` 在 `PATH` 中。

```bash
cargo build --release -p poa-cli
```

仓库根目录已经提供启动脚本。后续统一使用：

```bash
./poa <command>
```

它会自动增量构建并运行 release 版本，不需要安装全局命令，也不依赖 shell alias。
直接输入 `poa` 会出现 `command not found`，因为当前目录默认不在 `PATH` 中；必须
保留前面的 `./`。

第一次创建目录并生成默认开发 SRS：

```bash
./poa setup                 # 默认 degree = 256
# ./poa setup 10000         # 指定更大的 degree
```

运行一组 mock 初始化和更新：

```bash
./poa prove-init mock-root-0
./poa prove-update \
  artifacts/states/init-state.txt \
  data/mock/deltas.csv \
  mock-root-1
./poa check-update-debug \
  artifacts/states/init-state.txt \
  data/mock/deltas.csv \
  artifacts/states/init-state-next.txt \
  artifacts/proofs/init-state-update-proof.txt
./poa prove-threshold artifacts/states/init-state-next.txt 100
./poa check-threshold \
  artifacts/states/init-state-next.txt.public \
  100 \
  artifacts/proofs/threshold-proof.txt
```

初始化产物会写入 `artifacts/states/init-state.txt` 和
`artifacts/proofs/init-proof.txt`；更新产物根据输入 state 的文件名自动命名。

也可以绕过启动脚本，直接运行：

```bash
cargo run -p poa-cli --
```

## 目录结构

```text
.
├── crates/                    Rust workspace crates
├── data/
│   ├── mock/                  mock CSV、SMT fixture、生成数据和 benchmark 输入
│   └── ethereum/              真实 Ethereum 执行状态变化输入
├── params/
│   ├── srs/                   KZG powers-of-tau SRS
│   ├── crs/                   Pedersen CRS 派生标签和说明
│   └── sp1/                   SP1 setup / verifying-key 缓存
├── artifacts/
│   ├── states/                prover state 和 public companion state
│   ├── proofs/                initialization/update/SMT/SP1 proof
│   ├── deltas/                同步器输出的规范化余额变化
│   ├── test-runs/             同步器元数据和测试输出
│   ├── reports/               报告
│   ├── benchmarks/            性能测试结果
│   └── legacy/                从旧目录迁移的历史产物
├── docs/                      架构与 SP1 Network 接入说明
├── tools/
│   └── kzg-msm-bench/         独立的 KZG/MSM 微基准，不参与 protocol benchmark
├── paper/                     协议论文（本地目录）
└── vendor/                    本地 patched dependency
```

`data/mock/generated/`、`data/mock/bench/`、`params/srs/*.bin` 和
`artifacts/` 下的运行产物默认不进入 Git。`artifacts/states/` 中的 prover
state 含余额和 blinding，应按敏感数据处理。

`crates/smt/`、`crates/smt-bench/`、`sp1-programs/smt-*` 和 `sp1-host` 中对应的
SMT host 入口是一套独立实验实现。高级 CLI 的 SMT 命令仍在使用它们，因此暂时保留，
但 initialization/insert/update 的 KZG protocol benchmark 不会调用它们。

`crates/static-bench/` 与 `crates/sp1-programs/static-init/` 是传统静态 PoA baseline。
它只验证账户输入、ECDSA ownership 和链状态 Merkle membership，不依赖 SRS，也不会
构造地址多项式、KZG accumulator/digest、opening 或可更新本地状态。

## Mock 数据

仓库自带小规模 fixture：

- `data/mock/reserves.csv`：初始化地址和余额；
- `data/mock/deltas.csv`：更新地址和有符号余额变化；
- `data/mock/smt/`：SMT 示例。

生成默认的确定性 mock chain：

```bash
./poa mock-data
```

默认规模为 64 个账户、8 个储备账户、6 个区块、每区块 20 笔交易，seed
为 42，输出到 `data/mock/generated/latest/`。也可显式指定：

```bash
./poa mock-data 1000 100 20 200 42
```

CSV 均无表头：

```text
# reserves.csv
0x<40 hex address>,<unsigned balance>

# deltas.csv
0x<40 hex address>,<signed delta>
```

读取 delta 时会规范化地址、排序、合并重复地址并删除零变化项。

## Ethereum 真实数据同步

复制并填写输入模板：

```bash
cp data/ethereum/transition.example.json data/ethereum/transition.json
./poa eth-sync data/ethereum/transition.json
```

默认输出：

```text
artifacts/deltas/ethereum.csv
artifacts/test-runs/ethereum-sync.json
```

前者可直接交给 `prove-update`；后者包含规范地址向量、delta 向量、区块和
state root 元数据、delta-list commitment 与 transition commitment。

生产验证还需要独立的 verifier policy 文件，格式见
`data/ethereum/finality-policy.example.json`。其中的 chain id、finalized roots、
last accepted root、last accepted public-state digest 和 pinned transition commitment
必须来自验证者信任的 finality/同步来源，不能直接从待验证 proof 或 sync-output
自报。完整协议状态摘要可用下面的命令计算，再由验证者独立记录到 policy：

```bash
./poa state-digest artifacts/states/init-state.txt
```

只记录链 state root 不够：同一个链根下可能连续执行 insert，产生不同的 accumulator
和 balance commitment。摘要会同时绑定 root、SRS degree、reserve count、accumulator
以及 balance commitment，防止旧协议状态分叉或重放。

同步器的输入不是单独的 Ethereum block。它必须是账本执行完成后得到的完整
state diff，并且区块已最终确认。Geth `prestateTracer` diff mode 可作为数据源，
但上游还必须覆盖 withdrawals、fee recipient 等协议级余额变化。详细格式见
`data/ethereum/README.md` 和 `crates/eth-sync/README.md`。

如需自定义输出路径：

```bash
./poa eth-sync transition.json deltas.csv sync-output.json
```

## 参数：CRS、SRS 与 SP1 setup

三类参数物理隔离，不能混用：

1. `params/srs/` 保存普通 KZG powers-of-tau G1/G2 powers。hidden insert 只需要普通
   G1 powers 来承诺 quotient witness，以及 `[1]_2,[tau]_2` 来构造隐藏点对象；默认
   SRS 不再生成百万级 hiding G1 powers。
2. `params/crs/` 保存 Pedersen commitment 和 Sigma ZKOpen 所用透明 CRS 的派生约定。
   基点使用标准 BLS12-381 G1 `XMD:SHA-256_SSWU_RO` hash-to-curve、独立 domain
   label 和 index 派生，不再使用已知离散对数的 `hash_to_scalar * G`。
3. `params/sp1/` 保存 SP1 guest 对应的 setup/verifying-key 缓存。它们不是 KZG
   参数，也不是 Pedersen CRS。

`./poa setup [degree]` 只生成默认开发 KZG SRS。协议 benchmark 只需为
initialization 和 KZG insert 生成 SP1 setup：

```bash
./poa sp1-setup
```

独立的 SMT 实现不参与 protocol benchmark；只有测试 SMT 路径时才执行：

```bash
./poa sp1-smt-setup
```

### Poseidon SMT + SP1 方案

这套实现把 genesis、地址集合维护与余额变化计算都放进 SP1。初始化使用两份通过同一个
ordered reserve commitment 绑定的 proof：`smt-init` guest 验证链余额证明并构造 Poseidon
SMT root，`init-ownership` guest 验证 ECDSA/密钥所有权。只有两份 proof 的 chain context、
reserve count 和 commitment 全部一致，host/verifier 才接受 genesis。
初始化输入必须按规范化后的 lowercase Ethereum address 严格升序排列；这样 host 不需要为
百万级输入再复制、排序一份完整 witness。示例 CSV 是 mock 入口，真实 Ethereum 集成通过
`prove_smt_initialization` 传入 ECDSA ownership signature 与 account/Merkle proof。

本地 prover 保存固定深度的 Poseidon Sparse Merkle Tree；update 的私有输入是 touch list、
旧叶子以及压缩后的 membership/non-membership paths。guest 验证地址到 Poseidon key 的
编码、旧 root、余额非负性，并批量计算新 root 和 aggregate delta。外部 verifier 只验证
可信本地 VK 对应的 SP1 proof，以及公开的旧/新链 state root、旧/新 SMT root、余额总量和
salted touch-list commitment。

SP1 proof 文件不会再保存 touch 地址、membership flags、Merkle paths、leaf salts、blind
delta 或 prover 提供的 VK。touch-list commitment 用于和独立验证的 sync 输出绑定；本实现
不负责证明 sync 数据确实来自 Ethereum 执行层。

固定深度树当前支持 `1..=128`。如果两个不同地址在配置深度内落到同一路径，初始化和
insert 会 fail closed，避免覆盖已有叶子；生产配置建议使用 128。初始 SMT root、balance
total、reserve count 和链 state root 均由 initialization proof 公开绑定，后续更新从这些
公开值递推。

```bash
./poa sp1-smt-setup
./poa smt-init 128 data/mock/init-witness.csv mock-chain \
  0x0000000000000000000000000000000000000000000000000000000000000000 \
  smt-session-0 artifacts/states/smt-0.txt artifacts/proofs/smt-init.txt
./poa smt-init-verify mock-chain \
  0x0000000000000000000000000000000000000000000000000000000000000000 \
  smt-session-0 artifacts/states/smt-0.txt artifacts/proofs/smt-init.txt
./poa smt-update artifacts/states/smt-0.txt data/mock/deltas.csv state-root-1 \
  artifacts/states/smt-1.txt artifacts/proofs/smt-update.txt
./poa smt-verify artifacts/states/smt-0.txt artifacts/states/smt-1.txt \
  artifacts/proofs/smt-update.txt update
```

要让 SMT 方案直接复用 protocol benchmark 已生成的 Ethereum 格式 mock 账户、ECDSA
signature、共享 Merkle prefix proof、delta 和 insert candidate，先准备原始 fixture，再执行
一次持久化 SMT initialization：

```bash
MASTER_N=1000 N_SIZES=1000 M_SIZES=100 \
  FIXTURE_DIR=data/mock/bench/generated-merkle-n1000-m100 \
  ./scripts/initialize_benchmark_data.sh

MASTER_N=1000 N_SIZES=1000 M_SIZES=100 SMT_DEPTH=128 \
  FIXTURE_DIR=data/mock/bench/generated-merkle-n1000-m100 \
  SMT_OUTPUT_DIR=data/mock/bench/smt-persisted-n1000-m100/master_n_1000/depth_128 \
  POA_SP1_PROOF_MODE=compressed \
  ./scripts/initialize_smt_benchmark_data.sh
```

第二个脚本会对每个 `n` 保存：

- `state-0000.txt`：小型状态元数据；
- `state-0000.leaves.bin` 和 `state-0000.nodes.bin`：可直接恢复的私有 SMT；
- `initialization-proof.txt`：两份绑定后的 SP1 initialization proof；
- `deltas-m-*.csv`、`insert.csv`：从同一份 NIZK mock fixture 导出的后续输入；
- `manifest.txt`：state root、新 state root、路径和规模信息。

重复运行会加载状态并验证 initialization proof，验证通过后直接复用，不重新建树或证明。
guest 或持久化格式升级后，可设置 `SMT_FORCE=true` 强制覆盖生成这一输出目录中的状态。
例如继续测试 `n=1000,m=100`：

```bash
RUN=data/mock/bench/smt-persisted-n1000-m100/master_n_1000/depth_128/n_1000
UPDATE_ROOT=$(sed -n 's/^m.100.new_state_root=//p' "$RUN/manifest.txt")
INSERT_ROOT=$(sed -n 's/^insert_new_state_root=//p' "$RUN/manifest.txt")

./poa smt-update "$RUN/state-0000.txt" "$RUN/deltas-m-100.csv" \
  "$UPDATE_ROOT" "$RUN/state-update-m100.txt" "$RUN/update-m100-proof.txt"

./poa smt-insert-file "$RUN/state-0000.txt" "$RUN/insert.csv" \
  "$INSERT_ROOT" "$RUN/state-insert.txt" "$RUN/insert-proof.txt"
```

update 和 insert 都从同一个初始化状态分别开始，互不覆盖。新格式不再把百万个 leaf
拼进超长文本行，因此加载时不会产生对应的大型临时字符串；旧的文本 SMT state 仍可读取。

#### 标准 SMT + SP1 benchmark

持久化准备完成后，使用独立的长驻 benchmark runner 测试 initialization、update 和
insert。它与 NIZK benchmark 使用相同的 warmup/sample 统计方法，但不会把 Cargo build、
fixture/state 文件加载、VK/PK context、CUDA worker 启动、guest ELF setup 或 proof 写盘计入
prover time：

```bash
MASTER_N=1000 N_SIZES=1000 M_SIZES=100 SMT_DEPTH=128 \
FIXTURE_DIR=data/mock/bench/generated-merkle-n1000-m100 \
SMT_STATE_DIR=data/mock/bench/smt-persisted-n1000-m100/master_n_1000/depth_128 \
SP1_PROVER=cuda POA_SP1_CUDA_DEVICE=0 POA_SP1_PROOF_MODE=compressed \
BENCHMARK_OPERATIONS=initialization,insert,update \
SAMPLES=3 WARMUP=1 \
OUTPUT_DIR=artifacts/benchmarks/smt-cuda-n1000-m100 \
./scripts/benchmark_smt_protocol.sh
```

每个 initialization sample 都会在 host 重新构造私有 Poseidon SMT，同时 `smt-init`
guest 在 SP1 内根据全部 leaves 独立重建并公开绑定 root；两项都属于在线 prover time。
update/insert 的 witness/multiproof 构造、host 私有状态转换、stdin 序列化与 CUDA IPC 也计入，
但所有 sample 都从同一个不可变的 `state-0000` 独立开始，不串联状态。为重复实验而进行的
整树 sample reset/deep clone 不属于协议在线工作，放在 prover timer 外；真正修改的路径、
新 root 计算和全部证明工作仍在 timer 内。开启 profile 后，这项排除成本会以
`sample_state_reset_excluded` 单独列出。

输出包括 `raw.csv`、`summary.csv`、`loading.csv`、`summary.md` 和 `proof-samples/`。
`proof_payload_bytes` 是原始二进制密码学 proof bundle；`artifact_bytes` 是当前项目落盘格式，
避免把 hex 文本膨胀误认为密码学证明大小。设置 `POA_SP1_PROFILE=1` 时还会生成
`profile/phase-times.csv`，其中列出 host 建树、witness、transition、stdin、SP1 prove 和
finalize 阶段；初始化额外执行的 cycle diagnostic probe 会从 measured prover time 扣除。

`scripts/benchmark_protocol.sh` 默认使用适合工作站的 SP1 分片与 trace-buffer
上限（`SHARD_SIZE=1048576`、两个 trace slots），以控制 Groth16 峰值内存。这些值
都会写入 benchmark 的 `environment.txt`，也可在命令前显式覆盖。

默认位置是 `params/sp1/`。开发 SRS 由确定性 seed 生成，不代表可信仪式，并会被
生产验证器拒绝。生产 SRS 必须由外部 ceremony 生成并导入：

```bash
./poa import-srs ceremony.srs.bin <ceremony-id>
```

导入器使用 subgroup-checked 反序列化，并用批量 pairing 关系检查普通 G1/G2 powers；
如果导入旧扩展格式中存在 legacy hiding powers，会在导入时丢弃它们。导入后在 SRS
旁写入 provenance `.meta` 文件。

`setup` **不会生成单独的 Pedersen CRS 文件**。Pedersen CRS 是透明 CRS：验证者
按照 `params/crs/domains.json` 记录的 suite、DST、label 和 index 重新 hash-to-curve。
它不需要秘密或可信仪式；KZG SRS 仍然需要外部 powers-of-tau ceremony，两者不能混用。

本次 CRS 升级与旧的 `hash_to_scalar * G` 基点不兼容。旧 state 中的 balance
commitment、旧 initialization/update/insert proof 都必须从 initialization 开始重新生成；
不能在旧 state 上继续 update。Merkle 分支的初始化 scheme 为
`kzg-nizk-init-v9-zkopen-keccak-merkle-unified`，insert scheme 为
`kzg-strong-zkopen-insert-v1-sp1-committed-input`。修改过 SP1 guest 后也必须重新运行 `./poa sp1-setup`；
loader 会比较 artifact 中记录的 ELF digest，旧 artifact 会 fail-closed 并提示重新 setup。
本轮只修改代码、未重新生成 SP1 artifact，因此首次运行前必须执行一次该命令。

SRS 读取器兼容两种文件：普通 `G1 powers + G2 powers`，以及末尾带 legacy hiding
G1 powers 的旧扩展格式。新生成的 SRS 将 hiding-power 长度写为零；`setup` 和 benchmark
准备阶段会在保留普通 powers/provenance 的前提下自动压缩旧扩展文件。替换实际
powers-of-tau 后仍必须重新生成依赖它的 state 和 proof。

底层 `gen-srs` 只生成明确标记的开发 SRS：

```bash
./poa gen-srs 10000 params/srs/custom-10000.bin
```

## 初始化、ZKOpen 与 hidden-point insert

初始化会生成 private prover state、public state companion 和 init proof。当前
初始化的 KZG evaluation 使用 Fiat–Shamir 非交互化的 Sigma ZKOpen，因此不会
把 evaluation 和 Pedersen blinding 直接写入 proof。

论文中的 initialization `C_shape` 是一个长度随最大集合规模增长的向量 Pedersen
commitment。当前 SP1 后端改用 domain-separated salted Keccak commitment：prover
先以 32-byte 私有随机 salt 提交 `(alpha, n, ordered address roots)`，再把 32-byte
摘要放入 Fiat–Shamir transcript 派生 `zeta`；SP1 guest 使用私有 salt 和地址 witness
重算摘要并检查相等。它保留 commit-before-challenge 的绑定关系（依赖 Keccak 的碰撞
抗性，隐藏性依赖私有高熵 salt），同时避免在 SP1 内进行约 `n` 次 BLS12-381
variable-base multiplication，也不再需要 initialization shape 的百万级 Pedersen 基点。
余额 commitment、evaluation commitment 和 KZG ZKOpen 不受此替换影响，仍分别
使用透明 Pedersen CRS 与普通 KZG SRS。

Insert 已切换到论文中的 `StrongZKOpen + ComNonZero` 协议。prover 在隐藏地址点
`u` 计算 `y=P(u)`，构造私有 quotient witness
`W_tilde=[beta^-1 Q_u(tau)]_1` 与公开 handle `D=[beta(tau-u)]_2`。
`StrongZKOpen(d,C_u,C_y;D)` 同时证明隐藏点、隐藏 evaluation 和 KZG opening；
`W_tilde` 不再公开，只通过一次性随机掩码响应 `Z_W` 出现在证明中。独立的
`ComNonZero(C_y)` 证明同一 committed evaluation 满足 `y*nu=1`。verifier 顶层只看到
`C_u,C_y,C_B,D` 及三个子证明，并额外检查 `e(d',G2)=e(d,D)`。

SP1 insert guest 现在对应论文的 committed-input SNARK 部分：私有验证 ECDSA ownership、
Merkle/account proof、地址编码和非负余额，并公开绑定 `C_u` 与 `C_B`。KZG pairing、
`StrongZKOpen` 和 `ComNonZero` 全部在 SP1 外验证，因此 SP1 输入和电路规模不再随旧
集合的 quotient 长度增长。由于 guest ELF 和公开值格式均已变化，升级后必须重新执行
`./poa sp1-setup`。

快捷初始化默认读取 `data/mock/reserves.csv`：

```bash
./poa prove-init <state-root> [reserves.csv]
```

注意：该 CSV 快捷入口仍使用 mock external ownership/balance adapter。真实链初始化
应通过库接口传入 `InitReserveWitness` 和真实 `ExternalProofAdapter`，不能把 mock
proof label 当作 Ethereum 账户证明。EthereumAccountProof 与链上 Merkle proof 的
构造方式取决于所使用的执行层状态树和 proof provider。

真实单地址插入可通过库接口 `KzgInsertWitness::ethereum(...)` 构造。默认
`apply_insert` 会选择 `Sp1NativeProofAdapter`：host 只把 artifact 标签绑定进外层
transcript，ECDSA ownership signature、公钥恢复、地址派生以及 Ethereum account MPT
balance proof 都在 SP1 guest 内验证；私钥不进入 SP1 stdin。签名采用
`r || s || yParity` 的 65-byte Ethereum 格式，绑定 operation、chain id、state root
和账户地址。真实钱包应对 `ownership_statement_hash(...)` 返回的 32-byte message
调用 `personal_sign`；guest 会重建 EIP-191 前缀摘要。它不会把 host-side 标签误当成
链证明本身。

## Range proof 与阈值证明

余额 range proof 使用与余额 commitment 相同的 Pedersen 基点。每个下界或上界
证明用两个 64-bit limb 组成一个 128-bit Bulletproof，并检查
`C_lo + 2^64 C_hi = C`。系统同时证明 `value >= 0` 与
`i128::MAX - value >= 0`，因此接受区间严格为 `[0, i128::MAX]`，同时不公开余额、
slack 或 blinding。

每个固定集合 update proof 都内嵌新总余额的非负 range proof；验证器还限制每个
公开 delta 以及全部公开 delta 的绝对值之和。这两部分共同排除有限域模数回绕。
普通 update 采用直接 `MultiZKOpen`：`D_Y` 一次性承诺全部隐藏 KZG evaluation，
Sigma protocol 证明这些 opening 来自旧 set digest；同一个 `D_Y` 再通过 committed-input
IPA 直接绑定到 Bulletproof 的零测试 witness wires。实现不再生成随机点 `theta`、
`C_v`、单点 `ZKOpen` 或第二份 evaluation-vector commitment。

update proof 的持久化格式因此升级为 `DPOAUPD6`：旧 update proof 必须重新生成，
KZG SRS 不需要因此重建；Pedersen CRS 会按域分离标签派生 `D_Y` 的向量基点和独立
blinding base。

`parallel-*` 命令属于独立的 legacy 分片实验，使用自己的 shard proof 类型，不是
`DPOAUPD6` 普通 update 路径，也不包含在 protocol benchmark 中。

insert proof 也内嵌插入后 aggregate balance commitment 的非负 range proof，避免
状态经过插入后离开协议接受的整数范围。

对公开阈值 `T` 证明 committed assets `>= T`：

```bash
./poa prove-threshold <private-state.txt> <T> [proof.txt]
./poa check-threshold <public-state.txt> <T> <proof.txt>
```

库接口还提供 `prove_committed_liability_threshold` 和
`verify_committed_liability_threshold`，用于论文中的 committed liabilities 比较；
证明对象是 `C_assets - C_liabilities` 对应的非负 slack。

## 高层命令

```text
./poa setup [max-degree]
./poa import-srs <source.srs.bin> <ceremony-id> [destination.srs.bin]
./poa mock-data [accounts reserves blocks txs-per-block seed]
./poa eth-sync <transition.json> [deltas.csv sync-output.json]
./poa prove-init <state-root> [reserves.csv]
./poa prove-update <state.txt> <deltas.csv> <new-state-root>
./poa check-update <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt> <sync-output.json> <policy.json>
./poa check-update-debug <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt>
./poa state-digest <state.txt>
./poa prove-threshold <state.txt> <threshold> [proof.txt]
./poa check-threshold <public-state.txt> <threshold> <proof.txt>
```

`check-update` 是 fail-closed 生产入口：要求 external-ceremony SRS、完整
committed-opening、finalized/last-accepted `ChainPolicy`，并把 delta CSV 绑定到指定的
Ethereum sync output。`check-update-debug` 才是允许 development SRS 且不声明链上
Sync/finality 安全性的本地测试入口。

若规范 Sync 输出为空，update 使用显式的 `dpoa-empty-update-v1` no-op artifact：
只推进已认证的链根，不改变 accumulator、reserve count 或 balance commitment。

原有的 `init`、`update`、`verify`、`smt-*`、`parallel-*`、benchmark 和持久化
run 命令仍保留，便于实验脚本显式控制每一个路径。运行
`./poa help-advanced` 可查看完整列表。

## 数据流

日常固定集合 NIZK 只需要记住以下流程：

```text
setup
  └─> params/srs/dev.srs.bin

mock reserves.csv ───────────────┐
                                 ├─> prove-init ─> init state + init proof
真实 InitReserveWitness + adapter ┘

finalized Ethereum state diff ─> eth-sync ─> canonical deltas.csv + sync metadata
mock deltas.csv ──────────────────────────────┘

old private state + deltas.csv + new state root + SRS
  └─> prove-update ─> next private/public state + update proof

old/new public state + deltas.csv + proof + external SRS + pinned sync output
  └─> check-update / production verifier

private state + public threshold
  └─> prove-threshold ─> value-hiding range proof

public state + same threshold + range proof
  └─> check-threshold
```

Pedersen commitment 所需基点在证明和验证过程中由代码加载/派生，不会作为数据流
中的独立输入文件。真实 Ethereum 初始化目前走库接口；`prove-init` 这个快捷命令
默认仍是 mock 初始化入口。

## Benchmark

正常的 `prove-init` 和 `prove-update` **不会自动重复运行 benchmark**。它们只执行
一次证明。需要分阶段诊断时，可临时启用内部 timing：

```bash
POA_TIMING=1 ./poa prove-update \
  artifacts/states/init-state.txt \
  data/mock/deltas.csv \
  timed-root
```

原来的 benchmark 命令仍然保留，参数语义没有改变，只是路径应使用新目录：

```bash
# 对已有 state/delta 重复测量；默认 5 次，warmup 1 次
./poa update-bench \
  params/srs/dev.srs.bin \
  artifacts/states/init-state.txt \
  data/mock/deltas.csv \
  5 1

# 不读取真实 state，直接构造 degree=10000、m=1000 的合成负载
./poa synthetic-update-bench \
  params/srs/dev.srs.bin \
  10000 1000 5 1

# 对 mock-chain 的所有窗口执行 init/update/verify 并写报告
./poa mock-bench \
  params/srs/dev.srs.bin \
  data/mock/generated/latest/manifest.txt \
  artifacts/reports/mock-bench.txt
```

`update-bench` 和 `synthetic-update-bench` 把统计结果打印到终端，不自动写文件；
`mock-bench` 的第三个参数是显式报告路径。benchmark 应始终通过 `./poa` 的 release
模式运行，否则 debug 编译会严重扭曲密码学运算耗时。

### 推荐：一条命令测试完整 NIZK

日常测试推荐使用一条简化命令：

```bash
./poa benchmark 1000 100
```

这里两个数字分别是 `n` 和 `m`，默认使用 CPU、`compressed` 模式、1 次 warmup 和
3 次正式采样。使用 CUDA 或修改采样数时：

```bash
./poa benchmark 1000 100 cuda
./poa benchmark 1000 100 cuda 3
```

该入口自动生成或复用对应的 mock 数据和 SRS，然后依次测试 init、update、insert。
终端只显示简短进度，以及三项操作的平均证明时间、平均验证时间和 proof size；完整日志、
逐样本 CSV 和详细报告仍保存在输出目录。需要 Groth16、Plonk、多组 `n/m`、单独 operation
或阶段 profile 时，再使用下面的高级脚本和环境变量。

固定的 powers-of-two 实验矩阵可以一键运行：

```bash
./poa benchmark-matrix          # CPU
./poa benchmark-matrix cuda     # CUDA
```

该脚本从 mock fixture/SRS 准备开始，测试 `n=1024,2048,4096,8192` 和
`m=256,512,1024`。动态 NIZK 的 init 和 insert 对每个 `n` 各产生一行结果，update
对 12 个 `(n,m)` 组合逐一测试；传统静态 PoA initialization 也对四个 `n` 分别测试。
静态和动态测试复用完全相同的 Ethereum 地址、ECDSA ownership、余额和固定深度 Merkle
fixture。每行包含 1 次 warmup 和 3 次 measured samples。CUDA 模式由 SDK 启动并持有
唯一的 `sp1-gpu-server`，等待其 Unix socket 就绪后再进入证明阶段，退出时自动回收。

### 独立 Ethereum MPT/SP1 benchmark

只测试 Ethereum state-trie account proof 的 RLP/MPT 验证时，使用独立 guest：

```bash
# 只测 SP1 execute 时间、cycles 和 syscalls，不生成证明；最后一个参数是 proof 数量
MPT_PROVE=0 ./poa benchmark-mpt cpu 3 1,16,256

# CUDA compressed proof，每种 proof 数量正式采样 3 次
./poa sp1-cuda-build
./poa benchmark-mpt cuda 3 1,16,256

# CUDA 批量矩阵：同一棵 8192 账户 MPT 的 1024、2048、4096、8192 条 proof
./poa benchmark-mpt-cuda-matrix
```

fixture 构建一棵真实结构的十六叉 Patricia trie，使用 Keccak key、hex-prefix compact
path、规范 extension/branch/leaf、RLP account 和 hashed/inline child reference；所有 proof
共享同一个 state root，不经过二叉 mock tree。测试不包含 ownership、KZG、Pedersen、SMT
或协议状态更新。`summary.csv`/`summary.md` 分开记录 MPT proof bytes、execute/cycles、
MPT 验证本体 cycles、prover、verifier 与 SP1 proof size；fixture 生成、独立 phase
profile 和 prover setup 排除在样本计时之外。
批量脚本只构建一次 8192 账户 MPT 并导出 proof，再按降序原地截断，避免重复 mock 和
复制大 witness。
更详细的边界见 `crates/ethereum-mpt-bench/README.md`。

完整协议矩阵由 `scripts/benchmark_protocol.sh` 运行。其 initialization fixture 在
SP1 外一次性生成 `10^6+1` 个确定性的有效 secp256k1 私钥、未压缩公钥、由 Keccak
派生的 Ethereum 地址、ECDSA ownership signatures、随机化余额，以及一棵覆盖全部
账户的固定高度二叉 Merkle tree。各规模使用同一 canonical account store 的前 `n` 个账户；
最后一个账户只存在于同一个 Ethereum state 中，供所有 insert benchmark 使用。SP1
内的统一 initialization guest 使用 patched `k256`/secp256k1 预编译恢复签名公钥、
用 Keccak permutation syscall 派生并核对地址，同时验证域分离的 leaf/node hash、
多项式随机点恒等式和私有 commitment opening，不再使用
`mock-private-key:<address>` / `mock-balance-proof:<address>` 标签。fixture 生成、磁盘
加载不计入 prover/verifier time。Ownership 与 Merkle/polynomial 现在只生成一份 SP1
proof，避免两次 stdin、两次递归压缩和两份 reserve commitment。

Initialization 不再为每个账户保存一条固定深度路径。不同 `n` 复用同一棵主树、同一个
state root 和相同高度，只持久化一个由后缀子树 frontier 组成的 shared-prefix proof；
guest 对前 `n` 个叶子做一次流式栈归并，工作量从 `O(n log N)` 降为 `O(n + log N)`，
且不再把约 `n log N` 个 sibling hash 写入 stdin。Insert 仍使用同一 root 下候选账户的
一条完整路径。
准备阶段在主树上应用随机 delta、记录真实的新 root 后恢复原叶子；
Sync/finality 证明仍按论文中的独立抽象处理，不计入 debug update verifier。

该二叉 Merkle tree 是 Ethereum 风格账户/密钥 benchmark fixture，不是 Ethereum 主网
MPT/Verkle 共识状态树；它用于隔离协议主体与 SP1 哈希路径性能。

完整 benchmark 必须分两阶段执行。先初始化并持久化最大到 `10^6` 个账户的数据：

```bash
./scripts/initialize_benchmark_data.sh
```

默认会准备以下矩阵：

- `n = 10^4, 10^5, 10^6`：共享一份 `10^6+1` 账户文件、一棵固定高度主 Merkle tree、
  同一个 state root 和 insert proof；每个 `n` 只持久化一个紧凑 shared-prefix proof；
- `m = 10^2, 10^3`：每个 `n` 先确定性生成最大 `10^3` 个互不重复的随机更新，
  `10^2` 是同一更新序列的前缀；两种规模分别持久化 canonical delta list 及其重建后
  的新 Merkle root；
- 一套由全部规模共享的 development benchmark SRS。普通 G1 powers 覆盖
  `MASTER_N+1`（insert 会增加一个账户），G2 powers 只覆盖 verifier 实际会
  提交的最大更新消失多项式 `max(m)`。这与 KZG 关系一致，并避免生成约一百万个协议
  完全不会使用的 G2 powers。

主树规模由 `MASTER_N` 控制，默认固定为 `1000000`，不随本次选取的 `N_SIZES` 缩小。
因此后续只测部分规模时可以继续读取同一份百万账户数据，例如
`MASTER_N=1000000 N_SIZES=10000,100000 ./scripts/benchmark_protocol.sh`。

Mock chain 使用固定深度 32 的 Keccak 二叉 Merkle Tree。实现只物化覆盖
`MASTER_N+1` 个真实账户的最小前缀，其余 `2^32` 容量由逐层预计算的 canonical
empty-subtree roots 表示，因此不会分配完整的 `2^32` 叶子。单账户 proof 固定包含
32 个 sibling；初始化的 shared-prefix proof 同样重建完整深度 32 的 state root。

文件默认持久化在：

```text
data/mock/bench/generated/
  preparation-manifest.txt
  master_n_1000000/ethereum-keccak-fixed32-merkle-prefix-v3-ecdsa/
    accounts.bin
    master-manifest.txt
    insert-merkle-proof.bin
    init-merkle-proofs-n-10000.bin
    init-merkle-proofs-n-100000.bin
    init-merkle-proofs-n-1000000.bin
    deltas-n-*-m-*.csv

params/srs/bench/
```

准备完成后再运行：

```bash
./scripts/benchmark_protocol.sh
```

如果只需要隔离测试 update，不运行耗费资源的 initialization/insert SP1 proof，可复用准备
阶段持久化的初始化后状态。该状态包含由 Mock 地址集合构造的真实根多项式、KZG
accumulator、余额向量和 Pedersen balance commitment；只省略 initialization proof：

```bash
BENCHMARK_OPERATIONS=update SAMPLES=3 WARMUP=1 \
  ./scripts/benchmark_protocol.sh
```

update-only 模式会跳过 `poa sp1-setup`；initialization-only 只准备统一 initialization
guest，insert-only 只准备 insert guest。初始化后状态的加载和一致性校验记录在
`loading.csv`，不计入 update prover/verifier time；MultiZKOpen、BP/IPA、range proof 和
update verifier 仍完整运行。

benchmark 脚本只加载并验证持久化数据；缺少任一指定规模的 SRS、初始化 fixture 或
delta fixture 都会立即退出，不会在 benchmark 过程中自动生成。默认运行
`3` 个 measured samples 和 `1` 个 warmup。可通过环境变量覆盖，例如：

```bash
SAMPLES=5 WARMUP=1 POA_SP1_PROOF_MODE=groth16 \
  ./scripts/benchmark_protocol.sh
```

### 传统静态 PoA baseline

静态 baseline 使用单个 SP1 guest 验证每个私有账户的规范 Ethereum 地址、非负余额、
ECDSA ownership signature 以及共享 Merkle prefix membership proof，并公开绑定
chain/state root、账户数量、有序账户 commitment 和总余额。它刻意不执行以下动态协议工作：

- 地址根多项式构造和随机点恒等测试；
- KZG accumulator/digest、KZG opening 或 ZKOpen；
- evaluation/balance Pedersen commitment opening；
- update/insert 所需的可更新 prover state。

它使用独立的静态 fixture 入口；不需要 SRS，也不需要
`initialize_benchmark_data.sh` 或 `initialize_smt_benchmark_data.sh`。先生成一次地址、
ECDSA、余额和 Merkle 数据：

```bash
MASTER_N=1000 N_SIZES=1000 \
FIXTURE_DIR=data/mock/bench/generated-static-n1000 \
./scripts/initialize_static_baseline_data.sh
```

然后使用 CUDA 正式测试：

```bash
MASTER_N=1000 N_SIZES=1000 \
FIXTURE_DIR=data/mock/bench/generated-static-n1000 \
SP1_PROVER=cuda POA_SP1_CUDA_DEVICE=0 POA_SP1_PROOF_MODE=compressed \
SAMPLES=3 WARMUP=1 \
OUTPUT_DIR=artifacts/benchmarks/static-cuda-n1000 \
./scripts/benchmark_static_baseline.sh
```

脚本只产生 initialization baseline。Cargo build、fixture 加载、VK setup、CUDA worker
启动和 guest upload 写入 `loading.csv`，不进入 sample；stdin 构造、传输和完整单 guest
proof 计入 prover time。结果格式与 NIZK/SMT benchmark 对齐，包括 `raw.csv`、
`summary.csv`、`summary.md`、`loading.csv` 和 `proof-samples/`。设置
`POA_SP1_PROFILE=1` 后，`guest-metrics.csv` 会分别给出
`ownership_context_hash`、`input_validation_merkle_ownership_and_commitment` 等 cycles。Merkle
prefix 重建和 reserve commitment 已并入账户主扫描，不再额外遍历完整账户向量。

### SP1 Network

SP1 Network client 位于独立 Cargo workspace，避免与主进程 Bulletproofs 的原生 `blst`
冲突。先构建一次 worker：

```bash
./poa sp1-network-build
```

随后在当前 shell 中安全设置 `NETWORK_PRIVATE_KEY`，并选择 Network backend：

```bash
read -s NETWORK_PRIVATE_KEY
export NETWORK_PRIVATE_KEY
export SP1_PROVER=network
```

NIZK initialization：

```bash
MASTER_N=1000 N_SIZES=1000 M_SIZES=100 \
FIXTURE_DIR=data/mock/bench/generated-merkle \
SRS_DIR=params/srs/bench BENCHMARK_OPERATIONS=initialization \
SAMPLES=1 WARMUP=0 POA_SP1_PROOF_MODE=compressed \
OUTPUT_DIR=artifacts/benchmarks/nizk-init-network-n1000 \
./scripts/benchmark_protocol.sh
```

SMT initialization：

```bash
MASTER_N=1000 N_SIZES=1000 M_SIZES=100 SMT_DEPTH=128 \
FIXTURE_DIR=data/mock/bench/generated-merkle \
SMT_OUTPUT_DIR=data/mock/bench/smt-persisted-network/master_n_1000/depth_128 \
POA_SP1_PROOF_MODE=compressed \
./scripts/initialize_smt_benchmark_data.sh
```

所有 Network stdin 都强制使用 private upload。返回 proof 在显式 verifier 阶段由主进程
使用本地可信 VK 验证；这次验证不会混入 prover benchmark。临时请求文件权限、worker
覆盖方式和安全边界见
[`docs/SP1_NETWORK.md`](docs/SP1_NETWORK.md)。

### 本地 CUDA prover

本地 GPU proving 使用独立 worker，因此普通 CPU/macOS 构建不需要 CUDA 依赖。CUDA
设备必须是 Linux x86_64，并能从容器内通过 `nvidia-smi` 访问。先在 GPU 机器构建：

```bash
./poa sp1-cuda-build
```

然后运行 NIZK benchmark：

```bash
SP1_PROVER=cuda POA_SP1_CUDA_DEVICE=0 POA_SP1_PROOF_MODE=compressed \
MASTER_N=1000 N_SIZES=1000 M_SIZES=100 \
FIXTURE_DIR=data/mock/bench/generated-merkle-n1000-m100 \
SRS_DIR=params/srs/bench-n1000-m100 \
BENCHMARK_OPERATIONS=initialization,insert,update \
SAMPLES=3 WARMUP=1 \
OUTPUT_DIR=artifacts/benchmarks/nizk-cuda-n1000-m100 \
./scripts/benchmark_protocol.sh
```

第一次 CUDA setup 会由 SP1 6.2.4 自动下载匹配的
`~/.sp1/bin/sp1-gpu-server`。benchmark 使用一个长驻 worker，每个选中的 guest ELF
只 setup 一次；启动/setup 时间写入 `loading.csv` 和报告的 preparation 表，不进入
sample 的 prover time。项目固定使用带最小启动补丁的 `sp1-cuda` 6.2.4：SDK 仍只启动
并持有一个 GPU server，但会等待同一个子进程最长 60 秒创建 socket；worker 退出时沿用
SDK 的 `kill_on_drop` 自动回收。worker 返回的 proof 在独立 verifier 阶段使用本地可信 VK 验证。
建议先使用 `compressed`：它加速 SP1 core proving 且不需要 Docker；
`groth16/plonk` 的最终 wrapper 仍使用原有本地 Docker/artifact 路径。本集成没有启用
额外的 Icicle `groth16-cuda` wrapper。完整环境要求、设备选择和诊断方式见
[`docs/SP1_CUDA.md`](docs/SP1_CUDA.md)。

### SP1 阶段分析

要分析 initialization 和 insert 的 guest 规模及每阶段耗时，使用独立的 profile 入口。
它会为统一的 `init` 和 `kzg-insert` 各额外执行一次 guest，采集
instructions、SP1 gas、内存地址数、precompile syscall 次数和 guest 内部阶段 cycles，
随后照常生成真实 proof 并记录 host/SP1 wall time。额外 execution probe 会单独报告，
并从普通 benchmark 的 prover time 中扣除：

```bash
MASTER_N=16 N_SIZES=16 M_SIZES=16 \
  OUTPUT_DIR=artifacts/benchmarks/sp1-profile-n16 \
  ./poa profile-sp1
```

默认使用 `compressed`，不需要 Docker/Groth16 artifacts。若需要分析最终 wrapper，可显式
使用 `POA_SP1_PROOF_MODE=groth16`，但仍需满足其 Docker 和内存要求。输出包括：

```text
profile/profile.md              易读阶段汇总
profile/phase-times.csv         host、execute、SP1 prove、verifier wall time
profile/guest-metrics.csv       instructions、gas、syscalls、各 guest 阶段 cycles
profile/sp1-prover-spans.log    SP1 core shard、recursion、shrink/wrap tracing spans
```

guest 内部阶段使用 cycles 而不是墙钟时间，因为 zkVM 内部没有稳定的 wall clock，而且
cycles 才是可跨机器比较的电路工作量。`sp1-prover-spans.log` 中并行 task 的 busy time
可能重叠，不能直接相加当作总 prover time；总 wall time 以 `phase-times.csv` 为准。
profile 模式会增加一次不生成 proof 的 guest execution，因此它是诊断模式；cycle marker
只在这个 execution probe 中启用，真实 proof 中关闭。probe 已从报告中的 benchmark prover
总时间扣除，正式发表总耗时仍应使用不带 `POA_SP1_PROFILE=1` 的普通 benchmark。

KZG ceremony、subgroup 和 power-sequence 检查属于 `setup/import-srs` 参数认证阶段；
`.meta` 文件中的 BLAKE3 digest 绑定认证后的完整 SRS artifact。proof verifier 不重新
审计 SRS，也不会扫描百万个 powers；benchmark 的 verifier time 只包含当前 proof 的验证。

初始化脚本只构建一次最大规模主树并持久化账户、初始化 shared-prefix proof、insert
单路径、delta roots 和初始化后多项式状态；initialization/insert 的 SP1 guest 在证明
过程中验证各自的证明。普通 benchmark 加载不会把百万份私钥、公钥长期保留在内存；
这些字段仍在账户文件中，只有 full fixture validation 才临时读取并校验。
百万规模准备过程本身可能消耗大量内存、磁盘和
时间，但这些时间不会进入 protocol prover/verifier 统计。SRS 会按两个阶段显示进度，
默认使用全部逻辑 CPU；可用 `SRS_THREADS=8 ./scripts/initialize_benchmark_data.sh` 限制
并行度。文件名同时绑定最大 G1 degree 和最大 G2 degree，参数矩阵不变时会
直接复用，不会重新生成。

## 测试

常规工作区测试：

```bash
cargo test --workspace
```

只验证主要模块：

```bash
cargo test -p nizk-fixed-set
cargo test -p eth-sync
cargo test -p smt
cargo test -p poa-cli
```

SP1 proving/setup 依赖本机 SP1 toolchain，耗时和资源占用明显高于普通 Rust 单元测试。

## 当前安全边界

- 内置 SRS 与 Pedersen 基点派生均为开发方案，不是生产 ceremony/CRS；
- mock CSV 初始化使用 mock external proof adapter；
- Ethereum 同步器验证输入一致性并绑定 transition，但数据完整性最终依赖可信的
  execution/state-diff provider 或额外可验证执行证明；
- private state 会落盘，调用方负责加密、访问控制和安全删除；
- 任何协议或序列化格式变更后，都应重新生成 SRS/状态/证明测试产物。

论文对照实现位于 `paper/dpoa_optimized_update.tex`，核心代码分别位于
`crates/nizk/`、`crates/eth-sync/`、`crates/smt/` 与 `crates/sp1-host/`。
