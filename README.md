# Dynamic Private Proof of Assets

Rust 原型，实现论文中的动态隐私资产证明流程。当前仓库包含两条路径：

- `nizk-fixed-set`：基于集合多项式、KZG、Pedersen commitment、ZKOpen、
  HPolyCom/HZKOpen 和 Bulletproofs 的固定集合 NIZK；
- `smt` + `sp1-host`：Sparse Merkle Tree 与 SP1 guest/host 的更新和插入路径；
- `eth-sync`：把执行完成且已最终确认的 Ethereum state diff 转换为协议需要的
  地址向量和余额变化向量。

本仓库目前是研究原型，不应直接用于托管真实资产或生产证明。

## 快速开始

要求 Rust stable。所有命令都从仓库根目录运行。

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
│   ├── srs/                   KZG SRS，包括 HPolyCom hiding powers
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
├── paper/                     协议论文（本地目录）
└── vendor/                    本地 patched dependency
```

`data/mock/generated/`、`data/mock/bench/`、`params/srs/*.bin` 和
`artifacts/` 下的运行产物默认不进入 Git。`artifacts/states/` 中的 prover
state 含余额和 blinding，应按敏感数据处理。

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

1. `params/srs/` 保存 KZG powers-of-tau。当前 SRS 同时包含普通 G1/G2 powers
   与 HPolyCom 使用的独立 hiding G1 powers。
2. `params/crs/` 保存 Pedersen commitment 和 Sigma ZKOpen 所用透明 CRS 的派生约定。
   基点使用标准 BLS12-381 G1 `XMD:SHA-256_SSWU_RO` hash-to-curve、独立 domain
   label 和 index 派生，不再使用已知离散对数的 `hash_to_scalar * G`。
3. `params/sp1/` 保存 SP1 guest 对应的 setup/verifying-key 缓存。它们不是 KZG
   参数，也不是 Pedersen CRS。

`./poa setup [degree]` 只生成默认开发 KZG SRS。SP1 setup 较慢，按需单独执行：

```bash
./poa sp1-setup
```

默认位置是 `params/sp1/`。开发 SRS 由确定性 seed 生成，不代表可信仪式，并会被
生产验证器拒绝。生产 SRS 必须由外部 ceremony 生成并导入：

```bash
./poa import-srs ceremony.srs.bin <ceremony-id>
```

导入器使用 subgroup-checked 反序列化，并用批量 pairing 关系检查普通 G1/G2 powers
和 HPolyCom hiding powers；导入后在 SRS 旁写入 provenance `.meta` 文件。

`setup` **不会生成单独的 Pedersen CRS 文件**。Pedersen CRS 是透明 CRS：验证者
按照 `params/crs/domains.json` 记录的 suite、DST、label 和 index 重新 hash-to-curve。
它不需要秘密或可信仪式；KZG SRS 仍然需要外部 powers-of-tau ceremony，两者不能混用。

本次 CRS 升级与旧的 `hash_to_scalar * G` 基点不兼容。旧 state 中的 balance
commitment、旧 initialization/update/insert proof 都必须从 initialization 开始重新生成；
不能在旧 state 上继续 update。初始化 scheme 已升级为
`kzg-nizk-init-v5-zkopen-h2c-crs-mock-bound`，insert scheme 为
`kzg-nizk-insert-v5-hpoly-bounded-range-mock-bound`。修改过 SP1 guest 后也必须重新运行 `./poa sp1-setup`；
loader 会比较 artifact 中记录的 ELF digest，旧 artifact 会 fail-closed 并提示重新 setup。
本轮只修改代码、未重新生成 SP1 artifact，因此首次运行前必须执行一次该命令。

SRS 文件格式已经扩展：旧格式为 `G1 powers + G2 powers`，新格式在末尾追加
HPolyCom 的 hiding G1 powers。读取器仍能读取旧格式，因此普通 KZG 初始化/更新
不一定立即失效；但依赖 HPolyCom/HZKOpen 的 insert 必须使用新格式。`./poa setup`
会检查默认 `params/srs/dev.srs.bin`，发现旧格式时自动按原 degree 重新生成完整 SRS。
只要实际替换了 SRS，最安全的做法仍是重新生成依赖它的 state 和 proof。

底层 `gen-srs` 只生成明确标记的开发 SRS：

```bash
./poa gen-srs 10000 params/srs/custom-10000.bin
```

## 初始化、ZKOpen 与 HPolyCom

初始化会生成 private prover state、public state companion 和 init proof。当前
初始化的 KZG evaluation 使用 Fiat–Shamir 非交互化的 Sigma ZKOpen，因此不会
把 evaluation 和 Pedersen blinding 直接写入 proof。

insert 路径对旧/新 accumulator evaluation 使用 ZKOpen；商多项式使用
HPolyCom 与 HZKOpen。HPolyCom 通过隐藏多项式对多项式 commitment 本身做隐藏，
它依赖 KZG SRS 中单独的 hiding powers。

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
transcript，私钥所有权、地址派生以及 Ethereum account MPT balance proof 都在
SP1 guest 内验证；它不会把 host-side 标签误当成链证明本身。

## Range proof 与阈值证明

余额 range proof 使用与余额 commitment 相同的 Pedersen 基点。每个下界或上界
证明用两个 64-bit limb 组成一个 128-bit Bulletproof，并检查
`C_lo + 2^64 C_hi = C`。系统同时证明 `value >= 0` 与
`i128::MAX - value >= 0`，因此接受区间严格为 `[0, i128::MAX]`，同时不公开余额、
slack 或 blinding。

每个固定集合 update proof 都内嵌新总余额的非负 range proof；验证器还限制每个
公开 delta 以及全部公开 delta 的绝对值之和。这两部分共同排除有限域模数回绕。
update proof 的持久化格式因此升级为 `DPOAUPD5`：旧 update proof 必须重新生成，
KZG SRS 不需要因此重建。

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

完整协议矩阵由 `scripts/benchmark_protocol.sh` 运行。其 initialization fixture 在
SP1 外生成：确定性的有效 secp256k1 私钥、未压缩公钥、由 Keccak 派生的 Ethereum
地址、随机化余额、EIP-6800 basic-data leaves，以及一棵 256 叉 Banderwagon Verkle
tree。前 `n` 个账户作为初始化储备，第 `n+1` 个账户只存在于同一个 Ethereum state
中，供 insert benchmark 使用。SP1 内实际执行私钥到地址验证、EIP-6800 tree-key 与
basic-data 编码检查、Banderwagon commitment 解析和 IPA opening 验证，不再使用
`mock-private-key:<address>` / `mock-balance-proof:<address>` 标签。fixture 生成、磁盘
加载和密钥一致性检查单独记录，不计入 prover/verifier time。

初始化不会把同一份证明复制 `n` 次：每个账户有独立的 key/value opening，密码学上
按 Verkle witness 的标准方式聚合为一份 multiproof，并在 SP1 guest 中验证一次。
Insert 使用同一 state root 下的单账户 Verkle proof。Update fixture 对随机 delta 应用
新余额后重新构建 Verkle tree，以真实的新 root 作为协议输入；Sync/finality 证明仍按
论文中的独立抽象处理，不计入 debug update verifier。

该后端固定使用 `crate-crypto/rust-verkle` commit
`e27b8b4edf1992b4afa636c2fc7983bcc27ddb88`，其 Pedersen basis、31-byte stem/1-byte
suffix、leaf splitting 和 IPA transcript 与 EIP-6800 参考实现一致。它属于研究型
benchmark 依赖，不应被描述为当前 Ethereum 主网共识状态树实现。

完整 benchmark 必须分两阶段执行。先初始化并持久化最大到 `10^6` 个账户的数据：

```bash
./scripts/initialize_benchmark_data.sh
```

默认会准备以下矩阵：

- `n = 10^4, 10^5, 10^6`：每个规模都有独立的 `n+1` 账户 Verkle tree、初始化
  multiproof 和 insert proof；
- `m = 10^2, 10^3`：每个 `n` 先确定性生成最大 `10^3` 个互不重复的随机更新，
  `10^2` 是同一更新序列的前缀；两种规模分别持久化 canonical delta list 及其重建后
  的新 Verkle root；
- 对应的 development benchmark SRS。

文件默认持久化在：

```text
data/mock/bench/generated/
  preparation-manifest.txt
  n_10000/ethereum-eip6800-verkle-v2/
  n_100000/ethereum-eip6800-verkle-v2/
  n_1000000/ethereum-eip6800-verkle-v2/

params/srs/bench/
```

准备完成后再运行：

```bash
./scripts/benchmark_protocol.sh
```

benchmark 脚本只加载并验证持久化数据；缺少任一指定规模的 SRS、初始化 fixture 或
delta fixture 都会立即退出，不会在 benchmark 过程中自动生成。默认运行
`3` 个 measured samples 和 `1` 个 warmup。可通过环境变量覆盖，例如：

```bash
SAMPLES=5 WARMUP=1 POA_SP1_PROOF_MODE=groth16 \
  ./scripts/benchmark_protocol.sh
```

初始化脚本会在宿主侧验证账户、公私钥、basic-data、初始化 multiproof、insert proof、
delta 的旧 root 和重建后的新 root；initialization/insert 的 SP1 guest 随后还会在证明
过程中再次验证对应的 Verkle opening。百万规模准备过程本身可能消耗大量内存、磁盘和
时间，但这些时间不会进入 protocol prover/verifier 统计。

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
