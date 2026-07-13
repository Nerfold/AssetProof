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
./poa check-update \
  artifacts/states/init-state.txt \
  data/mock/deltas.csv \
  artifacts/states/init-state-next.txt \
  artifacts/proofs/init-state-update-proof.txt
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
2. `params/crs/` 保存 Pedersen commitment 和 Sigma ZKOpen 所用基点的派生约定。
   当前实现仍通过代码中的 domain-separated label 确定性派生，这仅适合原型；
   生产版本必须换成离散对数关系未知、经过审计的独立基点。
3. `params/sp1/` 保存 SP1 guest 对应的 setup/verifying-key 缓存。它们不是 KZG
   参数，也不是 Pedersen CRS。

`./poa setup [degree]` 只生成默认开发 KZG SRS。SP1 setup 较慢，按需单独执行：

```bash
./poa sp1-setup
```

默认位置是 `params/sp1/`。开发 SRS 由确定性 seed 生成，不代表可信仪式；生产
环境应替换为经过验证的 ceremony 输出并单独记录来源和 digest。

目前 `setup` **不会生成单独的 Pedersen CRS 文件**。Pedersen 和 ZKOpen 的基点
仍由代码按照 `params/crs/domains.json` 中的 label 确定性派生；该目录现在保存的
是派生约定，不是二进制 CRS。因为当前开发派生方式不能提供生产环境要求的未知
离散对数关系，它只能用于原型。生产化时应改为独立生成/导入并校验 Pedersen CRS。

SRS 文件格式已经扩展：旧格式为 `G1 powers + G2 powers`，新格式在末尾追加
HPolyCom 的 hiding G1 powers。读取器仍能读取旧格式，因此普通 KZG 初始化/更新
不一定立即失效；但依赖 HPolyCom/HZKOpen 的 insert 必须使用新格式。`./poa setup`
会检查默认 `params/srs/dev.srs.bin`，发现旧格式时自动按原 degree 重新生成完整 SRS。
只要实际替换了 SRS，最安全的做法仍是重新生成依赖它的 state 和 proof。

自定义 SRS 仍可用底层命令生成：

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

## 高层命令

```text
./poa setup [max-degree]
./poa mock-data [accounts reserves blocks txs-per-block seed]
./poa eth-sync <transition.json> [deltas.csv sync-output.json]
./poa prove-init <state-root> [reserves.csv]
./poa prove-update <state.txt> <deltas.csv> <new-state-root>
./poa check-update <old-state.txt> <deltas.csv> <new-state.txt> <proof.txt>
```

`check-update` 是当前原型产物的本地 debug verifier；它不会把 mock external
adapter 提升为真实链信任来源。生产 verifier 仍要求完整的 committed-opening 与
真实 external/sync proof。

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

old/new public state + deltas.csv + proof + SRS
  └─> check-update / production verifier
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
