# Models 与 Enum

## 覆盖范围

- `TargetSpec`
- `TransportSpec`
- `RecordDomain`
- `ObservationKind`
- `FactKind`
- `ArtifactKind`
- `ContextKind`
- `Observation`
- `Fact`
- `Artifact`
- `ContextEntry`
- `BaseInferenceResult`
- `ResolvedSymbolResult`
- `CrashAnalysisResult`
- `GdbMiResult`
- `LibcLeakConstraint`
- `LibcCandidate`
- `LibcSearchResult`
- `FmtTargetRef`
- `FmtValueRef`
- `FmtOffset`
- `FmtLeak`
- `FmtWriteRequest`
- `FmtWriteAtom`
- `FmtWriteTask`
- `FmtWritePlan`
- `FmtRenderStep`
- `RenderedFmtTask`
- `FmtWriteStrategy`
- `FmtReadMode`
- `FmtTaskPolicy`
- `FmtLayoutPolicy`
- `ImportRef`
- `ImportModel`
- `AssignNode`
- `CallNode`
- `ExprNode`
- `AnalysisNode`
- `OpaqueCallNode`
- `RecursiveCallNode`
- `FunctionActionDef`
- `TopLevelBlockDef`
- `ExpActionIR`
- `WorkflowCheckpoint`
- `WorkflowPrimitive`
- `WorkflowTranscript`
- `WorkflowStepReceipt`
- `WorkflowExecutionResult`

## `TargetSpec`

`TargetSpec` 统一描述“目标是什么”，核心字段包括：

- `kind`
- `binary`
- `host` / `port`
- `base_url`
- `ws_url`
- `argv` / `env` / `cwd`
- `ssh_*`

它的意义是让连接模式不再依赖 `remote_mode: bool`，而是显式落在数据模型里。

## `TransportSpec`

`TransportSpec` 统一描述“这次怎么连”，核心字段包括：

- `kind`
- `timeout`
- `connect_timeout`
- `headers`
- `follow_redirects`
- `verify`
- `delimiter`
- `metadata`

它负责承载 transport 生命周期和协议相关配置。

## 为什么使用 `Enum`

枚举提供稳定可比对的语义集合，避免字符串拼写漂移造成“看起来差不多、实际不一致”的问题。

## Registry 相关枚举

新的 registry 不再围绕“地址记录 / base 记录”工作，而是围绕语义更稳定的几类枚举：

- `RecordDomain`
- `ObservationKind`
- `FactKind`
- `ArtifactKind`
- `ContextKind`

这些枚举继续使用 `str + Enum`，原因是相同的：

- 枚举约束（类型安全）
- 字符串兼容（便于日志、序列化、展示）

其中 `ArtifactKind` 现在包含 `CATALOG_RESULT`，用于保存 `LibcSearchResult` 这类 catalog 检索产物。

## 数据模型如何支撑 Registry 与 Transport

- `TargetSpec`：描述目标
- `TransportSpec`：描述 transport 配置
- `Observation`：记录原始观测
- `Fact`：记录稳定结论
- `Artifact`：记录可复用产物
- `ContextEntry`：记录会话上下文
- `BaseInferenceResult`：承载最小 base inference 闭环结果
- `ResolvedSymbolResult`：承载 DynELF / symbol resolve 结果
- `CrashAnalysisResult`：承载 core dump 分析结果
- `GdbMiResult`：承载结构化 GDB/MI 命令结果

模型层让 Registry 不只是“存值”，而是“存值 + 存上下文 + 存可信度”。

## FMT 共享模型

FMT 的结构化 DTO 现在统一收口在 `src/chun/core/models/fmt.py`，而不是继续挂在插件目录内部。这样做有两个目的：

- `session.fmt`、blind executor、后续 planner / writer 可以共享同一组类型，而不是各自维护私有 dataclass
- 模型层职责更清晰：`plugins/fmt` 负责 service / orchestration，`core/models` 负责稳定数据形状

这些模型会继续通过 `chun.core.models`、`chun.core` 和顶层 `chun` 公开导出，脚本态和插件态都应复用同一套类型入口。

当前这组模型包括：

- `FmtTargetRef`：描述规范化后的目标地址引用，保留原始输入、解析地址、符号来源与元数据
- `FmtValueRef`：描述规范化后的写入值引用，支持字面值或符号值
- `FmtOffset`：描述最终确认后的 offset fact；确认后的值应写回 `fmt.offset`
- `FmtOffsetProbeMode`：描述 offset 探测模式，当前支持 `sequential` 与 `positional_window`
- `FmtOffsetProbeResult`：描述一次 offset 探测 artifact，包含 `method`、`matched_token`、`raw_output`、`tokens`、`window_start/window_end`、`sep`、`confidence`
- `FmtLeak`：描述一次 fmt 读取结果；默认更接近 observation，而不是 fact
- `FmtWriteRequest`：描述用户层原始写入请求
- `FmtWriteAtom`：描述最小独立写单元，新增了 `end_address` 便于 payload/executor 做区间判断
- `FmtWriteTask`：描述一个可独立执行的任务，新增了 `total_atoms`
- `FmtWritePlan`：描述 service 输出的完整计划。当前它表达的是 CHun 的计划对象，而不是自研 atom 优化器本体；会显式记录 `backend`、`offset`、`data_offset`，并额外暴露 `total_atoms`、`total_tasks` 与 `is_blind_safe`
- `FmtWriteCandidate`：描述单个 strategy 下的写入候选，包含 `plan`、`rendered_tasks`、`error` 以及若干便于比较的聚合属性
- `FmtWriteComparison`：描述同一目标/值在多种 strategy 下的对照结果；实现了 `__str__()`，可直接 `print(report)` 得到可读摘要，并支持基于 `buflen/end` 输出 `✅ / ❌ / ❔` 状态
- `FmtWritesComparison`：描述同一批写请求在多种 strategy 下的对照结果，适合多地址写/GOT overwrite 的横向比较
- `FmtRenderStep`：描述单个 atom 在 renderer 阶段的具体决策，包括 padding、arg index、specifier 与计数器推进
- `RenderedFmtTask`：描述 renderer 产出的纯字节任务，显式区分 `fmt_bytes`、`data_bytes` 与最终 `payload`，并保留 `backend`、`layout`、初始/最终计数器
- `FmtExecutionMethod`：描述 executor 最终采用的分发方式，例如 `sendline` 或 `exchange`
- `FmtExecutionReceipt`：描述一次 task 执行回执，包含 `rendered`、`payload`、`response`、`transport_kind` 与 `dispatch`
- `FmtExecutionResult`：描述一次完整写执行的聚合结果，包含 `plan`、`receipts`、`responses`、`task_indexes` 与 `total_tasks`

这组 FMT DTO 现在统一采用 `slots=True, frozen=True`。语义上它们是“可缓存、可对比、可入库”的 IR，而不是 service 内部可随手改写的状态对象。为避免出现“dataclass 冻结了但 metadata 还能被偷偷改”的假不可变状态，`metadata` 也会在构造时被冻结。

配套枚举：

- `FmtWriteStrategy`
- `FmtReadMode`
- `FmtTaskPolicy`
- `FmtLayoutPolicy`
- `FmtResultKind`

以及基础别名：

- `AddressLike`
- `ValueLike`
- `FmtEndian`

当前 write path 的关键语义差异是：

- `FmtOffset`
  - 仍然表示最终确认后的 fmt offset fact
- `FmtWritePlan.offset`
  - 即 `fmt_offset`
  - 表示输入缓冲区首个机器字槽位对应的 positional index
- `FmtWritePlan.data_offset`
  - 表示用户显式覆盖的尾部地址区首槽位
  - 若未显式提供，可以保持为 `None`
- `RenderedFmtTask.data_offset`
  - 表示该 task 最终收敛后的尾部地址区首槽位
- `FmtRenderStep.arg_index`
  - 表示当前 atom 最终命中的 positional index

这让 CHun 可以在保留自己 typed models 的同时，把底层 payload 算法委托给 pwntools，并明确表达：

- `fmt_offset` 是输入缓冲区起始槽位
- `data_offset` 是 append-address 数据区起始槽位
- 两者不再被视为天然相等

## Libc Catalog 模型

新增的 libc catalog DTO 只服务于“版本候选检索”这条链路，不参与现有 `EvidenceRegistry` 的会话内事实存储：

- `LibcLeakConstraint`：描述单条符号泄漏约束，内置 `offset_12bit` 便于直接映射 SQLite 检索键。
- `LibcCandidate`：描述单个 libc 候选，保留 `libc_id` / `name` / `arch` / `build_id` 与匹配结果。
- `LibcSearchResult`：描述一次查询的完整返回，包含约束集合、候选列表、是否存在精确匹配以及查询模式。

这组模型的目标是让未来的 `InferenceService` 只消费结构化对象，而不是直接拼接 SQL。

`BaseInferenceResult` 当前暴露：

- `raw_base`
- `aligned_base`
- `stored_fact`
- `value`

其中 `value` 是 `aligned_base` 的语义化别名，方便脚本里直接继续做地址计算。

## Workflow / Action IR 模型

workflow 相关 DTO 现在拆成了两组。

### 编译期 Action IR

编译期模型统一放在 `src/chun/core/models/action_ir.py`。

这组模型描述 exploit 源码的静态结构：

- `ImportRef` / `ImportModel`
  - 记录 import 区域
- `FunctionActionDef`
  - 当前模块内函数定义对应的 ActionDef
- `TopLevelBlockDef`
  - 定义之间的顶层可执行块
- `ExpActionIR`
  - 整个 exploit 文件的 Action IR 容器
- `AssignNode`
  - 赋值语句
- `CallNode`
  - 指向当前模块内 ActionDef 的调用边
- `PrimitiveNode`
  - 直接 IO 原语或 session 初始化原语
- `ExprNode`
  - 纯值构造调用，例如 `flat()`、`str()`、`int()`
  - 当前会同时保留表达式结构以及可稳定求值时的 `resolved_value` / `value_summary`
- `AnalysisNode`
  - 推断/分析类调用，不作为 replay 必需路径
- `OpaqueCallNode`
  - 当前无法稳定翻译的调用
- `RecursiveCallNode`
  - 递归或循环展开时的停止节点

### 执行期 Workflow

执行期模型统一放在 `src/chun/core/models/workflow.py`。

这组模型是 runtime / executor 真正消费的对象：

- `WorkflowCheckpoint`
  - workflow 执行期检查点
- `WorkflowPrimitive`
  - runtime 真正执行的 primitive；当前第一版支持 `session_init`、`send`、`sendline`、`expect`、`recv`、`assign`、`call`、`checkpoint`
- `WorkflowTranscript`
  - 某个入口块/函数展开后的流程序列；不仅保留 IO primitive，也保留运行期变量绑定与分析调用
- `WorkflowStepReceipt`
  - 单步执行后的结构化回执
- `WorkflowExecutionResult`
  - 一次 transcript 执行的聚合结果

这两层模型现在都支持通过 `WorkflowJsonCodec` 稳定导出成 JSON：

- `ExpActionIR` -> `*.action_ir.json`
- `WorkflowTranscript` -> `*.workflow.json`

这样 workflow 可以把“分析资产”和“执行资产”分开落盘，而不是把 replay 能力绑死在一次 Python 进程里。

这层模型的核心原则是：

- 结构优先于语义猜测
- 只让当前模块内 `def` 成为 ActionDef
- 外部调用统一通过 translator registry 诚实降级

## 为什么要显式带 `domain`

`domain` 用来给未来插件预留能力域，不让所有记录都挤在一个平面命名空间里。

例如：

- `RecordDomain.LIBC`
- `RecordDomain.FMT`
- `RecordDomain.HEAP`
- `RecordDomain.TRANSPORT`
- `RecordDomain.DEBUGGER`
