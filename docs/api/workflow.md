# Workflow / Action IR API

## 定位

workflow 现在已经明确拆成两层：

- 编译期
  - `exp -> action IR`
- 执行期
  - `transcript -> runtime / executor`

它不是完整 replay engine，但已经提供了后续 workflow/replay 所需的两类基础设施：

1. 把 exploit 源码稳定转成结构化 action IR
2. 把 transcript 真正跑起来，并把执行结果写回 registry

## 入口

当前公开入口包括：

```python
from chun import (
    ExploitWorkflowCompiler,
    WorkflowExecutor,
    WorkflowJsonCodec,
    ProcessWorkflowRuntime,
    ProcessLauncher,
)

compiler = ExploitWorkflowCompiler()
codec = WorkflowJsonCodec()
executor = WorkflowExecutor(runtime=ProcessWorkflowRuntime())
launcher = ProcessLauncher(binary="./chall")
```

它们不挂在 `session` 上，因为这层处理的是 exploit 源码和高层 replay，而不是单个 session 的固有能力。

## CLI 用法

workflow 现在已经接到 `chun` CLI：

```bash
chun workflow export ./exp.py
chun workflow show ./exp.py
chun workflow run ./exp.workflow.json
```

`workflow run` 在执行完成后，除了打印 `entry_action / total_steps / final_checkpoint`，还会默认追加一段 registry 摘要：

- 默认层级：`context + facts`
- 默认详细度：`standard`
- 默认日志级别：`info`

这里故意不默认展开 `observations` / `artifacts`，因为 workflow 执行期间会产生大量 `workflow.exec.response.*` 和 step receipt，直接全量打印通常噪音过高。当前 CLI 的目标是先让你快速确认：

- 当前 checkpoint 在哪
- 推导出的关键事实是否已经落到 registry
- 这次 replay 是否真的完成了关键分析链

默认导出规则：

- 输入 `./exp.py`
- 默认在同目录生成：
  - `./exp.action_ir.json`
  - `./exp.workflow.json`

如果不指定 `--entry`，`export` 默认会把整份 exp 的顶层块顺序拼成一个模块级 transcript，而不是只导某一个 block。

可选参数：

```bash
chun workflow export ./exp.py --entry menu
chun workflow export ./exp.py --entry exp.menu
chun workflow export ./exp.py --out-dir ./.chun
```

其中：

- `--entry menu`
  - 会自动补成 `exp.menu`
- `--out-dir`
  - 只改变导出目录，不改变文件前缀；文件前缀始终取脚本名 stem

## Action IR

### `compile_source()`

```python
ir = compiler.compile_source(source, module_name="exp")
```

会把源码按 `def` 边界切成：

- `ImportModel`
- `TopLevelBlockDef("exp.__block__.0")`
- `FunctionActionDef("exp.menu")`
- `TopLevelBlockDef("exp.__block__.1")`

### ActionDef 规则

只有两类对象会成为 ActionDef：

- `FunctionActionDef`
- `TopLevelBlockDef`

外部函数不会因为“它是个函数”就自动变成 ActionDef。

例如：

- `menu(1)` 如果 `menu` 是当前模块定义，会变成 `CallNode(callee="exp.menu")`
- `flat(...)`
- `str(...)`
- `s.infer.search_libc(...)`

这些不会变成新的 ActionDef，而是分别降级成：

- `ExprNode`
- `AnalysisNode`
- `OpaqueCallNode`

### Pure 构造器的双保留策略

对于 `flat()`、`p64()`、`bytes()` 这类稳定 pure 构造器，当前 `ExprNode` 会同时保留：

- 表达式结构
- 已求值结果 `resolved_value`

因此后续从 `action IR -> transcript` 时，可以直接消费最终 payload，而不是重新运行一遍构造函数。

## Translator Registry

调用分类通过 `WorkflowTranslatorRegistry` 完成。

当前内置 effect：

- `pure`
- `io_primitive`
- `analysis`
- `expandable_macro`
- `opaque`

当前默认覆盖：

- `str` / `int` / `bytes`
- `flat` / `p8/p16/p32/p64`
- `u8/u16/u32/u64`
- `cyclic`
- `.encode()`
- `send` / `sendline`
- `recv` / `recvuntil`
- `sa` / `sla`
- `infer.search_libc` / `infer.libc_base_from`

未知调用不会崩，而是降级成 `OpaqueCallNode`。

## 递归展开

### `expand_action()`

```python
expanded = compiler.expand_action(ir, "exp.add")
```

递归只发生在两种情况：

1. 调用目标是当前模块内定义的 `FunctionActionDef`
2. 调用命中了已注册的 `expandable_macro`

停止规则：

- 命中调用环：生成 `RecursiveCallNode`
- 超过 `max_expand_depth`：生成 `OpaqueCallNode(truncated=True)`

## 执行期 Transcript

### `build_transcript()`

```python
transcript = compiler.build_transcript(ir, "exp.menu")
```

输出 `WorkflowTranscript`，内部是 runtime 真正消费的 `WorkflowPrimitive` 序列。

现在的 transcript 不再只是“冻结后的 send/recv 字节流”，而是“可执行流程”：

- IO primitive 仍然保留
- 运行期赋值也保留
- 会影响 Registry / 运行期状态的分析调用也保留

当前 primitive 集合是：

- `session_init`
- `send`
- `sendline`
- `expect`
- `recv`
- `assign`
- `call`
- `checkpoint`

这层会把诸如：

- `sla` -> `expect` + `sendline`
- `sa` -> `expect` + `send`

折叠成稳定 transcript。同时：

- `s = CHun.script(...).start()`
  - 会变成 `session_init`，并把 session 重新绑定回原脚本变量名
- `leak = s.recv_leak(...)`
  - 会变成 `assign`
- `s.infer.libc_base_from_symbol_leak(...)`
  - 会变成 `call`

因此 ret2libc 这类“先 leak，再 infer，再 resolve，再 pack”的数据流不会在导出期被错误快照化。

### `build_module_transcript()`

```python
transcript = compiler.build_module_transcript(ir)
```

这个入口更适合 CLI 导出场景。它会按 `ExpActionIR.entrypoints` 的顺序，把整份脚本的顶层 block 展开成一个模块级 transcript。

默认导出的 `*.workflow.json` 走的就是这条路径。

### JSON 导出

```python
WorkflowJsonCodec.dump_action_ir(ir, "./exp.action_ir.json")
WorkflowJsonCodec.dump_transcript(transcript, "./exp.workflow.json")
```

当前建议同时保留两份：

- `*.action_ir.json`
  - 用于分析、审计、后续重新编译 transcript
- `*.workflow.json`
  - 用于直接 replay 执行

`WorkflowJsonCodec.load_transcript(...)` 可以直接把导出的 transcript 读回 `WorkflowTranscript`，再交给 `WorkflowExecutor` 执行。

### 当前 replay 边界

`workflow run` 现在优先回放“流程”，而不是只回放导出期已经求值完成的 payload。

稳定支持的场景包括：

- 字面量 `bytes` / `str`
- `flat()` / `p64()` / `str(...).encode()` 这类在导出期已经能求值的 pure 构造器
- 本地 helper 的简单 `return`，只要最终仍能收敛到可求值的 pure 表达式
- `recv_leak -> infer.* -> resolve.* -> p64/flat/拼接` 这类依赖运行期 Registry / session 状态的 ret2libc 流程
- 依赖脚本变量绑定的表达式，例如 `leak`、`s`、`idx`

执行期现在会维护一份 live env，并把脚本变量重新绑定到 workflow runtime 中：

- `session_init` 会把 `s` 这类脚本变量绑定回 script façade
- `assign` 会把返回值写回 env
- `call` 会按当前 env + session 执行分析/推导步骤
- `send` / `sendline` / `expect` 的 payload 会在真正发送前按 live env 求值

因此像：

- `p64(s.resolve.symbol("system"))`
- `b"a" * 8 + p64(s.resolve.symbol("__free_hook"))`
- `s.infer.libc_base_from_symbol_leak(..., symbol_offset=s.libc.sym["puts"])`

现在都可以延迟到 `workflow run` 时再求值，而不是在 `workflow export` 时就强行冻结。

当前仍然有边界，但已经从“动态 payload 全不支持”收缩成“无法在 runtime façade / 受控 eval 环境里解释的调用仍需显式补 translator 或 façade 能力”。也就是说，问题不再是 ret2libc 的动态地址本身，而是某个具体调用是否已经被纳入 workflow runtime 的语义面。

## Runtime / Executor

执行期主体位于 `src/chun/core/workflow/`：

- [compiler.py](/Users/zaochuan/Documents/code/python/CHun_pwn/src/chun/core/workflow/compiler.py:1)
- [runtime.py](/Users/zaochuan/Documents/code/python/CHun_pwn/src/chun/core/workflow/runtime.py:1)
- [launchers.py](/Users/zaochuan/Documents/code/python/CHun_pwn/src/chun/core/workflow/launchers.py:1)
- [executor.py](/Users/zaochuan/Documents/code/python/CHun_pwn/src/chun/core/workflow/executor.py:1)

当前最小执行接口是：

- `start_session()`
- `execute_primitive(...)`
- `checkpoint(...)`
- `close_session()`

第一版 runtime 是 `ProcessWorkflowRuntime`，launcher 是 `ProcessLauncher`。

对于从 `CHun.script("./fm").start()` 编译出的 `session_init`，当前 transcript 会显式保留：

- `binary`
- `cwd`
- `libc/ld/env/log_level` 等 launcher 参数

如果导出期没有显式写出 `libc=...`，`workflow run` 的 `ProcessLauncher` 还会像脚本态 `CHun.script(...).start()` 一样，尝试从 `ELF(binary).libc` 自动推断并绑定 `session.libc_elf`。这样 `s.libc.sym[...]` 这类脚本态访问在 replay 时仍然成立。

这样 `chun workflow run ./exp.workflow.json` 不必重新解析原始 exp，也能在新的 session 中稳定起本地 process。

`WorkflowExecutor.execute(transcript, launcher=...)` 会：

1. 遍历 transcript
2. 调 runtime
3. 记录 step receipt / 原始 response / transcript / execution result
4. 返回 `WorkflowExecutionResult`

### Registry 回写

当前 workflow 执行会写回：

- transcript -> artifact
- step receipt -> artifact
- 原始响应 -> observation
- 当前 checkpoint -> context

全部使用 `RecordDomain.WORKFLOW`。

## 核心模型

编译期模型定义在：

- [src/chun/core/models/action_ir.py](/Users/zaochuan/Documents/code/python/CHun_pwn/src/chun/core/models/action_ir.py:1)

包括：

- `ImportRef`
- `ImportModel`
- `FunctionActionDef`
- `TopLevelBlockDef`
- `ExpActionIR`
- `AssignNode`
- `CallNode`
- `PrimitiveNode`
- `ExprNode`
- `AnalysisNode`
- `OpaqueCallNode`
- `RecursiveCallNode`

执行期模型定义在：

- [src/chun/core/models/workflow.py](/Users/zaochuan/Documents/code/python/CHun_pwn/src/chun/core/models/workflow.py:1)

包括：

- `WorkflowCheckpoint`
- `WorkflowPrimitive`
- `WorkflowTranscript`
- `WorkflowStepReceipt`
- `WorkflowExecutionResult`

## 当前边界

当前已经完成：

- exploit 文件按 `def` 边界切块
- 基础 AST lowering
- translator registry 初版
- 递归展开与停止条件
- primitive transcript 生成
- pure expr 的“结构 + 已求值结果”双保留
- 本地 process workflow runtime / launcher / executor
- Action IR / WorkflowTranscript 的 JSON 导出与导入
- `chun workflow export/show/run` CLI

当前还没做：

- blind / remote / websocket runtime
- runtime checkpoint 恢复
- 条件分支 / 重试策略
- 更高层 workflow engine
