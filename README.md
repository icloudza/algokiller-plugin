# algokiller-plugin

**语言**：**中文** | [English](README.en.md)

面向 ARM64 trace 证据分析与算法/密文还原的 **Claude Desktop plugin**。把 AlgoKiller 方法论打包为 skill，配本地 MCP server 驱动 native `ak_search` 引擎（14 个 subcommand，专攻 GB 级 trace）。

> **方法论 + ak_search 引擎原作**：[AlgoKiller](https://github.com/lidongyooo/AlgoKiller) by [@lidongyooo](https://github.com/lidongyooo)
> 上游贡献 `match` / `context` / `daemon` 三个核心子命令（mmap + BMH + 行号索引 + tab 协议 daemon）以及原始方法论 harness。
> 本仓库在此之上额外扩展了 11 个 native 子命令（`regflow` / `producer` / `semop` / `lint` / `fold` / `callgraph` / `modgraph` / `hexblock` / `constscan` / `cryptoinstr` / `bytes`，详见 [tools/search/README.md](tools/search/README.md)）并把整套打包为 Claude Desktop plugin。原始代码版权归上游作者；plugin 自身的扩展代码 MIT。

---

## 🚀 快速安装

```bash
claude plugin marketplace add icloudza/algokiller-plugin
claude plugin install algokiller@algokiller-suite
```

更新：

```bash
claude plugin marketplace update
claude plugin update algokiller@algokiller-suite
```

> Claude Code REPL 里也可以用 `/plugin marketplace add ...` / `/plugin install ...` slash 等价命令。手动安装方式见下方 [完整安装说明](#安装)。

**Cursor / Codex**：本仓库也提供标准 stdio MCP server 配置示例。Cursor 可直接使用 `.cursor/mcp.json`；Codex 可复制 `examples/mcp/codex.config.toml` 到 `~/.codex/config.toml`。详见 [Cursor and Codex MCP setup](docs/mcp-clients.md)。注意：非 Claude 客户端只能直接使用 MCP 工具，不会自动获得 Claude slash commands / skill 自动加载。

---

## 能力

1. **Skills**（model-invoked 自动加载）
   - `algokiller:ciphertext-recovery` —— 密文 / header / token 反向还原加密、签名、编码算法
   - `algokiller:trace-analysis` —— 字段语义 / 执行流 / 检测点 / buffer 生命周期等开放问题
2. **Slash commands**（强激活）
   - `/algokiller:ciphertext <trace> <task>`
   - `/algokiller:general <trace> <task>`
3. **26 个 MCP 工具**(19 trace/artifact/static + 7 hypothesis-ledger)
   - 绑定 / 制品：`bind_trace` / `pick_output_dir`（弹原生目录选择器）/ `write_artifact` / `list_artifacts` / `read_artifact`
   - 基础检索：`trace_search` / `trace_context`
   - 数据流：`trace_regflow`（寄存器演化）/ `trace_producer`（找值的最近写入者）/ `trace_semop`（指令语义分类，11 类）
   - 体检与降噪：`trace_lint`（一遍 JSON 体检）/ `trace_fold`（block-aware 折叠，115 MB → 1.1 MB）
   - 调用图：`trace_callgraph`（Top-K / xref）/ `trace_modgraph`（跨模块矩阵）/ `trace_hexblock`（call+args+hexdump+ret 结构化）
   - 密码学指纹：`trace_constscan`（**97 个** hash/cipher/ecc/crc/mac 常数指纹 — 95 个 scalar literal + 2 个 NEON SIMD 广播；含 MD5 init+T 表 / SHA-256 init+K 表 / SM3 init+T_j / SHA-3 / CRC32 / AES sbox+Te0 / SM4 / ChaCha20 / Poly1305 / SipHash / HMAC ipad-opad (scalar + SIMD) / P-256 / secp256k1 / Ed25519 / Curve25519；带 `verdict` 分级 `real` / `real_simd` / `weak` / `alu_only`；MD5.T[i] 等主循环常数附 `block_count_estimate`）/ `trace_cryptoinstr`（ARM Crypto Extensions 硬件指令：AES/SHA-1/SHA-256/SHA-512/SHA-3/SM3/SM4/GHASH）/ `trace_bytes`（hex 字面量含自动反序变体）
   - 静态分析：`run_static_tool` —— 白名单调用系统 CLI（radare2 / binutils / LLVM / jtool2 / class-dump / ripgrep / jq）
4. **反漂移注入**
   - 每次工具返回带 `discipline_reminder`；每 20 次附 `discipline_full_reinjection` 完整规则段
5. **Sub-agents**
   - `hypothesis-reviewer` —— 独立 context 蓝军，`hypothesis_conclude(high)` 之前主 agent 通过 `Agent` 工具 spawn 它做独立证据审查。详见 [docs/agents.md](docs/agents.md)。
6. **大 trace 多线程扫描**
   - `trace_constscan` / `trace_cryptoinstr` 自动按 CPU 数据并行（默认 = 主机核数，封顶 16，可经 `threads` 参数覆盖）。4.5 GB / 48 M 行 trace 上 `constscan` 8 线程 ≈ 19 s（单线程 121 s），输出对所有线程数 byte-identical。

---

## 平台要求

- **macOS**（Apple Silicon / Intel，`bin/ak_search` 按本机架构编译）
- **Python 3.11+**
- **零 Python 外部依赖**（MCP server 用纯标准库讲 JSON-RPC 2.0 over stdio）

二进制架构不匹配时重编：

```bash
cd tools/search && make
cp ak_search ../../server/bin/ak_search
```

---

## 安装

> 一行装机命令见顶部 [🚀 快速安装](#-快速安装)。

**手动安装（备选）**：克隆仓库后在 Claude Desktop → `+` → **Plugins** → **Add plugin** → 选本地目录。

```bash
git clone https://github.com/icloudza/algokiller-plugin
```

装完应能看到 `algokiller` 在 **Plugins** 菜单，`/algokiller:ciphertext` 和 `/algokiller:general` 在 **Slash commands**。

> 如果之前以本地目录方式注册过同名 plugin，marketplace 装新版后用 `claude plugin uninstall <name>@<old-source>` 卸掉老版本，避免双注册。

---

## 如何生成 trace

本 plugin 期待的 trace 格式由配套采集器 **[GumTrace](https://github.com/lidongyooo/GumTrace)** 生成 —— 基于 Frida Gum Stalker 引擎的 ARM64 动态指令追踪工具，作者 [@lidongyooo](https://github.com/lidongyooo)。

| 维度 | 说明 |
|---|---|
| 平台 | Android (ARM64) + iOS (ARM64) |
| 引擎 | Frida Gum Stalker |
| 输出 | `[module] 0xABS!0xREL mnemonic operands; ...` + `call func:` + `ret:` 等 5 类行 |
| 与本 plugin 关系 | **配套工具链**：GumTrace 出 trace → algokiller plugin 分析 trace |

### 端到端工作流

```bash
# 1. 编译 GumTrace（首次）
git clone https://github.com/lidongyooo/GumTrace.git
cd GumTrace
./build_android.sh    # 或 ./build_ios.sh

# 2. 推送到设备并 Frida 注入
adb push build_android/libGumTrace.so /data/local/tmp/
frida -U -f com.example.app -l example.js

# 3. 在 App 里触发要分析的操作（登录 / 发消息 / token 生成等）

# 4. 拉回 trace 文件到 macOS
adb pull /data/data/com.example.app/trace.log ~/captures/login.trace.log

# 5. 喂给本 plugin（在 Claude Desktop 自然语言触发或敲 slash）
#    例如："用 algokiller ciphertext 模式分析 ~/captures/login.trace.log，还原 X-Sign 密文 a3b2c1..."
```

详细 hook 写法见 GumTrace 的 [example.js](https://github.com/lidongyooo/GumTrace/blob/main/example.js) / [example_ios.js](https://github.com/lidongyooo/GumTrace/blob/main/example_ios.js)。

> Frida 原生 trace（`frida-trace` / Stalker 默认 emit）格式不兼容本 plugin —— 必须用 GumTrace 的自定义 emitter。

---

## 使用

**强激活（推荐）**：

```
/algokiller:ciphertext /Users/you/login.trace.log 还原 header X-Sign 中的密文 a3b2c1d4...
/algokiller:general    /Users/you/risk.trace.log  说明第 99999 行 x0 返回值是怎么计算出来的
```

**自由输入**（让 Claude 按 skill description 自动加载）：

> 这里有 ARM64 trace `/path/to/trace.log`，帮我还原生成密文 `a3b2c1...` 的算法。

Slash command 形式更确定，自由输入更自然。

---

## 交付物存放路径

每次 `bind_trace` 自动按 **5 段优先级** 解析输出目录，并把结果通过 response 的 `output_dir_resolved` + `output_dir_source` 两个字段告诉 agent；agent 必须在首次 `write_artifact` 之前把位置告诉用户。

```
① bind_trace(output_dir=...)              ← 显式参数
② $ALGOKILLER_OUTPUT_DIR                  ← env 全局覆盖（CI / 高级用户）
③ <project>/.algokiller.toml [output] dir ← 项目级配置
④ <project>/.algokiller/<trace>/<ts>/     ← trace 路径上溯 4 层找项目标记
                                            (.git / pyproject.toml / Cargo.toml /
                                             package.json / go.mod / Makefile 等)
⑤ <Documents>/AlgoKiller-Reports/<trace>/<ts>/   ← 兜底
   (Linux 优先 XDG_DOCUMENTS_DIR；macOS/Windows 用 ~/Documents)
```

每次 bind 都新建 `<ts>/` 子目录，方便横向对照。

**`pick_output_dir`**：用户想交互式选位置时，agent 调这个工具弹原生选择器——macOS Finder `choose folder`、Windows `FolderBrowserDialog`、Linux `zenity` / `kdialog`；headless / web 客户端返回 `unsupported`，agent 收到 hint 后改走"让用户在对话里说路径"。

**`.algokiller.toml` 项目配置示例**（放在项目根）：

```toml
[output]
dir = "build/algokiller-reports"   # 相对路径相对于项目根；也支持绝对路径
```

`write_artifact("recovered.py", source)` 写 `recovered_CIPHERTEXT_<ts>.py`。不再写 `.notes.md` sidecar——报告本身就承载所有上下文，sidecar 是冗余的 token 开销。

---

## 目录结构

```
algokiller-plugin/
├── .claude-plugin/plugin.json
├── .mcp.json                       # MCP server 声明
├── LICENSE                         # MIT
├── server/                         # JSON-RPC 2.0 MCP server (stdio)
│   ├── algokiller_mcp.py
│   ├── state.py / daemon.py / discipline.py / artifacts.py
│   ├── static_tools.py             # 白名单 CLI runner
│   └── bin/ak_search               # native 搜索引擎 (Mach-O)，**不进 Bash PATH**
├── skills/                         # 所有 skill（含 slash 激活入口和方法论）
│   ├── ciphertext/SKILL.md         # /algokiller:ciphertext 强激活（user-only）
│   ├── general/SKILL.md            # /algokiller:general 强激活（user-only）
│   ├── ciphertext-recovery/SKILL.md  # 完整密文还原方法论（model + user）
│   └── trace-analysis/SKILL.md       # 完整通用 trace 分析方法论（model + user）
└── README.md / README.en.md
```

---

## 本地 smoke test（不进 Claude Desktop）

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | python3 server/algokiller_mcp.py
```

期望：`initialize` 响应 + `tools/list` 返回 26 个工具（19 个 trace/artifact/static 工具 + 7 个 hypothesis-ledger 工具，含 `pick_output_dir` / `mark_hypothesis_reviewed` / `hypothesis_archive`）。

---

## 配合 Binary Ninja MCP（动静结合）

trace 看"发生了什么"，BN 看"代码长什么样"。装任一 BN MCP 自动启用联动：

| Plugin | License | Transport |
|---|---|---|
| [fosdickio/binary_ninja_mcp](https://github.com/fosdickio/binary_ninja_mcp) | GPL-3.0 | stdio |
| [jtang613/BinAssistMCP](https://github.com/jtang613/BinAssistMCP) | MIT | HTTP/SSE |

均为 Binary Ninja plugin，要求本机有 BN 商业 license。SKILL 通过 namespace（`binary_ninja_mcp.*` / `binassist.*`）自动识别，无需配置。BN 不在线时 plugin 仍可单跑——SKILL 不会假装调 BN 工具，且会在交付的"未确认缺口"里建议补做静态分析。

---

## 系统 CLI 工具联动 — `run_static_tool`

白名单受控 shell（argv 模式，无 injection 可能）。用户机器已装的 CLI 装了就有：

| 类别 | 工具 |
|---|---|
| 基础 | `file`、`lipo`、`rax2`、`rg`、`jq`、`c++filt`、`llvm-cxxfilt`、`addr2line` |
| radare2 | `rabin2`、`rasm2`、`r2`（严格边界）|
| binutils | `readelf`、`objdump`、`nm`、`strings` |
| LLVM | `llvm-objdump`、`llvm-nm`、`llvm-readelf`、`llvm-strings` |
| Mach-O / iOS | `otool`、`jtool2`、`class-dump` |

未安装时返回 `hint` 字段告知 brew 命令。

**r2 边界**：必含 `-q -2 -n -c "<single cmd>"`；禁 `-A` / `aaa` / `aac` 等完整分析命令。

**优先级**：`binary_ninja_mcp.*` 在线 > `run_static_tool` > trace-only。

---

## 故障排查

### Plugin 装上但工具不可见

最常见原因：`${CLAUDE_PLUGIN_ROOT}` 未被这版 Desktop 展开。手动改安装后的 `.mcp.json` 为绝对路径：

```json
{
  "mcpServers": {
    "algokiller": {
      "command": "python3",
      "args": ["-u", "/ABS/PATH/server/algokiller_mcp.py"],
      "cwd": "/ABS/PATH",
      "env": {
        "ALGOKILLER_PLUGIN_ROOT": "/ABS/PATH",
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

查 Claude Desktop MCP server 日志，找 `[algokiller-mcp]` 开头的 stderr 行定位。

### `bind_trace` 报 binary not found / Permission denied

plugin 启动时自动 `chmod +x` + `xattr -d com.apple.quarantine`。失败时手动：

```bash
chmod +x server/bin/ak_search
xattr -d com.apple.quarantine server/bin/ak_search
file server/bin/ak_search   # 应为 Mach-O 64-bit executable arm64
```

架构不匹配时重编：`cd tools/search && make && cp ak_search ../../server/bin/`。

### `bind_trace` 在 GB trace 上看似卡住

`ak_search` 首次建索引，5GB 约 30-60s。`pgrep -lf ak_search` 看到进程 CPU 满载即正常。索引完成后所有调用毫秒级。

### artifacts 累积

```bash
ls -dt ~/AlgoKiller/artifacts/*/*/ | tail -n +11 | xargs rm -rf
```

### daemon 残留

plugin 已注册 `atexit` + SIGTERM/SIGINT cleanup。Desktop 强杀时偶发残留：

```bash
pkill -f "ak_search daemon"
```

daemon 无状态，下次 `bind_trace` 自动重启。
