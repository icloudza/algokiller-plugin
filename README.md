# algokiller-plugin

**语言**：**中文** | [English](README.en.md)

面向 ARM64 trace 证据分析与算法/密文还原的 **Claude Desktop plugin**。把 AlgoKiller 方法论打包为 skill，配本地 MCP server 驱动 native `ak_search` 引擎，专攻 GB 级 trace。

---

## 能力

1. **Skills**（model-invoked 自动加载）
   - `algokiller:ciphertext-recovery` —— 密文 / header / token 反向还原加密、签名、编码算法
   - `algokiller:trace-analysis` —— 字段语义 / 执行流 / 检测点 / buffer 生命周期等开放问题
2. **Slash commands**（强激活）
   - `/algokiller:ciphertext <trace> <task>`
   - `/algokiller:general <trace> <task>`
3. **7 个 MCP 工具**
   - `bind_trace` / `trace_search` / `trace_context` / `write_artifact` / `list_artifacts` / `read_artifact`
   - `run_static_tool` —— 白名单调用系统 CLI（radare2 / binutils / LLVM / jtool2 / class-dump / ripgrep / jq）
4. **反漂移注入**
   - 每次工具返回带 `discipline_reminder`；每 20 次附 `discipline_full_reinjection` 完整规则段

---

## 平台要求

- **macOS**（Apple Silicon / Intel，`bin/ak_search` 按本机架构编译）
- **Python 3.11+**
- **零 Python 外部依赖**（MCP server 用纯标准库讲 JSON-RPC 2.0 over stdio）

二进制架构不匹配时重编：

```bash
cd <AlgoKiller>/tools/search && make
cp ak_search <plugin>/server/bin/ak_search
```

---

## 安装

**方式 1（推荐）**：Claude Desktop → `+` → **Plugins** → **Add plugin** → 选目录或 zip。

**方式 2**：

```bash
zip -r algokiller-plugin.zip algokiller-plugin -x '*.pyc' '__pycache__/*'
# 上传到 Plugins → Add plugin → Upload a file
```

装完应能看到 `algokiller` 在 **Plugins** 菜单，`/algokiller:ciphertext` 和 `/algokiller:general` 在 **Slash commands**。

---

## 如何生成 trace

本 plugin 期待的 trace 格式由配套采集器 **[GumTrace](https://github.com/lidongyooo/GumTrace)** 生成 —— 基于 Frida Gum Stalker 引擎的 ARM64 动态指令追踪工具（334⭐，作者 [@lidongyooo](https://github.com/lidongyooo)）。

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

## 交付物

每次 `bind_trace` 创建新会话目录：

```
~/AlgoKiller/artifacts/<trace_basename>/<YYYYMMDD_HHMMSS>/
```

`write_artifact("recovered.py", source)` 写 `recovered_CIPHERTEXT_<ts>.py`；带 notes 时同时写 `*.notes.md`。

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

期望：`initialize` 响应 + `tools/list` 返回 7 个工具。

---

## 设计取舍

薄壳变体 —— Claude Desktop 当 agent，plugin 只贡献：

- native `ak_search` 引擎（GB 级 mmap + 行号索引 + ASCII case-insensitive + daemon）
- `trace_search` 的 0x hex 字节反序 / 剥前导零 fallback
- 方法论：从原 harness 移植 + 补强 VMP / OLLVM / 白盒密码 / 国密 / AEAD / setoken / 反调试
- 每工具返回的纪律重注入（替代原 `system_reinjection_interval` loop）

**不带过来**：原 agent loop / note-compactor / ask-user reviewer / session 持久化 / LiteLLM 配置。

---

## 配合 Binary Ninja MCP（动静结合）

trace 看"发生了什么"，BN 看"代码长什么样"。装任一 BN MCP 自动启用联动：

| Plugin | License | Transport |
|---|---|---|
| [fosdickio/binary_ninja_mcp](https://github.com/fosdickio/binary_ninja_mcp) (348⭐) | GPL-3.0 | stdio |
| [jtang613/BinAssistMCP](https://github.com/jtang613/BinAssistMCP) (33⭐) | MIT | HTTP/SSE |

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

架构不匹配时重编：`cd <AlgoKiller>/tools/search && make && cp ak_search <plugin>/bin/`。

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
