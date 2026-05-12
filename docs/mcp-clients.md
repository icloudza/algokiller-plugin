# Cursor and Codex MCP setup

`algokiller-plugin` is packaged first as a Claude plugin, but the runtime
server is a plain stdio MCP server:

```bash
python3 server/algokiller_mcp.py
```

That means Cursor, Codex, and other MCP clients can use the 25 MCP tools
directly. The Claude-only pieces are the slash commands and automatic skill
loading; non-Claude clients should prompt the agent with the workflow notes
below.

## Cursor

This repository includes a project-scoped Cursor config at
`.cursor/mcp.json`. Open this repository in Cursor, then check
**Cursor Settings → Tools & MCP** and enable or refresh the `algokiller`
server.

For a global Cursor install, copy this JSON into `~/.cursor/mcp.json` and
replace the paths with the absolute path to your checkout:

```json
{
  "mcpServers": {
    "algokiller": {
      "type": "stdio",
      "command": "python3",
      "args": [
        "-u",
        "/ABS/PATH/algokiller-plugin/server/algokiller_mcp.py"
      ],
      "env": {
        "ALGOKILLER_PLUGIN_ROOT": "/ABS/PATH/algokiller-plugin",
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

## Codex

Codex reads MCP servers from `~/.codex/config.toml`. Copy
`examples/mcp/codex.config.toml` into that file and replace `/ABS/PATH`
with the absolute path to this checkout:

```toml
[mcp_servers.algokiller]
command = "python3"
args = ["-u", "/ABS/PATH/algokiller-plugin/server/algokiller_mcp.py"]
cwd = "/ABS/PATH/algokiller-plugin"
env = { ALGOKILLER_PLUGIN_ROOT = "/ABS/PATH/algokiller-plugin", PYTHONUNBUFFERED = "1" }
startup_timeout_sec = 30
tool_timeout_sec = 600
```

Restart Codex after editing the config so it can spawn the MCP server and
list tools.

## Verify before using a real trace

Run the MCP smoke test from the repository root:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | python3 server/algokiller_mcp.py
```

Expected result: `initialize` responds and `tools/list` returns 25 tools.

If `bind_trace` fails with `binary not found`, `Permission denied`, or an
architecture error, rebuild the native engine:

```bash
cd tools/search
make
cp ak_search ../../server/bin/ak_search
chmod +x ../../server/bin/ak_search
```

On macOS, if Gatekeeper quarantined the binary:

```bash
xattr -d com.apple.quarantine server/bin/ak_search
```

## Prompting non-Claude clients

Cursor and Codex do not automatically load Claude skills or slash commands.
Use an explicit prompt that names the trace, the mode, and the evidence
discipline:

```text
Use the algokiller MCP tools on /Users/me/captures/login.trace.log.
Mode: ciphertext.
Task: recover how the request signing header is produced.

Start by calling bind_trace, then trace_lint. Use trace_search,
trace_context, trace_bytes, trace_regflow, trace_producer, trace_constscan,
and trace_cryptoinstr as needed. Track high-confidence claims with the
hypothesis ledger and cite concluded hypotheses in the final artifact.
```

For open trace-analysis questions:

```text
Use the algokiller MCP tools on /Users/me/captures/risk.trace.log.
Mode: general.
Task: explain how the x0 value at line 99999 was produced.

Start by calling bind_trace, then gather nearby context and data-flow
evidence before writing a conclusion.
```

## 中文说明

本仓库首先是 Claude 插件，但底层 `server/algokiller_mcp.py` 是标准
stdio MCP server。因此 Cursor / Codex 也可以直接使用 25 个 MCP 工具。

区别是：Cursor / Codex 不会自动获得 Claude 的 slash command 和 skill
自动加载能力。使用时需要在 prompt 里明确要求：

- 先调用 `bind_trace`
- 再调用 `trace_lint`
- 密文/签名还原走 `ciphertext` 模式
- 开放 trace 分析走 `general` 模式
- 高置信推断要走 hypothesis ledger，并在最终交付物里引用 `[H<n>]`

Cursor 项目级配置已经放在 `.cursor/mcp.json`。如果你想全局使用，把上面
的 JSON 复制到 `~/.cursor/mcp.json` 并改成绝对路径。

Codex 使用 `~/.codex/config.toml`。把
`examples/mcp/codex.config.toml` 里的配置复制进去，并把 `/ABS/PATH`
替换成当前仓库的绝对路径。
