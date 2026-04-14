# sepolicy-mcp

MCP server for AOSP SELinux denial analysis. Parses dmesg/logcat AVC denials, dedupes, translates to AOSP macros (`binder_call`, `hal_client_domain`, etc.), cross-checks neverallows, and suggests `.te` file placement.

## Why

`audit2allow` is policy-agnostic — it emits raw `allow` rules that often violate AOSP neverallows and ignore idiomatic macros. Debugging denials manually burns ~50K tokens of agent context on log parsing and grep calls. This server does the mechanical work server-side and returns structured suggestions.

## Tools

| Tool | Purpose |
|---|---|
| `parse_denials(log_text)` | Dedupe AVC denials, preserve pid/comm |
| `suggest_fix(scontext, tcontext, tclass, perms, tree)` | AOSP macro + neverallow check + file placement |
| `check_neverallow(...)` | Run `sepolicy-analyze neverallow` against proposed rule |
| `list_trees` | Show configured trees |

## Macros recognized

`binder_call`, `add_service`, `add_hwservice`, `hal_client_domain` (hint), `hwbinder_use`, `net_domain`, `unix_socket_connect`, `file_type_auto_trans`, `set_prop`, `get_prop`, `init_daemon_domain`, `bluetooth_domain`, `r_dir_file`, `rw_dir_file`.

## Neverallow checking

Set `AOSP_OUT_<NAME>=/path/to/out` alongside `AOSP_TREE_<NAME>`. Server finds `sepolicy-analyze` host binary + compiled `root/sepolicy` automatically. Run `m sepolicy sepolicy-analyze` once before use.

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install fastmcp
pytest tests/
```

`.mcp.json`:

```json
{
  "mcpServers": {
    "sepolicy-aosp": {
      "command": "ssh",
      "args": [
        "melchior",
        "AOSP_TREE_A15=/mnt/micron/aosp",
        "AOSP_TREE_A13=/mnt/micron/aosp-a13",
        "AOSP_DEFAULT_TREE=a15",
        "/path/to/venv/bin/python3",
        "/path/to/sepolicy_mcp/server.py"
      ]
    }
  }
}
```

## Status

Scaffold. Implemented: denial parsing, dedupe, binder_call macro. TODO: neverallow shell-out to `sepolicy-analyze`, more macros (`hal_client_domain`, `net_domain`, `file_type_auto_trans`), context-file suggestions.
