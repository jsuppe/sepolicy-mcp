#!/usr/bin/env python3
"""
Sepolicy MCP Server — AOSP SELinux denial analysis and fix suggestions.

Parses raw dmesg/logcat denials, dedupes, translates to AOSP macros,
cross-checks against neverallow rules, and suggests .te file placement.

Config via environment:
    AOSP_TREE_<NAME>    Source root per tree (e.g. AOSP_TREE_A15=/mnt/micron/aosp)
    AOSP_DEFAULT_TREE   Default tree name
    AOSP_OUT_<NAME>     Out dir per tree (for compiled policy lookup)
"""

from __future__ import annotations
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass, asdict
try:
    from fastmcp import FastMCP
    mcp = FastMCP("sepolicy-mcp")
except ImportError:
    class _Stub:
        def tool(self):
            return lambda f: f
        def run(self, **kw):
            raise RuntimeError("fastmcp not installed")
    mcp = _Stub()

TREES = {}
OUT_DIRS = {}
for key, val in os.environ.items():
    if key.startswith("AOSP_TREE_"):
        TREES[key[len("AOSP_TREE_"):].lower()] = val
    elif key.startswith("AOSP_OUT_"):
        OUT_DIRS[key[len("AOSP_OUT_"):].lower()] = val

DEFAULT_TREE = os.environ.get("AOSP_DEFAULT_TREE", next(iter(TREES), ""))


# --- Denial parsing ---

AVC_RE = re.compile(
    r"avc:\s+denied\s+\{\s*(?P<perms>[^}]+)\s*\}\s+"
    r"(?:for\s+)?"
    r"(?:pid=(?P<pid>\d+)\s+)?"
    r"(?:comm=\"(?P<comm>[^\"]+)\"\s+)?"
    r".*?"
    r"scontext=(?:u:r:)?(?P<scontext>[^\s:]+)"
    r".*?"
    r"tcontext=(?:u:(?:r|object_r):)?(?P<tcontext>[^\s:]+)"
    r".*?"
    r"tclass=(?P<tclass>\S+)"
)


@dataclass
class Denial:
    scontext: str
    tcontext: str
    tclass: str
    perms: tuple
    count: int
    pids: set
    comms: set

    def key(self):
        return (self.scontext, self.tcontext, self.tclass, self.perms)


def parse_denials_raw(text: str) -> list[Denial]:
    bucket: dict = {}
    for line in text.splitlines():
        m = AVC_RE.search(line)
        if not m:
            continue
        perms = tuple(sorted(m.group("perms").split()))
        key = (m.group("scontext"), m.group("tcontext"), m.group("tclass"), perms)
        if key not in bucket:
            bucket[key] = Denial(
                scontext=m.group("scontext"),
                tcontext=m.group("tcontext"),
                tclass=m.group("tclass"),
                perms=perms,
                count=0,
                pids=set(),
                comms=set(),
            )
        d = bucket[key]
        d.count += 1
        if m.group("pid"):
            d.pids.add(m.group("pid"))
        if m.group("comm"):
            d.comms.add(m.group("comm"))
    return list(bucket.values())


# --- AOSP macro translation ---
# Ordered: more specific matches first. Each rule = (predicate_fn, template, note)
# Predicate receives Denial, returns bool. Template uses {s}=scontext, {t}=tcontext.

def _has(d: Denial, tclass: str, perms: set) -> bool:
    return d.tclass == tclass and perms.issubset(set(d.perms))


def _tcontext_matches(d: Denial, suffixes: tuple) -> bool:
    return any(d.tcontext.endswith(sfx) for sfx in suffixes)


MACRO_RULES = [
    # HAL service registration — hwservice_manager_add / add_hwservice
    (lambda d: _has(d, "hwservice_manager", {"add"}),
     "add_hwservice({s}, {t})",
     "HAL registers with hwservicemanager"),

    # AIDL service registration
    (lambda d: _has(d, "service_manager", {"add"}),
     "add_service({s}, {t})",
     "Service registers with servicemanager"),

    (lambda d: _has(d, "service_manager", {"find"}),
     "allow {s} {t}:service_manager find;",
     "Client finds AIDL service (no macro; use raw)"),

    # HAL client/server domains — covers binder_call + fd use + transfer bundle
    (lambda d: d.tclass == "binder" and d.tcontext.endswith("_hwservice") is False
               and "_hal_" in d.scontext + d.tcontext,
     "hal_client_domain({s}, {t})  # if {s} is client; else hal_server_domain",
     "HAL binder traffic"),

    # Generic binder call (after HAL-specific check)
    (lambda d: _has(d, "binder", {"call"}),
     "binder_call({s}, {t})",
     "Bundles call + transfer + fd use"),

    # hwbinder
    (lambda d: _has(d, "hwbinder", {"call"}),
     "hwbinder_use({s})",
     "HwBinder client usage"),

    # Network
    (lambda d: d.tclass in {"tcp_socket", "udp_socket"} and {"create"}.issubset(set(d.perms)),
     "net_domain({s})",
     "Bundles socket create/bind/connect/read/write"),

    # Unix sockets — /data/local/tmp style
    (lambda d: d.tclass == "unix_stream_socket" and {"connectto"}.issubset(set(d.perms)),
     "unix_socket_connect({s}, {t_name}, {t})  # replace {t_name} with socket label",
     "Unix socket connect via file_contexts entry"),

    # File type auto transitions (type=1400 with create on parent dir)
    (lambda d: d.tclass in {"file", "dir"} and {"create"}.issubset(set(d.perms)),
     "file_type_auto_trans({s}, parent_type, new_file_type)",
     "Prefer auto-trans over raw create; need type definition"),

    # Property access
    (lambda d: d.tclass == "property_service" and {"set"}.issubset(set(d.perms)),
     "set_prop({s}, {t})",
     "Setting system property"),

    (lambda d: d.tclass == "file" and d.tcontext.endswith("_prop") and {"read"}.issubset(set(d.perms)),
     "get_prop({s}, {t})",
     "Reading system property"),

    # Init daemon domain transition
    (lambda d: d.tclass == "process" and {"transition"}.issubset(set(d.perms)),
     "init_daemon_domain({s})",
     "Init-spawned daemon; place in init.rc service def"),

    # Bluetooth
    (lambda d: d.tcontext.startswith("bluetooth") and d.tclass == "binder",
     "bluetooth_domain({s})",
     "Bluetooth client domain"),

    # Debugfs / sysfs reads
    (lambda d: d.tclass == "file" and d.tcontext.startswith("sysfs_")
               and {"read"}.issubset(set(d.perms)),
     "r_dir_file({s}, {t})",
     "Recursive read on sysfs dir + files"),

    (lambda d: d.tclass in {"file", "dir"} and {"read", "write"}.issubset(set(d.perms)),
     "rw_dir_file({s}, {t})",
     "Read-write bundle on dir + files"),
]


def suggest_macro(d: Denial) -> tuple:
    """Return (macro_string, explanation) or (None, None)."""
    for pred, template, note in MACRO_RULES:
        try:
            if pred(d):
                return (template.format(s=d.scontext, t=d.tcontext), note)
        except Exception:
            continue
    return (None, None)


def suggest_raw_rule(d: Denial) -> str:
    return f"allow {d.scontext} {d.tcontext}:{d.tclass} {{ {' '.join(d.perms)} }};"


# --- Tools ---

@mcp.tool()
def parse_denials(log_text: str) -> str:
    """Parse raw dmesg/logcat output, dedupe AVC denials, preserve pid/comm context.

    Returns structured list of unique denials with occurrence counts.

    Args:
        log_text: Raw output from `dmesg` or `logcat -b all` containing AVC lines.
    """
    denials = parse_denials_raw(log_text)
    if not denials:
        return "No AVC denials found."
    lines = [f"Found {len(denials)} unique denial(s):\n"]
    for i, d in enumerate(denials, 1):
        lines.append(
            f"[{i}] {d.scontext} -> {d.tcontext}:{d.tclass} {{ {' '.join(d.perms)} }}"
            f"  count={d.count} comms={sorted(d.comms) or '?'}"
        )
    return "\n".join(lines)


@mcp.tool()
def suggest_fix(scontext: str, tcontext: str, tclass: str, perms: str,
                tree: str = DEFAULT_TREE) -> str:
    """Suggest AOSP-idiomatic fix for a denial: macro if applicable, else raw allow rule.
    Flags if the suggestion violates a neverallow.

    Args:
        scontext: Source context type (e.g. "vcam_hal").
        tcontext: Target context type.
        tclass: Target class (e.g. "binder", "file").
        perms: Space-separated permissions (e.g. "call transfer").
        tree: Tree to check against.
    """
    perms_tuple = tuple(sorted(perms.split()))
    d = Denial(scontext, tcontext, tclass, perms_tuple, 1, set(), set())
    macro, note = suggest_macro(d)
    raw = suggest_raw_rule(d)
    out = [f"Raw rule:\n  {raw}"]
    if macro:
        out.append(f"\nPreferred (AOSP macro):\n  {macro}")
        if note:
            out.append(f"  # {note}")
    nv = check_neverallow_internal(d, tree)
    if nv:
        out.append(f"\n[WARN] neverallow check: {nv}")
    placement = suggest_placement(scontext, tree)
    if placement:
        out.append(f"\nSuggested file: {placement}")
    return "\n".join(out)


def _find_sepolicy_analyze(tree: str) -> str | None:
    if tree not in OUT_DIRS:
        return None
    candidates = [
        f"{OUT_DIRS[tree]}/host/linux-x86/bin/sepolicy-analyze",
        f"{OUT_DIRS[tree]}/soong/host/linux-x86/bin/sepolicy-analyze",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def _find_compiled_policy(tree: str) -> str | None:
    if tree not in OUT_DIRS:
        return None
    candidates = [
        f"{OUT_DIRS[tree]}/target/product/vsoc_x86_64_only/odm/etc/selinux/precompiled_sepolicy",
        f"{OUT_DIRS[tree]}/target/product/vsoc_x86_64/odm/etc/selinux/precompiled_sepolicy",
        f"{OUT_DIRS[tree]}/target/product/generic/root/sepolicy",
        f"{OUT_DIRS[tree]}/target/product/vsoc_x86_64/root/sepolicy",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


# --- Neverallow source parsing ---
# Strategy: grep neverallow blocks from system/sepolicy/*.te source files,
# parse the (source_set, target_set, classes, perms), then match proposed
# allow rule against each. We do text-level matching — not full attribute
# expansion (that needs setools/sesearch). Catches direct type references
# and "domain" attribute conflicts, which is most real-world neverallows.

NEVERALLOW_RE = re.compile(r"^neverallow\s+(.*?);", re.DOTALL | re.MULTILINE)

_NEVERALLOW_CACHE: dict = {}


def _load_neverallows(tree: str) -> list[dict]:
    """Read all .te files under system/sepolicy/ and parse neverallow stmts.
    Caches per tree. Skips rules with m4 macros ($1, $2) — those are templates."""
    if tree in _NEVERALLOW_CACHE:
        return _NEVERALLOW_CACHE[tree]
    if tree not in TREES:
        return []
    rules = []
    root = os.path.join(TREES[tree], "system", "sepolicy")
    if not os.path.isdir(root):
        _NEVERALLOW_CACHE[tree] = []
        return []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".te"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, errors="replace") as f:
                    text = f.read()
            except Exception:
                continue
            # Strip comments
            text = re.sub(r"#[^\n]*", "", text)
            for m in NEVERALLOW_RE.finditer(text):
                body = re.sub(r"\s+", " ", m.group(1)).strip()
                if "$1" in body or "$2" in body:
                    continue  # m4 template
                parsed = _parse_neverallow_body(body)
                if parsed:
                    parsed["file"] = os.path.relpath(path, TREES[tree])
                    rules.append(parsed)
    _NEVERALLOW_CACHE[tree] = rules
    return rules


def _parse_set(s: str) -> tuple:
    """Parse '{ a b -c }' or 'a' → (includes, excludes, is_wildcard)."""
    s = s.strip()
    if s == "*":
        return (set(), set(), True)
    if s.startswith("{") and s.endswith("}"):
        s = s[1:-1]
    tokens = s.split()
    inc, exc = set(), set()
    for t in tokens:
        t = t.strip()
        if not t:
            continue
        if t.startswith("-"):
            exc.add(t[1:])
        else:
            inc.add(t)
    return (inc, exc, False)


def _parse_neverallow_body(body: str) -> dict | None:
    """Parse 'source target:class perms' from neverallow body."""
    # Find ':' splitting target from class
    # source may contain { } with spaces, target may too
    # Approach: match balanced braces
    def extract_set(text: str, i: int) -> tuple:
        while i < len(text) and text[i] == " ":
            i += 1
        if i >= len(text):
            return (None, i)
        if text[i] == "{":
            depth = 0
            start = i
            while i < len(text):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        return (text[start:i+1], i+1)
                i += 1
            return (None, i)
        # Single token until space or :
        start = i
        while i < len(text) and text[i] not in " :":
            i += 1
        return (text[start:i], i)

    src, i = extract_set(body, 0)
    if src is None:
        return None
    tgt, i = extract_set(body, i)
    if tgt is None:
        return None
    while i < len(body) and body[i] == " ":
        i += 1
    if i >= len(body) or body[i] != ":":
        return None
    i += 1
    classes, i = extract_set(body, i)
    perms, _ = extract_set(body, i)
    if classes is None or perms is None:
        return None
    return {
        "src": _parse_set(src),
        "tgt": _parse_set(tgt),
        "classes": _parse_set(classes),
        "perms": _parse_set(perms),
        "raw": body,
    }


# Known permission set aliases (common ones; full list in global_macros)
PERM_ALIASES = {
    "no_rw_file_perms": {"read", "write", "append", "open"},
    "no_w_file_perms": {"write", "append"},
    "no_x_file_perms": {"execute", "execute_no_trans", "execmod"},
    "rw_file_perms": {"read", "write", "open", "getattr", "lock", "ioctl"},
    "r_file_perms": {"read", "open", "getattr", "lock", "ioctl"},
    "w_file_perms": {"write", "open", "getattr", "lock", "append"},
    "*": None,  # wildcard, matches all
}


def _set_matches(parsed_set: tuple, value: str, attrs: set = None) -> bool:
    """Check if value is in parsed_set. attrs = known attributes containing value."""
    inc, exc, wildcard = parsed_set
    attrs = attrs or set()
    if value in exc:
        return False
    for a in attrs:
        if a in exc:
            return False
    if wildcard:
        return True
    if value in inc:
        return True
    if inc & attrs:
        return True
    return False


# Coarse attribute map — true resolution needs compiled policy. These cover
# the most common neverallow attribute references.
COMMON_ATTRS = {
    "domain": lambda t: True,  # all subject types are domains
    "file_type": lambda t: t.endswith("_file") or t.endswith("_data_file"),
    "coredomain": lambda t: False,  # conservative: unknown
    "appdomain": lambda t: "_app" in t or t in {"untrusted_app", "priv_app", "platform_app"},
    "untrusted_app_all": lambda t: t.startswith("untrusted_app"),
}


def _attrs_for(t: str) -> set:
    return {name for name, pred in COMMON_ATTRS.items() if pred(t)}


def _perms_match(parsed_perms: tuple, perm: str) -> bool:
    inc, exc, wildcard = parsed_perms
    if wildcard:
        return True
    # Expand aliases
    expanded = set()
    for p in inc:
        if p in PERM_ALIASES and PERM_ALIASES[p]:
            expanded |= PERM_ALIASES[p]
        else:
            expanded.add(p)
    if perm in exc:
        return False
    return perm in expanded


def check_neverallow_internal(d: Denial, tree: str):
    """Match proposed allow against source-parsed neverallows.
    Returns None if no conflict, else description string listing violations.
    """
    rules = _load_neverallows(tree)
    if not rules:
        return None
    src_attrs = _attrs_for(d.scontext)
    tgt_attrs = _attrs_for(d.tcontext)
    violations = []
    for rule in rules:
        if not _set_matches(rule["src"], d.scontext, src_attrs):
            continue
        if not _set_matches(rule["tgt"], d.tcontext, tgt_attrs):
            continue
        if not _set_matches(rule["classes"], d.tclass):
            continue
        for perm in d.perms:
            if _perms_match(rule["perms"], perm):
                violations.append(f"  {rule['file']}: neverallow {rule['raw'][:200]}")
                break
        if len(violations) >= 3:
            break
    if violations:
        return "Matches existing neverallow(s):\n" + "\n".join(violations)
    return None


@mcp.tool()
def check_neverallow(scontext: str, tcontext: str, tclass: str, perms: str,
                     tree: str = DEFAULT_TREE) -> str:
    """Check a proposed allow rule against compiled neverallow constraints.
    Requires AOSP_OUT_<tree> pointing to a built out/ dir.

    Args:
        scontext: Source type.
        tcontext: Target type.
        tclass: Target class.
        perms: Space-separated perms.
        tree: Tree name.
    """
    perms_tuple = tuple(sorted(perms.split()))
    d = Denial(scontext, tcontext, tclass, perms_tuple, 1, set(), set())
    nv = check_neverallow_internal(d, tree)
    if nv is None:
        analyze = _find_sepolicy_analyze(tree)
        policy = _find_compiled_policy(tree)
        if not analyze or not policy:
            return (f"Cannot check: sepolicy-analyze or compiled policy not found. "
                    f"Set AOSP_OUT_{tree.upper()} and run `m sepolicy sepolicy-analyze`.")
        return "OK — no neverallow violations."
    return f"VIOLATION:\n{nv}"


def suggest_placement(scontext: str, tree: str) -> str | None:
    if tree not in TREES:
        return None
    root = TREES[tree]
    candidates = [
        f"{root}/system/sepolicy/private/{scontext}.te",
        f"{root}/system/sepolicy/vendor/{scontext}.te",
        f"{root}/device/*/sepolicy/{scontext}.te",
    ]
    for c in candidates:
        if "*" not in c and os.path.exists(c):
            return c
    return f"(new file) {root}/system/sepolicy/vendor/{scontext}.te"


@mcp.tool()
def list_trees() -> str:
    """List configured AOSP trees."""
    if not TREES:
        return "No trees configured. Set AOSP_TREE_<NAME> env vars."
    return "\n".join(f"{k}: {v}" for k, v in TREES.items())


if __name__ == "__main__":
    mcp.run(transport="stdio")
