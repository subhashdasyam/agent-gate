#!/usr/bin/env python
"""embedded: find shell code inside files an agent writes, which runs later.

A shell gate cannot see `npm test` running a `test` script that an agent
wrote a minute ago with its Write/Edit/apply_patch tool. This module pulls the
shell snippets out of the file types that commonly hold them, so the same
command analyzer can judge them at write time:

  *.sh *.bash *.zsh *.ksh, .envrc, sh/bash/zsh shebang (incl. env -S) -> whole file
  package.json      -> "scripts", plus git-hook keys: lint-staged,
                       simple-git-hooks, husky.hooks, pre-commit
  Makefile / *.mk / GNUmakefile -> recipe lines (tab or inline `t: ; cmd`),
                       $(shell ...), simple variables expanded, included
                       makefiles that exist next to it
  justfile          -> recipe lines and `x := \\`cmd\\`` backticks
  .github/workflows -> `run:` steps            .gitlab-ci.yml -> script keys
  Taskfile*.yml     -> cmds / cmd / sh          tox.ini -> commands

Fail closed: when a file of one of these kinds cannot be analyzed completely
(too big, too many snippets, JSON that does not parse, .RECIPEPREFIX,
$(eval ...)), the result contains (UNVERIFIABLE, reason) and the caller
reviews the write instead of passing it.

Public: analyzable(path) -> bool
        shell_snippets(path, content) -> [(label, shell_text)]
"""
import json
import os
import re

MAX_BYTES = 2_000_000
MAX_SNIPPETS = 3000
UNVERIFIABLE = "!unverifiable"
SHEBANG_RE = re.compile(r"^#!\s*\S*/(?:env\s+(?:-\S+\s+)*)?(sh|bash|zsh|dash|ksh|ash|mksh)\b")
PKG_HOOK_KEYS = ("lint-staged", "simple-git-hooks", "pre-commit", "husky", "gitHooks", "ghooks")

try:  # optional: better CI YAML handling when PyYAML is around
    import yaml  # type: ignore
except Exception:  # noqa: BLE001
    yaml = None


def _kind(path, content=None):
    name = os.path.basename(path)
    low = name.lower()
    norm = "/" + path.replace("\\", "/")
    if low.endswith((".sh", ".bash", ".zsh", ".ksh")) or low == ".envrc":
        return "script"
    if low == "package.json":
        return "package"
    if low in ("makefile", "gnumakefile") or low.endswith(".mk"):
        return "make"
    if low in ("justfile", ".justfile"):
        return "just"
    if "/.github/workflows/" in norm.lower() and low.endswith((".yml", ".yaml")):
        return "workflow"
    if low == ".gitlab-ci.yml":
        return "gitlab"
    if re.fullmatch(r"taskfile(\.dist)?\.ya?ml", low):
        return "task"
    if low == "tox.ini":
        return "tox"
    if content is not None and SHEBANG_RE.match(content.lstrip("﻿").split("\n", 1)[0]):
        return "script"
    return None


def analyzable(path, content=None):
    return _kind(path, content) is not None


def _ci_expr(s):
    """${{ github.x }} templating is not shell: neutralize."""
    return re.sub(r"\$\{\{.*?\}\}", "CIEXPR", s, flags=re.S)


def _yaml_walk(node, keys, label, out):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in keys:
                for item in (v if isinstance(v, list) else [v]):
                    if isinstance(item, str):
                        out.append((f"{label}.{k}", _ci_expr(item)))
                    elif isinstance(item, dict):   # Taskfile: {cmd: ...} / {sh: ...}
                        _yaml_walk(item, keys, label, out)
            else:
                _yaml_walk(v, keys, label, out)
    elif isinstance(node, list):
        for v in node:
            _yaml_walk(v, keys, label, out)


def _yaml_fallback(content, keys, label, out):
    """No PyYAML: `key: cmd`, `key: |` blocks and `- cmd` lists under key."""
    lines = content.splitlines()
    i = 0
    key_re = re.compile(r"^(\s*)-?\s*(%s)\s*:\s*(.*)$" % "|".join(map(re.escape, keys)))
    while i < len(lines):
        m = key_re.match(lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(3).strip()
        if rest and rest[0] not in "|>" and not rest.startswith("["):
            out.append((f"{label}.{m.group(2)}", _ci_expr(rest.strip("'\""))))
            i += 1
            continue
        block = []
        i += 1
        while i < len(lines) and (not lines[i].strip() or
                                  len(lines[i]) - len(lines[i].lstrip()) > indent):
            ln = lines[i].strip()
            if ln.startswith("- "):
                ln = ln[2:].strip("'\"")
            block.append(ln)
            i += 1
        if block:
            out.append((f"{label}.{m.group(2)}", _ci_expr("\n".join(block))))


def _yaml_snippets(content, keys, label, out):
    if yaml is not None:
        try:
            _yaml_walk(yaml.safe_load(content), keys, label, out)
            return
        except Exception:  # noqa: BLE001  partial/invalid YAML: use the fallback
            pass
    _yaml_fallback(content, keys, label, out)


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)


# ------------------------------------------------------------------ make ------
_MAKE_VAR = re.compile(r"^\s*(?:export\s+|override\s+)?([A-Za-z_][\w.-]*)\s*(?:::?=|\?=|\+=|=)\s*(.*)$")


def _make(content, path, out, depth=0):
    # .RECIPEPREFIX = >   : recipe lines start with that character instead of a tab
    m = re.search(r"^\s*\.RECIPEPREFIX\s*:?:?=\s*(\S)", content, re.M)
    prefix = m.group(1) if m else "\t"
    # $(eval ...) only re-reads make text built from variables/defines, which
    # we expand and analyze below, and $(shell ...) is extracted on any line
    variables = {}
    lines = content.splitlines()
    for ln in lines:
        if ln.startswith(prefix) or ln.startswith("\t"):
            continue
        m = _MAKE_VAR.match(ln)
        if m and ":" not in m.group(1):
            variables[m.group(1)] = m.group(2)

    def expand(s, n=0):
        if n > 4:
            return s
        s2 = re.sub(r"\$[\(\{]([A-Za-z_][\w.-]*)[\)\}]",
                    lambda m: variables.get(m.group(1), "MAKEVAR"), s)
        return expand(s2, n + 1) if s2 != s and "$(" in s2 else s2

    def clean(s):
        s = expand(s.lstrip("@-+ \t"))
        s = re.sub(r"\$[@<^?*%+|]", "MAKEVAR", s)
        return s.replace("$$", "$")

    buf, in_define = "", False
    for ln in lines:
        if re.match(r"^\s*define\b", ln):
            in_define = True
        if in_define:
            if re.match(r"^\s*endef\b", ln):
                in_define = False
            else:
                out.append(("define", clean(ln)))
            continue
        for sh in re.findall(r"\$\(shell\s+([^)]*)\)", ln):
            out.append(("$(shell)", clean(sh)))
        inc = re.match(r"^\s*-?s?include\s+(.+)$", ln)
        if inc and depth < 2 and path:
            for name in inc.group(1).split():
                full = os.path.join(os.path.dirname(path), expand(name))
                try:
                    if os.path.getsize(full) <= MAX_BYTES:
                        with open(full, encoding="utf-8", errors="replace") as fh:
                            _make(fh.read(), full, out, depth + 1)
                except OSError:
                    pass
        is_recipe = ln.startswith(prefix) or ln.startswith("\t")
        if not is_recipe and not buf:
            m = re.match(r"^[^\t#=]*?[^:=]:(?!=)[^;=]*;(.*)$", ln)   # `target: deps ; cmd`
            if m and m.group(1).strip():
                out.append(("recipe", clean(m.group(1))))
            continue
        piece = ln[1:] if is_recipe and not buf else ln
        if piece.endswith("\\"):
            buf += piece[:-1] + " "
            continue
        out.append(("recipe", clean(buf + piece)))
        buf = ""


def shell_snippets(path, content):
    if not isinstance(content, str) or not content:
        return []
    kind = _kind(path, content)
    if kind is None:
        return []
    if len(content) > MAX_BYTES:
        return [(UNVERIFIABLE, f"file larger than {MAX_BYTES} bytes")]
    content = content.lstrip("﻿")
    out = []
    if kind == "script":
        out.append(("script", content))
    elif kind == "package":
        try:
            data = json.loads(content)
        except ValueError:
            return [(UNVERIFIABLE, "package.json does not parse as JSON")]
        if isinstance(data, dict):
            for k, v in (data.get("scripts") or {}).items() if isinstance(data.get("scripts"), dict) else []:
                if isinstance(v, str):
                    out.append((f"scripts.{k}", v))
            for key in PKG_HOOK_KEYS:
                for v in _strings(data.get(key)):
                    out.append((key, v))
            cfg = data.get("config")
            if isinstance(cfg, dict) and isinstance(cfg.get("ghooks"), dict):
                for v in _strings(cfg["ghooks"]):
                    out.append(("config.ghooks", v))
    elif kind == "make":
        _make(content, path, out)
    elif kind == "just":
        for bt in re.findall(r"`([^`\n]+)`", content):
            out.append(("backtick", bt))
        for line in content.splitlines():
            if line[:1] in (" ", "\t") and line.strip() and not line.strip().startswith("#"):
                out.append(("recipe", re.sub(r"\{\{.*?\}\}", "JUSTVAR", line.strip().lstrip("@-"))))
    elif kind == "workflow":
        _yaml_snippets(content, ("run",), "workflow", out)
    elif kind == "gitlab":
        _yaml_snippets(content, ("script", "before_script", "after_script"), "gitlab", out)
    elif kind == "task":
        _yaml_snippets(content, ("cmds", "cmd", "sh"), "task", out)
    elif kind == "tox":
        grab = False
        for line in content.splitlines():
            m = re.match(r"^\s*(commands(?:_pre|_post)?|allowlist_externals)\s*=\s*(.*)$", line)
            if m:
                grab = m.group(1).startswith("commands")
                if grab and m.group(2).strip():
                    out.append(("tox", m.group(2).strip()))
                continue
            if grab and line[:1] in (" ", "\t") and line.strip():
                out.append(("tox", line.strip()))
            elif line.strip():
                grab = False
    if len(out) > MAX_SNIPPETS:
        return [(UNVERIFIABLE, f"more than {MAX_SNIPPETS} embedded commands")]
    return out
