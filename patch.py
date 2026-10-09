#!/usr/bin/env python
"""patch: Codex `apply_patch` format, parsed the way Codex parses it.

Grammar (from codex-rs/apply-patch/src/parser.rs, lenient about whitespace
around markers, like Codex):

  *** Begin Patch
  [*** Environment ID: <id>]
  *** Add File: <path>        then "+line" lines
  *** Delete File: <path>
  *** Update File: <path>     [*** Move to: <path>]  then hunks:
      "@@" / "@@ ctx" lines, " ctx" / "-old" / "+new" lines, [*** End of File]
  *** End Patch

Public:
  parse(text) -> list of ops, or None when the text is not a patch
  new_content(op, base_dir) -> (text, exact) the file after the patch;
      exact=False when we could only collect the added lines
"""
import os

BEGIN, END = "*** Begin Patch", "*** End Patch"
ADD, DELETE, UPDATE, MOVE = "*** Add File: ", "*** Delete File: ", "*** Update File: ", "*** Move to: "
EOF_MARK, ENV_ID = "*** End of File", "*** Environment ID: "


def parse(text):
    if not isinstance(text, str):
        return None
    lines = text.replace("\r\n", "\n").split("\n")
    stripped = [ln.strip() for ln in lines]
    if BEGIN not in stripped:
        return None
    i = stripped.index(BEGIN) + 1
    ops, cur = [], None
    while i < len(lines):
        raw, s = lines[i], stripped[i]
        # inside an Update hunk, " x" / "+x" / "-x" are hunk lines even when x
        # looks like a marker: Codex keeps indented markers as context
        if cur is not None and cur["op"] == "update" and raw[:1] in (" ", "+", "-"):
            h = cur["hunks"][-1]
            if raw[0] == "+":
                h[1].append(raw[1:]); cur["add"].append(raw[1:])
            elif raw[0] == "-":
                h[0].append(raw[1:])
            else:
                h[0].append(raw[1:]); h[1].append(raw[1:])
            i += 1
            continue
        if s == END:
            break
        if s.startswith(ENV_ID.strip()):
            i += 1
            continue
        if s.startswith(ADD.strip()):
            cur = {"op": "add", "path": s[len(ADD.strip()):].strip(), "add": [], "hunks": []}
            ops.append(cur)
        elif s.startswith(DELETE.strip()):
            cur = {"op": "delete", "path": s[len(DELETE.strip()):].strip(), "add": [], "hunks": []}
            ops.append(cur)
        elif s.startswith(UPDATE.strip()):
            cur = {"op": "update", "path": s[len(UPDATE.strip()):].strip(), "move_to": None,
                   "add": [], "hunks": [[[], [], None]]}
            ops.append(cur)
        elif s.startswith(MOVE.strip()) and cur is not None and cur["op"] == "update":
            cur["move_to"] = s[len(MOVE.strip()):].strip()
        elif s == EOF_MARK:
            pass
        elif cur is not None and cur["op"] == "add" and raw.startswith("+"):
            cur["add"].append(raw[1:])
        elif cur is not None and cur["op"] == "update":
            if s == "@@" or s.startswith("@@ "):
                ctx = s[3:] if s.startswith("@@ ") else None   # `@@ ctx`: seek this line first
                if cur["hunks"][-1][:2] != [[], []] or cur["hunks"][-1][2] is not None:
                    cur["hunks"].append([[], [], ctx])
                else:
                    cur["hunks"][-1][2] = ctx
            elif raw == "":
                cur["hunks"][-1][0].append(""); cur["hunks"][-1][1].append("")
        i += 1
    return ops


_UNI = {**{c: "-" for c in "\u2010\u2011\u2012\u2013\u2014\u2015\u2212"},
        **{c: "'" for c in "\u2018\u2019\u201a\u201b"},
        **{c: '"' for c in "\u201c\u201d\u201e\u201f"},
        **{c: " " for c in "\u00a0\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009"
                            "\u200a\u202f\u205f\u3000"}}


def _normalise(x):
    """Codex seek_sequence::normalise: trim + fancy dashes/quotes/spaces -> ASCII."""
    return "".join(_UNI.get(c, c) for c in x.strip())


def _seek(hay, needle, start):
    """Find `needle` lines in `hay` from `start`: exact, rstrip, strip, then
    Unicode-normalised, the same order of leniency as Codex's seek_sequence."""
    if not needle:
        return start
    for norm in (lambda x: x, str.rstrip, str.strip, _normalise):
        n = [norm(x) for x in needle]
        for k in range(start, len(hay) - len(needle) + 1):
            if [norm(x) for x in hay[k:k + len(needle)]] == n:
                return k
    return -1


def new_content(op, base_dir):
    if op["op"] == "add":
        return "\n".join(op["add"]) + "\n", True
    if op["op"] != "update":
        return None, True
    path = op["path"]
    full = path if os.path.isabs(path) or base_dir is None else os.path.join(base_dir, path)
    try:
        if os.path.getsize(full) > 2_000_000:
            raise OSError("too big")
        with open(full, encoding="utf-8", errors="replace") as fh:
            hay = fh.read().split("\n")
    except (OSError, TypeError):
        return "\n".join(op["add"]) + "\n", False
    pos = 0
    for old, new, ctx in op["hunks"]:
        if ctx is not None:   # `@@ ctx`: Codex seeks the context line, then the hunk after it
            c = _seek(hay, [ctx], pos)
            if c < 0:
                return "\n".join(op["add"]) + "\n", False
            pos = c + 1
        if not old and not new:
            continue
        k = _seek(hay, old, pos)
        if k < 0:
            return "\n".join(op["add"]) + "\n", False
        hay[k:k + len(old)] = new
        pos = k + len(new)
    return "\n".join(hay), True
