#!/usr/bin/env python
"""shparse: find every simple command bash would execute in a command line.

The gate's floor is only as good as its idea of "which words are commands".
Regex segment-splitting guesses; this module asks a real bash grammar
(tree-sitter-bash) and walks the whole tree, so commands inside if/for/while
bodies, { } groups, ( ) subshells, functions, $( ) and <( ) substitutions,
and pipelines are all seen. Words are resolved to literal text where that is
knowable (quotes removed, backslashes processed, $'..' decoded, ~ and
known/assigned variables expanded); anything unknowable becomes DYN.

Fail-closed rules:
  - tree-sitter ERROR/MISSING nodes      -> result.degraded
  - recursion past MAX_DEPTH             -> result.degraded
  - no tree-sitter installed             -> conservative fallback lexer that
    degrades on any construct it does not fully understand

Public: parse(cmd, cwd, home, env=None) -> ParseResult
"""
import os
import re

try:  # tree-sitter is the real parser; the fallback below is a safety net
    import tree_sitter_bash as _tsb
    from tree_sitter import Language, Parser

    _PARSER = Parser(Language(_tsb.language()))
    HAVE_TS = True
except Exception:  # noqa: BLE001  (any import/ABI problem -> fallback)
    _PARSER = None
    HAVE_TS = False

DYN = "\x00"          # marks an unknowable part of a word
MAX_ALTS = 16         # cap on alternative values per word (loop vars)
MAX_DEPTH = 6         # cap on nested parse (sh -c inside sh -c ...)
GLOB_CHARS = "*?["

STATEMENT_TYPES = {
    "program", "compound_statement", "do_group", "subshell", "list", "pipeline",
    "redirected_statement", "command", "if_statement", "elif_clause",
    "else_clause", "while_statement", "for_statement", "c_style_for_statement",
    "case_statement", "case_item", "function_definition", "negated_command",
    "variable_assignment", "variable_assignments", "declaration_command",
    "unset_command", "test_command",
}
WRITE_OPS = {">", ">>", ">|", "&>", "&>>", "<>"}
WORD_TYPES = {
    "word", "number", "raw_string", "ansi_c_string", "string", "translated_string",
    "string_content", "concatenation", "simple_expansion", "expansion",
    "command_substitution", "process_substitution", "arithmetic_expansion",
    "command_name", "variable_name", "special_variable_name", "file_descriptor",
    "heredoc_start", "heredoc_body", "heredoc_end", "heredoc_content", "comment",
    "file_redirect", "heredoc_redirect", "herestring_redirect", "subscript",
    "brace_expression", "test_operator", "binary_expression", "unary_expression",
    "parenthesized_expression", "postfix_expression", "ternary_expression",
    "regex", "extglob_pattern", "array", "expression", "number", "case_item",
}


class Word:
    """One shell word. `alts` are its possible literal values (DYN inside an
    alt marks an unknowable part). `glob` = unquoted * ? [ present.
    `procsub` = the word is a <( ) / >( ) process substitution."""
    __slots__ = ("alts", "glob", "procsub", "split")

    def __init__(self, alts, glob=False, procsub=False, split=False):
        alts = [a for a in alts][:MAX_ALTS]
        self.alts = alts or [DYN]
        self.glob = glob
        self.procsub = procsub
        self.split = split  # contains an unquoted expansion: bash word-splits it

    @property
    def lit(self):
        """The single literal value, or None if dynamic/ambiguous."""
        if len(self.alts) == 1 and DYN not in self.alts[0]:
            return self.alts[0]
        return None

    @property
    def dynamic(self):
        return any(DYN in a for a in self.alts)

    def show(self):
        return "|".join(a.replace(DYN, "<?>") for a in self.alts)

    __repr__ = show


class Redir:
    __slots__ = ("op", "fd", "target")

    def __init__(self, op, fd, target):
        self.op, self.fd, self.target = op, fd, target

    @property
    def is_write(self):
        if self.op in WRITE_OPS:
            return True
        # `>& file` (not `>&2`, not `>&-`) is a write too
        return self.op == ">&" and self.target is not None and \
            self.target.lit is not None and not re.fullmatch(r"\d+|-", self.target.lit)


class Cmd:
    """A simple command as bash would run it."""
    __slots__ = ("argv", "redirects", "cwd", "pipe_index", "pipe_len",
                 "upstream", "heredoc", "heredoc_dynamic", "herestring",
                 "in_subst", "text", "assigns")

    def __init__(self, argv, cwd, in_subst, text):
        self.argv = argv
        self.redirects = []
        self.cwd = cwd
        self.pipe_index = None
        self.pipe_len = None
        self.upstream = []
        self.heredoc = None          # literal heredoc body fed to stdin
        self.heredoc_dynamic = False  # body has expansions / substitutions
        self.herestring = None       # Word fed via <<<
        self.in_subst = in_subst
        self.text = text
        self.assigns = []            # [(name, Word)] for `NAME=val cmd`

    @property
    def stdin_from_pipe(self):
        return self.pipe_index is not None and self.pipe_index > 0

    def __repr__(self):
        return f"Cmd({[w.show() for w in self.argv]}, cwd={self.cwd})"


class ParseResult:
    def __init__(self, parser):
        self.parser = parser
        self.commands = []
        self.writes = []        # (Word, cwd) redirect writes on compound stmts
        self.var_refs = set()   # every $NAME referenced anywhere
        self.has_subst = False  # any $( ), ` `, <( ), >( )
        self.assignments = []   # [(name, Word)] every assignment anywhere
        self.degraded = False
        self.reasons = []

    def degrade(self, why):
        self.degraded = True
        if why not in self.reasons:
            self.reasons.append(why)


class Ctx:
    __slots__ = ("cwd", "home", "env", "in_subst", "depth")

    def __init__(self, cwd, home, env, in_subst=False, depth=0):
        self.cwd, self.home, self.env = cwd, home, env
        self.in_subst, self.depth = in_subst, depth

    def copy(self, **kw):
        c = Ctx(self.cwd, self.home, dict(self.env), self.in_subst, self.depth)
        for k, v in kw.items():
            setattr(c, k, v)
        return c


# --------------------------------------------------------------------------- #
# word decoding
# --------------------------------------------------------------------------- #
_ANSI = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b",
         "E": "\x1b", "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c(body):
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c != "\\" or i + 1 >= len(body):
            out.append(c); i += 1; continue
        n = body[i + 1]
        if n in _ANSI:
            out.append(_ANSI[n]); i += 2
        elif n == "x":
            m = re.match(r"[0-9a-fA-F]{1,2}", body[i + 2:])
            out.append(chr(int(m.group(), 16)) if m else "x"); i += 2 + (len(m.group()) if m else 0)
        elif n in "uU":
            m = re.match(r"[0-9a-fA-F]{1,%d}" % (4 if n == "u" else 8), body[i + 2:])
            out.append(chr(int(m.group(), 16)) if m else n); i += 2 + (len(m.group()) if m else 0)
        elif n in "01234567":
            m = re.match(r"[0-7]{1,3}", body[i + 1:])
            out.append(chr(int(m.group(), 8))); i += 1 + len(m.group())
        elif n == "c":  # control char: rare, unknowable enough
            out.append(DYN); i += 3
        else:
            out.append("\\" + n); i += 2
    return "".join(out)


def _unescape_bare(text):
    """Unquoted word: backslash quotes the next char; report unquoted globs."""
    out, glob, i = [], False, 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            if text[i + 1] != "\n":
                out.append(text[i + 1])
            i += 2
            continue
        if c in GLOB_CHARS:
            glob = True
        out.append(c)
        i += 1
    return "".join(out), glob


def _unescape_dq(text):
    """Inside double quotes only \\ $ ` " and newline are special."""
    return re.sub(r'\\([\\$`"\n])', lambda m: "" if m.group(1) == "\n" else m.group(1), text)


def _product(parts):
    alts = [""]
    for p in parts:
        alts = [a + b for a in alts for b in p][:MAX_ALTS]
    return alts


NUMERIC_VARS = {"RANDOM", "PPID", "UID", "EUID", "BASHPID", "LINENO", "SECONDS",
                "EPOCHSECONDS", "SRANDOM", "SHLVL", "COLUMNS", "LINES"}


def _var(name, ctx, res):
    res.var_refs.add(name)
    if name in NUMERIC_VARS and name not in ctx.env:
        return ["0"]
    if name in ctx.env:
        return list(ctx.env[name])
    if name == "HOME":
        return [ctx.home]
    if name == "PWD" and ctx.cwd:
        return [ctx.cwd]
    return [DYN]


_SUBSCRIPT_EVAL = re.compile(r"\[[^\]]*(\$\(|`|\$\[)")


def decode(node, ctx, res, first=True):
    """Return the Word for an argument-like node; walk any substitutions."""
    w = _decode(node, ctx, res, first)
    if node.type in ("raw_string", "string", "ansi_c_string", "word", "concatenation"):
        if any(_SUBSCRIPT_EVAL.search(a) for a in w.alts):
            res.degrade("array subscript text that bash may evaluate")
    return w


def _decode(node, ctx, res, first=True):
    t = node.type
    txt = node.text.decode("utf-8", "replace")
    if t == "word":
        if first and txt.startswith("~"):
            head, _, rest = txt.partition("/")
            lit, glob = _unescape_bare(rest)
            tail = ("/" + lit if _ or rest else "")
            if head == "~":
                return Word([ctx.home + tail], glob)
            if head == "~+" and ctx.cwd:
                return Word([ctx.cwd + tail], glob)
            return Word([DYN])  # ~user, ~-: unknowable here
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*=)~(/|$)", txt) if first else None
        if m:  # `dd of=~/x`: bash tilde-expands after = in assignment-like words
            lit, glob = _unescape_bare(txt[len(m.group(1)) + 1:])
            return Word([m.group(1) + ctx.home + lit], glob)
        lit, glob = _unescape_bare(txt)
        return Word([lit], glob)
    if t == "number":
        return Word([txt])
    if t == "$" and txt in ("$$", "$!", "$?", "$#"):
        return Word(["0"])  # tree-sitter emits $$ as an anonymous token
    if t == "raw_string":
        return Word([txt[1:-1]])
    if t == "ansi_c_string":
        return Word([_ansi_c(txt[2:-1])])
    if t in ("string", "translated_string"):
        parts = []
        for c in node.children:
            ct = c.type
            if ct in ('"', '$"'):
                continue
            if ct == "string_content":
                parts.append([_unescape_dq(c.text.decode("utf-8", "replace"))])
            else:
                parts.append(decode(c, ctx, res, first=False).alts)
        return Word(_product(parts) if parts else [""])
    if t == "concatenation":
        parts, glob, procsub, split = [], False, False, False
        for i, c in enumerate(node.children):
            w = decode(c, ctx, res, first=(first and i == 0))
            parts.append(w.alts)
            glob = glob or w.glob
            procsub = procsub or w.procsub
            split = split or w.split
        return Word(_product(parts), glob, procsub, split)
    if t == "simple_expansion":
        names = [c for c in node.children if c.type == "variable_name"]
        if names:
            return Word(_var(names[0].text.decode(), ctx, res), split=True)
        sp = [c.text.decode() for c in node.children if c.type == "special_variable_name"]
        if sp and sp[0] in ("$", "!", "?", "#"):
            return Word(["0"])          # always a number
        return Word([DYN], split=True)  # $1 $@ $* ...
    if t == "expansion":
        kids = [c for c in node.children if c.type not in ("${", "}")]
        if len(kids) == 1 and kids[0].type == "variable_name":
            return Word(_var(kids[0].text.decode(), ctx, res), split=True)
        ops = [c.type for c in node.children if not c.is_named]
        if "@" in ops and any(c.type in ("P", "E", "A", "K") or c.text in (b"P",) for c in node.children):
            res.degrade("${x@P}-style expansion re-evaluates text")
        names = [c for c in node.children if c.type == "variable_name"]
        if names and any(o in (":-", "-", ":=", "=") for o in ops):
            v = _var(names[0].text.decode(), ctx, res)
            if DYN not in v[0]:
                for c in node.children:
                    _walk_words(c, ctx, res)
                return Word(v, split=True)
        for c in node.children:  # ${x:-$(cmd)} etc: still walk substitutions
            _walk_words(c, ctx, res)
        for c in node.children:
            if c.type == "variable_name":
                res.var_refs.add(c.text.decode())
        return Word([DYN])
    if t in ("command_substitution", "process_substitution"):
        res.has_subst = True
        sub = ctx.copy(in_subst=True)
        for c in node.children:
            if c.type in STATEMENT_TYPES:
                walk(c, sub, res)
        return Word([DYN], procsub=(t == "process_substitution"))
    # arithmetic, brace expressions, extglobs, anything else: unknowable
    _walk_words(node, ctx, res)
    return Word([DYN])


def _walk_words(node, ctx, res):
    """Find substitutions buried in nodes we do not otherwise interpret
    (test expressions, case patterns, arithmetic): decode every word."""
    for c in node.children:
        if c.type in ("command_substitution", "process_substitution", "simple_expansion",
                      "expansion", "raw_string", "string", "word", "concatenation",
                      "ansi_c_string", "translated_string"):
            decode(c, ctx, res)
        elif c.type in STATEMENT_TYPES:
            walk(c, ctx, res)
        else:
            _walk_words(c, ctx, res)


# --------------------------------------------------------------------------- #
# statement walking
# --------------------------------------------------------------------------- #
def _resolve_dir(word, ctx):
    lit = word.lit if word is not None else None
    if lit is None or word.glob:
        return None
    if lit == "-":
        return None
    p = lit if os.path.isabs(lit) else (os.path.join(ctx.cwd, lit) if ctx.cwd else None)
    return os.path.normpath(p) if p else None


def _assign(node, ctx, res):
    name = node.child_by_field_name("name")
    val = node.child_by_field_name("value")
    w = decode(val, ctx, res) if val is not None else Word([""])
    if name is not None:
        nm = name.text.decode()
        res.assignments.append((nm, w))
        if nm in ("IFS", "BASH_ALIASES", "BASH_CMDS"):
            res.degrade(f"assignment to {nm} changes how bash reads words")
        op = [c.type for c in node.children]
        if "+=" in op or name.type != "variable_name":
            ctx.env[nm] = [DYN]
        else:
            ctx.env[nm] = w.alts


def _command(node, ctx, res):
    argv, assigns = [], []
    for i, c in enumerate(node.children):
        f = node.field_name_for_child(i)
        if c.type == "variable_assignment":
            assigns.append(c)
        elif f == "name":
            inner = c.children[0] if c.children else c
            argv.append(decode(inner, ctx, res))
        elif f == "argument":
            argv.append(decode(c, ctx, res))
        elif c.type.endswith("_redirect"):
            pass  # handled below with the command object
        elif c.type in ("command_substitution", "process_substitution"):
            argv.append(decode(c, ctx, res))
    prefix = []
    if assigns:
        tmp_ctx = ctx.copy()
        for a in assigns:
            _assign(a, tmp_ctx, res)
            nm = a.child_by_field_name("name")
            if nm is not None:
                prefix.append((nm.text.decode(), Word(tmp_ctx.env.get(nm.text.decode(), [DYN]))))
        if not argv:  # bare `X=1` parsed as a command: it is an assignment
            for a in assigns:
                _assign(a, ctx, res)
            return None
    argv = _split_words(argv, res)
    for w in argv:
        for alt in w.alts:
            if re.search(r"\[[^\]]*(\$\(|`|\$\[)", alt):
                res.degrade("array subscript text that bash may evaluate")
    cmd = Cmd(argv, ctx.cwd, ctx.in_subst, node.text.decode("utf-8", "replace"))
    cmd.assigns = prefix
    for c in node.children:
        if c.type.endswith("_redirect"):
            _redirect(c, cmd, ctx, res)
    res.commands.append(cmd)
    # cd / pushd change where later relative paths land
    if argv and argv[0].lit in ("cd", "pushd") and not ctx.in_subst:
        args = [w for w in argv[1:] if not (w.lit or "").startswith("-")]
        if not args:
            ctx.cwd = ctx.home if argv[0].lit == "cd" else None
        else:
            ctx.cwd = _resolve_dir(args[0], ctx)
    elif argv and argv[0].lit in ("popd", "eval", "source", ".") and not ctx.in_subst:
        ctx.cwd = None   # may cd in ways we cannot follow
    return cmd


def _split_words(argv, res):
    """Unquoted $X undergoes word splitting: X="rm -rf" makes two words."""
    out = []
    for w in argv:
        if not w.split or not any(re.search(r"[ \t\n]", a) for a in w.alts):
            out.append(w)
            continue
        pieces = [a.split() for a in w.alts]
        if len({len(p) for p in pieces}) != 1:
            res.degrade("word splitting with ambiguous word count")
            out.append(Word([DYN]))
            continue
        for i in range(len(pieces[0])):
            out.append(Word([p[i] for p in pieces], w.glob))
    return out


def _redirect(node, cmd, ctx, res):
    t = node.type
    if t == "file_redirect":
        fd = op = None
        target = None
        for i, c in enumerate(node.children):
            f = node.field_name_for_child(i)
            if c.type == "file_descriptor":
                fd = c.text.decode()
            elif f == "destination":
                target = decode(c, ctx, res)
            elif not c.is_named:
                op = c.type
        r = Redir(op, fd, target)
        if cmd is not None:
            cmd.redirects.append(r)
        elif r.is_write and target is not None:
            res.writes.append((target, ctx.cwd))
    elif t == "heredoc_redirect":
        start = node.child_by_field_name("start") or next(
            (c for c in node.children if c.type == "heredoc_start"), None)
        quoted = start is not None and re.search(r"['\"\\]", start.text.decode()) is not None
        body = next((c for c in node.children if c.type == "heredoc_body"), None)
        dyn = False
        if body is not None and not quoted:
            for c in body.children:
                if c.type in ("simple_expansion", "expansion", "command_substitution"):
                    decode(c, ctx, res)
                    dyn = True
        if cmd is not None:
            cmd.heredoc = body.text.decode("utf-8", "replace") if body is not None else ""
            cmd.heredoc_dynamic = dyn
        # tree-sitter nests `cmd <<EOF | other` and `cmd <<EOF && next` inside
        # the heredoc node. A nested pipeline is downstream of cmd.
        for c in node.children:
            if c.type == "pipeline":
                elems = [e for e in c.children if e.is_named]
                upstream = [cmd] if cmd is not None else []
                if cmd is not None and cmd.pipe_index is None:
                    cmd.pipe_index, cmd.pipe_len = 0, len(elems) + 1
                for i, el in enumerate(elems):
                    before = len(res.commands)
                    walk(el, ctx.copy(), res)
                    new = res.commands[before:]
                    for x in new:
                        if x.pipe_index is None:
                            x.pipe_index, x.pipe_len, x.upstream = i + 1, len(elems) + 1, list(upstream)
                    upstream.extend(new)
            elif c.type in STATEMENT_TYPES:
                walk(c, ctx, res)
            elif c.type.endswith("_redirect"):
                _redirect(c, cmd, ctx, res)
    elif t == "herestring_redirect":
        for c in node.children:
            if c.is_named:
                w = decode(c, ctx, res)
                if cmd is not None:
                    cmd.herestring = w
    else:
        _walk_words(node, ctx, res)


def walk(node, ctx, res):
    if ctx.depth > MAX_DEPTH:
        res.degrade("nesting too deep")
        return
    t = node.type
    if t == "ERROR" or node.is_missing:
        res.degrade("parse error near %r" % node.text.decode("utf-8", "replace")[:40])
    if node.is_named and t not in STATEMENT_TYPES and t not in WORD_TYPES and t != "ERROR":
        res.degrade(f"unmodelled shell construct: {t}")
    if t == "comment":
        return
    if t == "command":
        _command(node, ctx, res)
        return
    if t == "redirected_statement":
        body = node.child_by_field_name("body")
        cmd = None
        if body is not None and body.type == "command":
            cmd = _command(body, ctx, res)
        elif body is not None:
            # `a && b <<EOF` / `a; b > f`: tree-sitter hangs the redirect on the
            # whole list, but bash binds it to the LAST simple command (b).
            before = len(res.commands)
            walk(body, ctx, res)
            if body.type in ("list", "pipeline"):
                new = [x for x in res.commands[before:] if not x.in_subst]
                cmd = new[-1] if new else None
        # tree-sitter reads `bash 0<&0` as argv [bash, 0] + `<&0`; bash reads the
        # touching `0` as the redirect's fd. Undo that when the bytes touch.
        reds = [c for c in node.children if c.type.endswith("_redirect")]
        if cmd is not None and body is not None and body.type == "command" and reds:
            last = body.children[-1] if body.children else None
            if last is not None and last.type == "number" and last.end_byte == reds[0].start_byte \
                    and cmd.argv and cmd.argv[-1].lit == last.text.decode():
                cmd.argv.pop()
        for c in node.children:
            if body is not None and (c.start_byte, c.end_byte) == (body.start_byte, body.end_byte):
                continue
            if c.type.endswith("_redirect"):
                _redirect(c, cmd, ctx, res)
            elif c.type in STATEMENT_TYPES:
                walk(c, ctx, res)
        return
    if t == "pipeline":
        elems = [c for c in node.children if c.is_named]
        upstream = []
        for i, el in enumerate(elems):
            before = len(res.commands)
            walk(el, ctx.copy(), res)  # each element runs in a subshell
            new = res.commands[before:]
            for c in new:
                if c.pipe_index is None:
                    c.pipe_index, c.pipe_len, c.upstream = i, len(elems), list(upstream)
            upstream.extend(new)
        return
    if t in ("subshell", "function_definition"):
        sub = ctx.copy()
        for c in node.children:
            walk(c, sub, res)
        if t == "function_definition" and sub.cwd != ctx.cwd:
            ctx.cwd = None   # calling it later moves us somewhere we did not track
        return
    if t == "variable_assignment":
        _assign(node, ctx, res)
        return
    if t == "declaration_command":
        words, named = [], False
        for c in node.children:
            if c.type in ("variable_assignment", "variable_name"):
                named = True
            if c.type == "variable_assignment":
                _assign(c, ctx, res)
            elif not c.is_named and c.type in ("export", "declare", "typeset", "local", "readonly"):
                words.append(Word([c.type]))
            elif c.is_named and c.type not in ("variable_name",):
                words.append(decode(c, ctx, res))
        # flags-only forms (`export -p`, `declare -x`) print the environment:
        # surface them as a command so the classifier can see that
        if not named and words and all((w.lit or "").startswith("-") for w in words[1:]):
            res.commands.append(Cmd(words, ctx.cwd, ctx.in_subst, node.text.decode("utf-8", "replace")))
        return
    if t == "unset_command":
        for c in node.children:
            if c.type in ("variable_name", "word"):
                ctx.env.pop(c.text.decode(), None)
        return
    if t == "for_statement":
        var = node.child_by_field_name("variable")
        vals = []
        has_in = any(c.type == "in" for c in node.children)
        for i, c in enumerate(node.children):
            if node.field_name_for_child(i) == "value":
                vals.extend(decode(c, ctx, res).alts)
        if var is not None:
            ctx.env[var.text.decode()] = vals[:MAX_ALTS] if (has_in and vals) else [DYN]
        body = node.child_by_field_name("body")
        if body is not None:
            walk(body, ctx, res)
        return
    # everything else (program, list, if/while/case, { }, do_group, test,
    # negation, c-style for): walk children in order with a shared context
    for c in node.children:
        if c.type in STATEMENT_TYPES or c.type == "ERROR" or c.is_missing:
            walk(c, ctx, res)
        elif c.is_named:
            _walk_words(c, ctx, res) if c.child_count else None
            if c.type in ("command_substitution", "process_substitution",
                          "simple_expansion", "expansion", "string", "concatenation"):
                decode(c, ctx, res)


# --------------------------------------------------------------------------- #
# fallback lexer (no tree-sitter): understands only plain command lines
# --------------------------------------------------------------------------- #
_RESERVED = {"if", "then", "else", "elif", "fi", "for", "while", "until", "do",
             "done", "case", "esac", "function", "select", "in", "{", "}", "!",
             "[[", "]]", "time", "coproc"}


def _fallback(cmd, cwd, home, env):
    """No tree-sitter: a small lexer that handles quoting, escapes, simple
    $VAR expansion, prefix assignments, redirections, ; && || | & and
    newlines, and degrades on everything else (compound statements,
    substitutions, heredocs, braces, parentheses)."""
    res = ParseResult("fallback")
    if re.search(r"`|\$\(|[<>]\(|<<|[(){}]", cmd):
        res.degrade("fallback parser: compound/substitution syntax")
    ctx = Ctx(cwd, home, dict(env or {}))
    st = {"words": [], "redirs": [], "pending": None, "upstream": [], "pipe_i": 0}
    w = {"buf": [], "glob": False, "split": False, "have": False, "first": True}

    def lit_var(name):
        vals = _var(name, ctx, res)
        return vals[0] if len(vals) == 1 and DYN not in vals[0] else DYN

    def end_word():
        if not w["have"]:
            return
        text = "".join(w["buf"])
        word = Word([text], w["glob"], split=w["split"])
        if st["pending"]:
            st["redirs"].append(Redir(st["pending"], None, word)); st["pending"] = None
        else:
            st["words"].append(word)
        w.update(buf=[], glob=False, split=False, have=False, first=True)

    def end_cmd(op):
        end_word()
        words = st["words"]
        assigns = []
        while words and words[0].lit and re.match(r"^[A-Za-z_]\w*=", words[0].lit):
            nm, _, val = words[0].lit.partition("=")
            assigns.append((nm, Word([val])))
            res.assignments.append((nm, Word([val])))
            if nm in ("IFS", "BASH_ALIASES", "BASH_CMDS"):
                res.degrade(f"assignment to {nm} changes how bash reads words")
            words = words[1:]
        if words:
            if words[0].lit in _RESERVED:
                res.degrade("fallback parser: compound statement")
            c = Cmd(_split_words(words, res), ctx.cwd, False, cmd)
            c.redirects = st["redirs"]
            c.assigns = assigns
            if st["upstream"]:
                c.pipe_index, c.upstream = st["pipe_i"], list(st["upstream"])
            res.commands.append(c)
            head = words[0].lit
            if head in ("cd", "pushd"):
                a = [x for x in words[1:] if not (x.lit or "").startswith("-")]
                ctx.cwd = home if not a else _resolve_dir(a[0], ctx)
            elif head in ("popd", "eval", "source", "."):
                ctx.cwd = None
            if op in ("|", "|&"):
                st["upstream"].append(c); st["pipe_i"] += 1
                if st["pipe_i"] == 1:
                    c.pipe_index = 0
            else:
                st["upstream"], st["pipe_i"] = [], 0
        else:
            for nm, val in assigns:
                ctx.env[nm] = val.alts
        st["words"], st["redirs"] = [], []

    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c == "\\" and i + 1 < n:
            if cmd[i + 1] != "\n":
                w["buf"].append(cmd[i + 1]); w["have"] = True
            i += 2; continue
        if c == "'":
            j = cmd.find("'", i + 1)
            if j < 0:
                res.degrade("fallback parser: unbalanced quote"); j = n
            w["buf"].append(cmd[i + 1:j]); w["have"] = True; i = j + 1; continue
        if c == '"':
            j = i + 1
            while j < n and cmd[j] != '"':
                if cmd[j] == "\\" and j + 1 < n and cmd[j + 1] in '\\$`"\n':
                    if cmd[j + 1] != "\n":
                        w["buf"].append(cmd[j + 1])
                    j += 2; continue
                if cmd[j] == "$":
                    m = re.match(r"\$(\w+|\{\w+\})", cmd[j:])
                    if m:
                        w["buf"].append(lit_var(m.group(1).strip("{}"))); j += len(m.group()); continue
                    w["buf"].append(DYN); j += 1; continue
                w["buf"].append(cmd[j]); j += 1
            if j >= n:
                res.degrade("fallback parser: unbalanced quote")
            w["have"] = True; i = j + 1; continue
        if c == "$":
            m = re.match(r"\$(\w+|\{\w+\}|\$)", cmd[i:])
            w["have"] = True
            if m:
                name = m.group(1).strip("{}")
                w["buf"].append("0" if name == "$" else lit_var(name))
                w["split"] = True
                i += len(m.group()); continue
            res.degrade("fallback parser: complex expansion")
            w["buf"].append(DYN); i += 1; continue
        if c in " \t":
            end_word(); i += 1; continue
        if c in "\n;&|":
            two = cmd[i:i + 2]
            if two == "&>":
                end_word(); st["pending"] = "&>>" if cmd[i:i + 3] == "&>>" else "&>"
                i += len(st["pending"]); continue
            op = two if two in ("&&", "||", ";;", "|&") else c
            end_cmd(op); i += len(op); continue
        if c in "<>":
            m = re.match(r"(>>|>\||>&|<>|<&|>|<)", cmd[i:])
            if w["have"] and "".join(w["buf"]).isdigit():   # 2>file: fd number
                w.update(buf=[], glob=False, split=False, have=False, first=True)
            else:
                end_word()
            st["pending"] = m.group(1); i += len(m.group(1)); continue
        if c == "~" and not w["have"] and (i + 1 >= n or cmd[i + 1] in "/ \t;&|"):
            w["buf"].append(home); w["have"] = True; i += 1; continue
        if c == "~" and w["have"] and re.fullmatch(r"[A-Za-z_]\w*=", "".join(w["buf"])) and \
                (i + 1 >= n or cmd[i + 1] in "/ \t;&|"):
            w["buf"].append(home); i += 1; continue   # of=~/x
        if c in GLOB_CHARS:
            w["glob"] = True
        w["buf"].append(c); w["have"] = True; i += 1
    end_cmd(None)
    return res


# --------------------------------------------------------------------------- #
# coverage invariant: every non-blank byte bash will read must belong to some
# grammar node. If tree-sitter skipped bytes, its idea of argv differs from
# bash's (seen: `python3 - <<EOF` drops the `-`), so the parse is not trusted.
_GAP_OK = re.compile(rb"(?:[ \t\r\n]|\\\n)*")


def _uncovered(node, src):
    kids = node.children
    if not kids or node.type in ("heredoc_body", "string_content", "comment",
                                 "raw_string", "word", "ansi_c_string"):
        return None
    pos = node.start_byte
    for c in kids:
        gap = src[pos:c.start_byte]
        if gap and not _GAP_OK.fullmatch(gap):
            return gap
        bad = _uncovered(c, src)
        if bad is not None:
            return bad
        pos = max(pos, c.end_byte)
    gap = src[pos:node.end_byte]
    if gap and not _GAP_OK.fullmatch(gap):
        return gap
    return None


def parse(cmd, cwd, home=None, env=None, depth=0):
    home = home or os.path.expanduser("~")
    if not HAVE_TS:
        return _fallback(cmd, cwd, home, env)
    res = ParseResult("tree-sitter")
    src = cmd.encode("utf-8", "surrogateescape")
    tree = _PARSER.parse(src)
    root = tree.root_node
    gap = _uncovered(root, src)
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type == "comment" and src[max(0, n.start_byte - 2):n.start_byte] == b"\\\n":
            res.degrade("`#` after a line continuation is not a comment in bash")
        stack.extend(n.children)
    if gap is None and src[:root.start_byte].strip() + src[root.end_byte:].strip():
        gap = (src[:root.start_byte] + src[root.end_byte:]).strip()
    if gap is not None:
        res.degrade("parser skipped text %r" % gap.decode("utf-8", "replace")[:30])
    walk(root, Ctx(cwd, home, dict(env or {}), depth=depth), res)
    return res


if __name__ == "__main__":
    import sys
    r = parse(sys.argv[1], os.getcwd())
    print("parser:", r.parser, "degraded:", r.degraded, r.reasons)
    for c in r.commands:
        print(" ", c, "pipe", c.pipe_index, "redirs", [(x.op, x.target) for x in c.redirects],
              "heredoc" if c.heredoc is not None else "")
