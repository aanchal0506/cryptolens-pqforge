"""Splits a Python file into code units (functions, methods, module-level code).

We use the standard `ast` module, so nothing is executed. Each unit keeps its
own source text and line range, and nested functions become separate units.
"""
import ast
from dataclasses import dataclass, field


@dataclass
class CodeUnit:
    file: str
    name: str
    kind: str          # "function", "method" or "module"
    start: int
    end: int
    source: str
    stmts: list = field(repr=False, default_factory=list)


def build_alias_map(tree):
    """Map local names to the full module path they were imported from.

    import hashlib as h                      -> h: hashlib
    from Crypto.Cipher import AES            -> AES: Crypto.Cipher.AES
    from cryptography.hazmat.primitives import hashes as hh
                                             -> hh: cryptography.hazmat.primitives.hashes
    """
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for a in node.names:
                if a.name != "*":
                    aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def extract_units(source, filename="<string>"):
    tree = ast.parse(source)
    lines = source.splitlines()
    units = []

    def text(first, last):
        return "\n".join(lines[first - 1:last])

    def visit(body, prefix, in_class, emit_loose, loose_name):
        loose = []
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}{st.name}"
                units.append(CodeUnit(
                    filename, name, "method" if in_class else "function",
                    st.lineno, st.end_lineno, text(st.lineno, st.end_lineno), list(st.body)))
                visit(st.body, name + ".", False, False, None)
            elif isinstance(st, ast.ClassDef):
                visit(st.body, f"{prefix}{st.name}.", True, True, f"{prefix}{st.name}.<class body>")
            else:
                loose.append(st)
        if emit_loose and loose:
            first, last = loose[0].lineno, loose[-1].end_lineno
            units.append(CodeUnit(filename, loose_name, "module", first, last,
                                  text(first, last), loose))

    visit(tree.body, "", False, True, "<module>")
    return units, build_alias_map(tree)