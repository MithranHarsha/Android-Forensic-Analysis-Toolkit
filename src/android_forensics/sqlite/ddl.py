"""A small, strict ``CREATE TABLE`` reader: column names, declared types, keys and storage-relevant options.

The page-level engine must work on databases the SQLite library refuses to open, so it learns each table's columns from
the ``sql`` text stored in ``sqlite_master`` rather than from ``PRAGMA table_info``. What matters for reading records:

* how many columns a stored record has (a ``GENERATED ... VIRTUAL`` column is *not* stored; a ``STORED`` one is);
* which column is the **rowid alias** (a lone ``INTEGER PRIMARY KEY``: stored as NULL in the record, its value is the
  cell's rowid) — except ``INTEGER PRIMARY KEY DESC``, which SQLite deliberately does not treat as an alias;
* whether the table is ``WITHOUT ROWID`` (stored as an index b-tree: primary-key columns first) or virtual (no b-tree of
  its own).

Tested against ``PRAGMA table_xinfo`` on real and adversarial statements (``tests/unit/test_sqlite_ddl.py``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from android_forensics.models.enums import TypeAffinity
from android_forensics.sqlite.inspection import affinity_of

_WORD = re.compile(r"[A-Za-z_\u0080-￿][A-Za-z0-9_$\u0080-￿]*")
_NUMBER = re.compile(r"0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")
_CONSTRAINT_STARTS = frozenset({"CONSTRAINT", "PRIMARY", "NOT", "NULL", "UNIQUE", "CHECK", "DEFAULT", "COLLATE", "REFERENCES", "GENERATED", "AS"})
_TABLE_CONSTRAINTS = frozenset({"CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"})


class DdlError(ValueError):
    """The statement is not a CREATE TABLE this reader understands."""


@dataclass(frozen=True)
class Token:
    kind: str  # word · quoted · string · number · punct
    text: str  # identifiers dequoted, strings without quotes

    @property
    def upper(self) -> str:
        return self.text.upper() if self.kind == "word" else ""

    def is_word(self, *names: str) -> bool:
        return self.kind == "word" and self.text.upper() in names

    def is_punct(self, ch: str) -> bool:
        return self.kind == "punct" and self.text == ch


def tokenize(sql: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c.isspace():
            i += 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j + 1
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif c in "\"`":
            j = i + 1
            out = []
            while j < n:
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:
                        out.append(c)
                        j += 2
                        continue
                    break
                out.append(sql[j])
                j += 1
            tokens.append(Token("quoted", "".join(out)))
            i = j + 1
        elif c == "[":
            j = sql.find("]", i)
            j = n if j < 0 else j
            tokens.append(Token("quoted", sql[i + 1:j]))
            i = j + 1
        elif c == "'":
            j = i + 1
            out = []
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        out.append("'")
                        j += 2
                        continue
                    break
                out.append(sql[j])
                j += 1
            tokens.append(Token("string", "".join(out)))
            i = j + 1
        elif (m := _NUMBER.match(sql, i)) and (c.isdigit() or (c == "." and i + 1 < n and sql[i + 1].isdigit())):
            tokens.append(Token("number", m.group()))
            i = m.end()
        elif m := _WORD.match(sql, i):
            tokens.append(Token("word", m.group()))
            i = m.end()
        else:
            tokens.append(Token("punct", c))
            i += 1
    return tokens


@dataclass(frozen=True)
class ColumnDef:
    index: int  # position among all declared columns
    name: str
    declared_type: str
    affinity: TypeAffinity
    not_null: bool
    default_sql: str | None
    primary_key_position: int  # 0: not part of the primary key
    generated: str | None  # "virtual" | "stored" | None
    is_rowid_alias: bool

    @property
    def is_stored(self) -> bool:
        """Present in the on-disk record (virtual generated columns are computed on read, never stored)."""
        return self.generated != "virtual"


@dataclass(frozen=True)
class TableSql:
    name: str
    columns: tuple[ColumnDef, ...]
    without_rowid: bool
    virtual: bool
    autoincrement: bool
    strict: bool

    @property
    def stored_columns(self) -> tuple[ColumnDef, ...]:
        return tuple(c for c in self.columns if c.is_stored)

    @property
    def primary_key(self) -> tuple[str, ...]:
        return tuple(c.name for c in sorted((c for c in self.columns if c.primary_key_position), key=lambda c: c.primary_key_position))

    @property
    def rowid_alias(self) -> ColumnDef | None:
        return next((c for c in self.columns if c.is_rowid_alias), None)


# ------------------------------------------------------------------ parsing


def _skip_parens(tokens: list[Token], i: int) -> int:
    """``tokens[i]`` is ``(``: return the index just past its matching ``)``."""
    depth = 0
    while i < len(tokens):
        if tokens[i].is_punct("("):
            depth += 1
        elif tokens[i].is_punct(")"):
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise DdlError("unbalanced parentheses")


def _split_top_level(tokens: list[Token]) -> list[list[Token]]:
    items: list[list[Token]] = [[]]
    depth = 0
    for t in tokens:
        if t.is_punct("("):
            depth += 1
        elif t.is_punct(")"):
            depth -= 1
        if depth == 0 and t.is_punct(","):
            items.append([])
        else:
            items[-1].append(t)
    return [it for it in items if it]


def _type_text(tokens: list[Token]) -> str:
    out = ""
    for t in tokens:
        if t.kind == "punct" and t.text in "(),":
            out += t.text
        else:
            out += (" " if out and not out.endswith("(") and not out.endswith(",") else "") + t.text
    return out


def parse_create_table(sql: str) -> TableSql:
    tokens = tokenize(sql)
    i = 0
    if not (tokens and tokens[0].is_word("CREATE")):
        raise DdlError("not a CREATE statement")
    i = 1
    while i < len(tokens) and tokens[i].is_word("TEMP", "TEMPORARY"):
        i += 1
    virtual = i < len(tokens) and tokens[i].is_word("VIRTUAL")
    if virtual:
        i += 1
    if not (i < len(tokens) and tokens[i].is_word("TABLE")):
        raise DdlError("not a CREATE TABLE statement")
    i += 1
    if tokens[i:i + 3] and [t.upper for t in tokens[i:i + 3]] == ["IF", "NOT", "EXISTS"]:
        i += 3
    if i >= len(tokens):
        raise DdlError("missing table name")
    name = tokens[i].text
    i += 1
    if i < len(tokens) and tokens[i].is_punct("."):  # schema.name
        name = tokens[i + 1].text
        i += 2
    if virtual:
        return TableSql(name, (), False, True, False, False)
    if i >= len(tokens) or not tokens[i].is_punct("("):
        raise DdlError("only CREATE TABLE name(...) is supported (CREATE TABLE ... AS SELECT is stored by SQLite in this form)")
    end = _skip_parens(tokens, i)
    items = _split_top_level(tokens[i + 1:end - 1])
    tail = [t.upper for t in tokens[end:] if t.kind == "word"]

    columns: list[dict] = []
    table_pk: list[tuple[str, bool]] = []  # (column, descending)
    autoincrement = False
    for item in items:
        if item[0].is_word(*_TABLE_CONSTRAINTS) and item[0].kind == "word":
            j = 0
            if item[0].is_word("CONSTRAINT"):
                j = 2
            if j < len(item) and item[j].is_word("PRIMARY"):
                k = j + 2
                if k < len(item) and item[k].is_punct("("):
                    stop = _skip_parens(item, k)
                    for part in _split_top_level(item[k + 1:stop - 1]):
                        table_pk.append((part[0].text, False))  # a table-level DESC does not stop INTEGER PRIMARY KEY being the rowid alias
                    autoincrement = autoincrement or any(t.is_word("AUTOINCREMENT") for t in item[stop:])
            continue
        col = {"name": item[0].text, "type": "", "not_null": False, "default": None, "pk": False, "pk_desc": False, "generated": None}
        j = 1
        type_tokens: list[Token] = []
        while j < len(item) and not (item[j].kind == "word" and item[j].upper in _CONSTRAINT_STARTS):
            if item[j].is_punct("("):
                stop = _skip_parens(item, j)
                type_tokens.extend(item[j:stop])
                j = stop
                continue
            type_tokens.append(item[j])
            j += 1
        col["type"] = _type_text(type_tokens)
        while j < len(item):
            t = item[j]
            if t.is_word("CONSTRAINT"):
                j += 2
            elif t.is_word("PRIMARY"):
                col["pk"] = True
                j += 2
                if j < len(item) and item[j].is_word("ASC", "DESC"):
                    col["pk_desc"] = item[j].upper == "DESC"
                    j += 1
                while j < len(item) and not item[j].is_word("AUTOINCREMENT", "NOT", "NULL", "UNIQUE", "CHECK", "DEFAULT", "COLLATE", "REFERENCES", "GENERATED", "AS", "CONSTRAINT"):
                    j += 1  # ON CONFLICT clause
                if j < len(item) and item[j].is_word("AUTOINCREMENT"):
                    autoincrement = True
                    j += 1
            elif t.is_word("NOT") and j + 1 < len(item) and item[j + 1].is_word("NULL"):
                col["not_null"] = True
                j += 2
            elif t.is_word("DEFAULT"):
                j += 1
                start = j
                if j < len(item) and item[j].is_punct("("):
                    j = _skip_parens(item, j)
                else:
                    if j < len(item) and item[j].kind == "punct" and item[j].text in "+-":
                        j += 1
                    j += 1
                col["default"] = " ".join(("'" + x.text.replace("'", "''") + "'") if x.kind == "string" else x.text for x in item[start:j])
            elif t.is_word("GENERATED") or t.is_word("AS"):
                if t.is_word("GENERATED"):
                    j += 2  # GENERATED ALWAYS
                j += 1  # AS
                if j < len(item) and item[j].is_punct("("):
                    j = _skip_parens(item, j)
                col["generated"] = "virtual"
                if j < len(item) and item[j].is_word("STORED", "VIRTUAL"):
                    col["generated"] = item[j].upper.lower()
                    j += 1
            elif t.is_word("CHECK") and j + 1 < len(item) and item[j + 1].is_punct("("):
                j = _skip_parens(item, j + 1)
            elif t.is_word("REFERENCES"):
                j += 2
                if j < len(item) and item[j].is_punct("("):
                    j = _skip_parens(item, j)
                while j < len(item) and item[j].is_word("ON", "MATCH", "NOT", "DEFERRABLE", "INITIALLY", "DEFERRED", "IMMEDIATE", "DELETE", "UPDATE", "SET", "NULL", "DEFAULT", "CASCADE", "RESTRICT", "NO", "ACTION"):
                    j += 1
            elif t.is_word("COLLATE"):
                j += 2
            else:
                j += 1
        columns.append(col)

    without_rowid = "WITHOUT" in tail and "ROWID" in tail
    strict = "STRICT" in tail
    pk_names: list[tuple[str, bool]] = table_pk or [(c["name"], c["pk_desc"]) for c in columns if c["pk"]]
    positions = {n.lower(): p for p, (n, _) in enumerate(pk_names, 1)}
    desc = {n.lower(): d for n, d in pk_names}
    alias_name = None
    if not without_rowid and len(pk_names) == 1:
        only = pk_names[0][0].lower()
        target = next((c for c in columns if c["name"].lower() == only), None)
        if target is not None and target["type"].strip().upper() == "INTEGER" and not desc[only]:
            alias_name = only
    defs = tuple(
        ColumnDef(
            index=i, name=c["name"], declared_type=c["type"], affinity=affinity_of(c["type"]),
            not_null=c["not_null"] or (without_rowid and c["name"].lower() in positions),  # WITHOUT ROWID keys are implicitly NOT NULL
            default_sql=c["default"], primary_key_position=positions.get(c["name"].lower(), 0), generated=c["generated"],
            is_rowid_alias=c["name"].lower() == alias_name,
        )
        for i, c in enumerate(columns)
    )
    return TableSql(name=name, columns=defs, without_rowid=without_rowid, virtual=False, autoincrement=autoincrement, strict=strict)
