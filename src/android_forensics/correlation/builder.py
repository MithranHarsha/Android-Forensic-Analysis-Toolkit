"""Building the evidence graph, and finding what independently supports each recovered record and carved candidate (Phase 7).

**Entities and edges.** Every artifact is a node (a message, a call, a contact, or a generic artifact); so are the phone
numbers, people, applications, databases and files they mention or live in, and -- where a carved value matches one -- URLs
and timestamps. Edges read ``source --relation--> target``:

======================  ==========================================================================================
``phone SENT message``   the number sent this (received) message              ``phone RECEIVED message``  outgoing
``phone CALLED call``    the number called (incoming / missed / rejected)     ``phone RECEIVED call``     outgoing
``contact CONTACT_OF``   the contact lists this phone number / is this person
``artifact FOUND_IN``    a live record of this database; ``database FOUND_IN application``
``RECOVERED_FROM``       a recovered record and the database / WAL / journal its bytes were found in
``CORRELATES_WITH``      a recovered record or carved candidate and an independent artifact that carries the same fact
======================  ==========================================================================================

One phone number is one node, whichever artifact it came from, so a number in the SMS store, the call log and the contacts is
visibly the same ``PhoneNumber`` entity (``normalization.phone_key``: the trailing ten digits; short codes and sender names
have no key and are never matched).

**Corroboration** is the input the confidence scorer wants: one sentence per *kind* of independent source. A source is
independent only if it lives in a different database from the thing it supports (a carved hit in the free space of ``x.db-wal``
is not corroborated by a live row of ``x.db``: that is the same file's own data). A recovered record's timestamp must also be
structurally valid for its matches to count -- a record whose date is impossible is linked, and flagged not corroborated.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from android_forensics.carving.rules import carved_timestamp
from android_forensics.correlation.facts import Facts, facts_of, normalise_text, normalise_url
from android_forensics.correlation.graph import EvidenceGraph, Node
from android_forensics.models import Artifact, CarvedCandidate, CarveKind, EntityKind, Relation
from android_forensics.normalization.phone import phone_key

MAX_LINKS_PER_KIND = 5
NEAR_SECONDS = 3600
_SIDECAR = re.compile(r"-(?:wal|journal|shm)$")
_ROLE_KIND = {"message": EntityKind.MESSAGE, "call": EntityKind.CALL, "contact": EntityKind.CONTACT}


def database_of(path: str) -> str:
    """The database a file belongs to: a ``-wal`` / ``-journal`` / ``-shm`` sidecar resolves to its main file."""
    return _SIDECAR.sub("", path)


@dataclass(frozen=True)
class FileInfo:
    id: int
    path: str
    kind: str = "file"  # database | sidecar | file
    application: str | None = None


@dataclass(frozen=True)
class Subject:
    """An artifact taking part in correlation. ``ref`` is ``artifact:<id>`` once stored, ``recovered:<record id>`` while it is a draft.

    Correlation needs only an artifact's *facts* (phones, names, URLs, text, moment), a label, its status and extraction method —
    not its raw row, provenance or confidence factors, which weigh ~17 KB per artifact once parsed into models. Callers that hold
    a million artifacts therefore pass the precomputed ``facts``/``summary``/``status``/``method`` with ``artifact=None`` and drop the
    heavy model immediately (see :meth:`slim`); tests and small callers can still pass the full artifact."""

    ref: str
    artifact: Artifact | None
    origin: str  # "active" | "recovered"
    database: str  # path of the database it belongs to
    file_id: int  # evidence file of that database
    found_in: int | None = None  # recovered only: evidence file whose bytes held it (the database itself, or a sidecar)
    precomputed: Facts | None = None
    summary_text: str | None = None
    status_value: str | None = None
    method_value: str | None = None

    @staticmethod
    def slim(ref: str, artifact: Artifact, origin: str, database: str, file_id: int, found_in: int | None = None) -> Subject:
        return Subject(ref, None, origin, database, file_id, found_in, facts_of(artifact), artifact.summary, artifact.status.value,
                       artifact.extraction_method.value)

    @property
    def facts(self) -> Facts:
        if self.precomputed is not None:
            return self.precomputed
        assert self.artifact is not None
        return facts_of(self.artifact)

    @property
    def label(self) -> str | None:
        return self.summary_text if self.artifact is None else self.artifact.summary

    @property
    def status(self) -> str:
        return self.status_value or (self.artifact.status.value if self.artifact is not None else "")

    @property
    def method(self) -> str:
        return self.method_value or (self.artifact.extraction_method.value if self.artifact is not None else "")


@dataclass(frozen=True)
class Corroboration:
    """What independently supports one recovered record or carved candidate, in the scorer's terms."""

    ref: str
    sources: tuple[str, ...] = ()  # one sentence per kind of independent source
    targets: tuple[str, ...] = ()  # refs of the artifacts that support it
    corroborated: bool = False
    notes: tuple[str, ...] = ()


@dataclass
class Correlation:
    graph: EvidenceGraph
    corroboration: dict[str, Corroboration] = field(default_factory=dict)

    def for_ref(self, ref: str) -> Corroboration:
        return self.corroboration.get(ref) or Corroboration(ref)


def _natural(ref: str) -> tuple[str, int]:
    head, _, tail = ref.partition(":")
    return head, int(tail) if tail.isdigit() else 0


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _names(names: list[str]) -> str:
    names = sorted(set(names))
    if len(names) == 1:
        return f"contact {names[0]}"
    if len(names) == 2:
        return f"contacts {names[0]} and {names[1]}"
    return f"contacts {names[0]}, {names[1]} and {len(names) - 2} more"


def _seconds(a: str | None, b: str | None) -> int | None:
    from datetime import datetime

    if a is None or b is None:
        return None
    try:
        return abs(int((datetime.fromisoformat(a) - datetime.fromisoformat(b)).total_seconds()))
    except ValueError:
        return None


def _gap(seconds: int) -> str:
    return f"{seconds} s" if seconds < 120 else f"{seconds // 60} min"


class _Builder:
    def __init__(self, subjects: Sequence[Subject], carved: Sequence[CarvedCandidate], files: Mapping[int, FileInfo]):
        self.g = EvidenceGraph()
        self.files = files
        self.subjects = sorted(subjects, key=lambda s: (s.origin != "active", _natural(s.ref)))
        self.carved = sorted(carved, key=lambda c: c.id or 0)
        self.facts: dict[str, Facts] = {s.ref: s.facts for s in self.subjects}
        self.nodes: dict[str, Node] = {}
        self.by_ref = {s.ref: s for s in self.subjects}
        self.active = [s for s in self.subjects if s.origin == "active"]
        self.result = Correlation(self.g)

    # ------------------------------------------------------------------ structure

    def file_node(self, file_id: int) -> Node:
        info = self.files.get(file_id)
        path = info.path if info else f"file {file_id}"
        kind = EntityKind.DATABASE if info and info.kind == "database" else EntityKind.FILE
        node = self.g.node(kind, f"{kind.value}:{file_id}", path)
        if info and info.application and kind is EntityKind.DATABASE:
            app = self.g.node(EntityKind.APPLICATION, f"app:{info.application}", info.application)
            self.g.add_edge(node, Relation.FOUND_IN, app, f"{path} is a database of {info.application}")
        return node

    def subject_nodes(self) -> None:
        for s in self.subjects:
            f = self.facts[s.ref]
            kind = _ROLE_KIND.get(f.role, EntityKind.ARTIFACT)
            node = self.nodes[s.ref] = self.g.node(kind, s.ref, s.label or s.ref, status=s.status,
                                                   origin=s.origin, database=s.database)
            if s.origin == "active":
                where = self.file_node(s.file_id)
                self.g.add_edge(node, Relation.FOUND_IN, where, f"{node.label!r} is a live record of {where.label}")
            else:
                where = self.file_node(s.found_in or s.file_id)
                self.g.add_edge(node, Relation.RECOVERED_FROM, where,
                                f"{node.label!r} was {s.status.lower()} from {where.label} ({s.method})",
                                status=s.status, method=s.method)

    def phone_edges(self) -> None:
        for s in self.subjects:
            f, node = self.facts[s.ref], self.nodes[s.ref]
            for key in f.phones:
                phone = self.g.node(EntityKind.PHONE_NUMBER, f"phone:{key}", key)
                if f.role == "contact":
                    name = f.names[0] if f.names else "an unnamed contact"
                    self.g.add_edge(node, Relation.CONTACT_OF, phone, f"contact {name} lists this number", contact=name)
                elif f.role == "message" and f.direction == "in":
                    self.g.add_edge(phone, Relation.SENT, node, "this number sent the message to the device", direction="incoming")
                elif f.role == "message" and f.direction == "out":
                    self.g.add_edge(phone, Relation.RECEIVED, node, "the device sent the message to this number", direction="outgoing")
                elif f.role == "call" and f.direction == "in":
                    self.g.add_edge(phone, Relation.CALLED, node, "this number called the device", direction="incoming")
                elif f.role == "call" and f.direction == "out":
                    self.g.add_edge(phone, Relation.RECEIVED, node, "the device called this number", direction="outgoing")
                else:
                    self.g.add_edge(phone, Relation.CORRELATES_WITH, node, "this number appears in the record (direction not known)")
            if f.role == "contact" and f.names:
                person = self.g.node(EntityKind.PERSON, f"person:{f.names[0].casefold()}", f.names[0])
                self.g.add_edge(node, Relation.CONTACT_OF, person, f"this contact entry is {f.names[0]}")

    # ------------------------------------------------------------------ supporting sources

    def _support_sentences(self, targets: list[Subject], anchor_moment: str | None, anchor_valid: bool | None) -> list[str]:
        """One sentence per kind of source among ``targets`` (already independent of the thing they support). A source that is
        itself only a recovered record says so: it is weaker corroboration than a live row."""
        out: list[str] = []
        for origin, prefix in (("active", ""), ("recovered", "recovered ")):
            group = [t for t in targets if t.origin == origin]
            contacts = [t for t in group if self.facts[t.ref].role == "contact"]
            calls = [t for t in group if self.facts[t.ref].role == "call"]
            messages = [t for t in group if self.facts[t.ref].role == "message"]
            if contacts:
                out.append(prefix + _names([self.facts[t.ref].names[0] if self.facts[t.ref].names else "(unnamed)" for t in contacts]))
            if calls:
                text = f"{prefix}call log ({_plural(len(calls), 'call', 'calls')} with this number"
                gaps = [g for g in (_seconds(anchor_moment, self.facts[t.ref].moment) for t in calls if anchor_moment and self.facts[t.ref].moment)
                        if g is not None] if anchor_valid is not False else []
                if gaps and min(gaps) <= NEAR_SECONDS:
                    text += f"; nearest {_gap(min(gaps))} from this record"
                out.append(text + ")")
            if messages:
                out.append(f"{prefix}SMS thread ({_plural(len(messages), 'message', 'messages')} with this number)")
        return out

    def _link(self, source: Node, targets: list[Subject], via: str, corroborated: bool, anchor_moment: str | None, **extra) -> None:
        strength = {"contact": 1.0, "call": 0.8, "message": 0.7}
        for role in ("contact", "call", "message"):
            group = [t for t in targets if self.facts[t.ref].role == role]

            def gap(t: Subject) -> tuple[int, tuple[str, int]]:
                g = _seconds(anchor_moment, self.facts[t.ref].moment) if anchor_moment and self.facts[t.ref].moment else None
                return (g if g is not None else 10**12, _natural(t.ref))

            for t in sorted(group, key=gap)[:MAX_LINKS_PER_KIND]:
                g = gap(t)[0]
                self.g.add_edge(source, Relation.CORRELATES_WITH, self.nodes[t.ref],
                                f"shares {via} with {self.nodes[t.ref].label!r}" + ("" if corroborated else " (not counted: see notes)"),
                                strength=strength[role], via=via, corroborated=corroborated,
                                nearest_seconds=None if g >= 10**12 else g, **extra)

    def corroborate_recovered(self) -> None:
        by_phone: dict[str, list[Subject]] = {}
        for s in self.active:
            for k in self.facts[s.ref].phones:
                by_phone.setdefault(k, []).append(s)
        for r in self.subjects:
            if r.origin != "recovered":
                continue
            f = self.facts[r.ref]
            found: dict[str, Subject] = {}
            via: list[str] = []
            for k in f.phones:
                for t in by_phone.get(k, ()):
                    if t.database != r.database and self.facts[t.ref].role != f.role:
                        found.setdefault(t.ref, t)
                        via.append(f"phone:{k}")
            targets = list(found.values())
            valid = f.moment_valid is not False
            notes: list[str] = []
            if targets and not valid:
                notes.append("its timestamp is outside the plausible window, so the matching artifacts are linked but not counted as corroboration")
            if targets:
                self._link(self.nodes[r.ref], targets, via[0], valid, f.moment, timestamp_valid=valid)
            sources = tuple(self._support_sentences(targets, f.moment, f.moment_valid)) if valid else ()
            self.result.corroboration[r.ref] = Corroboration(r.ref, sources, tuple(sorted(found, key=_natural)), bool(sources), tuple(notes))

    # ------------------------------------------------------------------ carved candidates

    def _independent(self, c: CarvedCandidate, targets: list[Subject]) -> list[Subject]:
        home = database_of(c.source_file)
        return [t for t in targets if database_of(t.database) != home]

    def _record_values(self, c: CarvedCandidate) -> list[str]:
        try:
            values = json.loads(c.matched)
        except ValueError:
            return []
        return [v for v in values if isinstance(v, str)] if isinstance(values, list) else []

    def corroborate_carved(self) -> None:
        phones: dict[str, list[Subject]] = {}
        urls: dict[str, list[Subject]] = {}
        emails: dict[str, list[Subject]] = {}
        moments: dict[str, list[Subject]] = {}
        bodies: dict[str, list[Subject]] = {}
        names: dict[str, list[Subject]] = {}
        for s in self.subjects:
            f = self.facts[s.ref]
            for k in f.phones:
                phones.setdefault(k, []).append(s)
            for u in f.urls:
                urls.setdefault(u, []).append(s)
            for e in f.emails:
                emails.setdefault(e, []).append(s)
            if f.moment:
                moments.setdefault(f.moment, []).append(s)
            for t in f.texts:
                bodies.setdefault(t, []).append(s)
            for n in f.names:
                names.setdefault(n.casefold(), []).append(s)
        for c in self.carved:
            ref = f"carved:{c.id}"
            node = self.g.node(EntityKind.CARVED, ref, f"{c.kind.value} {c.matched[:40]}", status=c.status, offset=c.offset)
            where = self.file_node(c.evidence_file_id)
            self.g.add_edge(node, Relation.FOUND_IN, where, f"carved at byte {c.offset} of {where.label}", offset=c.offset, length=c.length)
            found: list[Subject] = []
            sentences: list[str] = []
            if c.kind is CarveKind.PHONE_NUMBER:
                self._match_phone(c, node, phone_key(c.matched), phones, found, sentences)
            elif c.kind is CarveKind.URL:
                self._match_url(c, node, normalise_url(c.matched), urls, found, sentences)
            elif c.kind is CarveKind.EMAIL:
                self._match_email(c, node, c.matched.lower(), emails, found, sentences)
            elif c.kind in (CarveKind.TIMESTAMP_UNIX_SECONDS, CarveKind.TIMESTAMP_UNIX_MILLIS, CarveKind.TIMESTAMP_WEBKIT_MICROS,
                            CarveKind.TIMESTAMP_TEXT):
                moment = carved_timestamp(c.kind, c.matched)
                self._match_moment(c, node, moment.strftime("%Y-%m-%dT%H:%M:%S") if moment else None, moments, found, sentences)
            elif c.kind is CarveKind.SMS_LIKE_TEXT:
                self._match_body(c, node, normalise_text(c.matched), bodies, found, sentences)
            elif c.kind is CarveKind.SQLITE_RECORD:
                for value in self._record_values(c):
                    self._match_phone(c, node, phone_key(value), phones, found, sentences, quiet=True)
                    self._match_body(c, node, normalise_text(value), bodies, found, sentences, quiet=True)
                    for named in self._independent(c, names.get(value.casefold(), [])):
                        if named not in found:
                            found.append(named)
                            sentences.append(f"the contact name {value!r}")
                            self.g.add_edge(node, Relation.CORRELATES_WITH, self.nodes[named.ref], f"a text value of the record is the name of {named.label!r}",
                                            strength=0.5, value=value)
            unique = tuple(dict.fromkeys(sentences))
            self.result.corroboration[ref] = Corroboration(ref, unique, tuple(sorted({t.ref for t in found}, key=_natural)), bool(unique))

    def _match_phone(self, c, node, key, index, found, sentences, quiet: bool = False) -> None:
        if not key:
            return
        targets = self._independent(c, index.get(key, []))
        phone = self.g.find(EntityKind.PHONE_NUMBER, f"phone:{key}")
        if not targets or phone is None:
            return
        self.g.add_edge(node, Relation.CORRELATES_WITH, phone, f"the carved number is the number of {_plural(len(targets), 'artifact', 'artifacts')}",
                        strength=0.8, artifacts=[t.ref for t in targets][:20])
        found.extend(t for t in targets if t not in found)
        sentences.extend(self._support_sentences(targets, None, None))

    def _match_url(self, c, node, key, index, found, sentences) -> None:
        targets = self._independent(c, index.get(key, [])) if key else []
        if not targets:
            return
        url = self.g.node(EntityKind.URL, f"url:{key}", key)
        self.g.add_edge(node, Relation.CORRELATES_WITH, url, "the carved URL is the same address as a browser artifact", strength=0.8)
        for t in targets[:MAX_LINKS_PER_KIND]:
            self.g.add_edge(self.nodes[t.ref], Relation.CORRELATES_WITH, url, "this artifact visited or downloaded from this address", strength=0.8)
        found.extend(t for t in targets if t not in found)
        sentences.append(f"browser history ({_plural(len(targets), 'entry', 'entries')} for this address)")

    def _match_email(self, c, node, key, index, found, sentences) -> None:
        targets = self._independent(c, index.get(key, []))
        if not targets:
            return
        for t in targets[:MAX_LINKS_PER_KIND]:
            self.g.add_edge(node, Relation.CORRELATES_WITH, self.nodes[t.ref], "the carved address is listed by this contact", strength=1.0, address=key)
        found.extend(t for t in targets if t not in found)
        sentences.append(_names([self.facts[t.ref].names[0] if self.facts[t.ref].names else "(unnamed)" for t in targets]))

    def _match_moment(self, c, node, key, index, found, sentences) -> None:
        targets = self._independent(c, index.get(key, [])) if key else []
        if not targets:
            return
        stamp = self.g.node(EntityKind.TIMESTAMP, f"timestamp:{key}Z", f"{key}Z")
        self.g.add_edge(node, Relation.CORRELATES_WITH, stamp, "the carved value reads as this instant", strength=0.6)
        for t in targets[:MAX_LINKS_PER_KIND]:
            self.g.add_edge(self.nodes[t.ref], Relation.CORRELATES_WITH, stamp, "this artifact carries this instant", strength=0.6)
        found.extend(t for t in targets if t not in found)
        roles: dict[str, int] = {}
        for t in targets:
            roles[self.facts[t.ref].role] = roles.get(self.facts[t.ref].role, 0) + 1
        sentences.extend(f"the timestamp of {_plural(n, role, role + 's')}" for role, n in sorted(roles.items()))

    def _match_body(self, c, node, key, index, found, sentences, quiet: bool = False) -> None:
        targets = self._independent(c, index.get(key, [])) if key else []
        if not targets:
            return
        for t in targets[:MAX_LINKS_PER_KIND]:
            self.g.add_edge(node, Relation.CORRELATES_WITH, self.nodes[t.ref], "the carved text is this message's body", strength=0.9)
        found.extend(t for t in targets if t not in found)
        sentences.append(f"the body of {_plural(len(targets), 'message', 'messages')}")


def build_correlation(subjects: Sequence[Subject], carved: Sequence[CarvedCandidate] = (), files: Mapping[int, FileInfo] | None = None) -> Correlation:
    """The evidence graph for ``subjects`` (active artifacts and recovered drafts) and ``carved`` candidates, with what supports each."""
    b = _Builder(subjects, carved, files or {})
    b.subject_nodes()
    b.phone_edges()
    b.corroborate_recovered()
    b.corroborate_carved()
    return b.result
