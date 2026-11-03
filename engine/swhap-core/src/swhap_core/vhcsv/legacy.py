"""Legacy Unipisa/DT2SG + guide dialect — READ-ONLY converter (csv-contract §11).

D2: the legacy dialect is supported read-only; **no writer exists and none will
be built**. This module converts legacy bytes INTO canonical in-memory
:class:`Row` objects, flagging every lossy or ambiguous conversion. Consumers:
``swhap csv convert --from unipisa`` and the validator's ``legacy`` audit
profile. Every converted field carries provenance state ``computed`` plus a
conversion note (§11). The conversion **exits 0** even with a worklist of review
items (§10); only an unrecognized header FAILs.
"""

from __future__ import annotations

import re
from datetime import datetime

from .dates import parse_date
from .grammar import (
    FIELD_NAMES,
    N_FIELDS,
    _legacy_match,
    _tokenize,
    validate_field,
)
from .model import (
    CSV_AMBIGUOUS_US_DATE,
    CSV_HEADER,
    FAIL,
    WARN,
    Diagnostic,
    ParseResult,
    ParsedDate,
    Row,
    Worklist,
)

BOM = b"\xef\xbb\xbf"

# §5.1 placeholder domains (the validator's data/placeholder_domains.json is the
# shared tracked source; this is the documented default member set).
DEFAULT_PLACEHOLDER_DOMAINS = ("noreply.example.org", "noreply.example.com")

# Legacy field positions → canonical Row construction (§11.1). Legacy order is
# dir, author-name, author-email, date, curator-name, curator-email, tag, msg.
_L_DIR, _L_ANAME, _L_AEMAIL, _L_DATE, _L_CNAME, _L_CEMAIL, _L_TAG, _L_MSG = range(8)

_RE_SLASH = re.compile(
    r"^(\d{1,2})/(\d{1,2})/(\d{4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?$"
)
_RE_ISO_NAIVE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})$")
_EPOCH = datetime(1970, 1, 1)


def _epoch(dt: datetime, offset_minutes: int = 0) -> int:
    return int((dt - _EPOCH).total_seconds()) - offset_minutes * 60


# ---------------------------------------------------------------------------
# §11.2 / §11.3 legacy date conversion
# ---------------------------------------------------------------------------
def convert_legacy_date(s: str):
    """Convert a legacy date token. Returns ``(ParsedDate|None, info)`` where
    ``info`` is a dict with keys ``ambiguous`` (bool), ``alt_iso`` (str|None),
    ``notes`` (list[str]), ``worklist`` (str|None)."""
    info = {"ambiguous": False, "alt_iso": None, "notes": [], "worklist": None}

    m = _RE_SLASH.match(s)
    if m:
        a, b, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hh, mm, ss = m.group(4), m.group(5), m.group(6)
        if 1 <= a <= 12 and 1 <= b <= 12:
            month, day = a, b  # ambiguous → US MM/DD
            info["ambiguous"] = True
            info["alt_iso"] = f"{year:04d}-{b:02d}-{a:02d}"  # the DD/MM alternate
        elif 13 <= a <= 31 and 1 <= b <= 12:
            month, day = b, a  # unambiguous DD/MM (A=day)
        elif 1 <= a <= 12 and 13 <= b <= 31:
            month, day = a, b  # unambiguous MM/DD (A=month)
        else:
            info["worklist"] = f"slash date {s!r} is not a valid calendar date under either reading"
            return None, info
        try:
            if hh is not None:
                sec = int(ss) if ss is not None else 0
                dt = datetime(year, month, day, int(hh), int(mm), sec)
                pd = ParsedDate(_epoch(dt), 0, "second")
                info["notes"].append("timezone unknown in legacy source; UTC assumed")
                if ss is None:
                    info["notes"].append("seconds absent in legacy source; zero-filled to :00")
            else:
                dt = datetime(year, month, day)
                pd = ParsedDate(_epoch(dt), 0, "day")
        except ValueError:
            info["worklist"] = f"slash date {s!r} is not a valid calendar date"
            return None, info
        return pd, info

    # ISO-shaped naive (newer legacy files): UTC assumed, NOT CSV-TZ on this path.
    m = _RE_ISO_NAIVE.match(s)
    if m:
        y, mo, d, h, mi, se = (int(g) for g in m.groups())
        try:
            dt = datetime(y, mo, d, h, mi, se)
        except ValueError:
            info["worklist"] = f"ISO date {s!r} is not a valid calendar date/time"
            return None, info
        info["notes"].append("timezone unknown in legacy source; UTC assumed")
        return ParsedDate(_epoch(dt), 0, "second"), info

    # ISO with offset / date-only / year-only — convert unchanged via §4 grammar.
    pd, errs = parse_date(s)
    if pd is not None:
        return pd, info

    info["worklist"] = (
        f"date {s!r} is not a pinned legacy shape (4-digit-year slash date or "
        "ISO date) — supply an unambiguous canonical date"
    )
    return None, info


def _is_placeholder(email: str, domains) -> bool:
    at = email.rfind("@")
    if at < 0:
        return False
    return email[at + 1:].lower() in domains


# ---------------------------------------------------------------------------
# converter
# ---------------------------------------------------------------------------
def convert(data: bytes, *, dialect: str | None = None,
            placeholder_domains=DEFAULT_PLACEHOLDER_DOMAINS) -> ParseResult:
    """Convert legacy CSV bytes to canonical rows (§11). Never writes legacy."""
    diags: list[Diagnostic] = []
    worklist: list[Worklist] = []
    rows: list[Row] = []

    # §11.4 file-level tolerances: BOM stripped+flagged, latin-1 fallback flagged.
    if data.startswith(BOM):
        worklist.append(Worklist("bom", "legacy file started with a UTF-8 BOM (stripped on read)"))
        data = data[len(BOM):]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
        worklist.append(Worklist("latin1", "legacy file is not UTF-8; decoded as latin-1 (1990s material)"))

    nl = text.find("\n")
    header_line = (text if nl < 0 else text[:nl]).rstrip("\r")
    try:
        tokens = next(__import__("csv").reader([header_line]))
    except Exception:
        tokens = header_line.split(",")
    matched = _legacy_match(tokens)
    if matched is None:
        diags.append(Diagnostic(
            CSV_HEADER, FAIL,
            "header matches no recognized legacy dialect. Recognized: "
            "unipisa `directory name,author name,author email,date,...` and "
            "guide `directory name,author name,author email,date original,...`",
            "§11.0.1"))
        return ParseResult("legacy", rows, diags, worklist)
    # --from unipisa accepts both legacy dialects (the flag names the profile,
    # not a single header — §11.0.1); ``dialect`` is advisory only.

    body = "" if nl < 0 else text.split("\n", 1)[1]
    records, tok_errors = _tokenize(body)
    for te in tok_errors:
        worklist.append(Worklist("malformed", te["message"], row=te["row"]))

    for ri, rec in enumerate(records, start=1):
        if len(rec) != N_FIELDS:
            worklist.append(Worklist(
                "arity", f"legacy record has {len(rec)} fields; expected {N_FIELDS}", row=ri))
            continue
        raw = [f.value for f in rec]
        stripped = [v.strip() for v in raw]
        for j, (a, b) in enumerate(zip(raw, stripped)):
            if a != b:
                worklist.append(Worklist(
                    "stripped", f"edge whitespace stripped from legacy field {j + 1}", row=ri))

        dirname = stripped[_L_DIR]
        aname = stripped[_L_ANAME]
        aemail = stripped[_L_AEMAIL]
        cname = stripped[_L_CNAME]
        cemail = stripped[_L_CEMAIL]

        # §11.1.1 release-tag conversion (three cases)
        legacy_tag = stripped[_L_TAG]
        if legacy_tag == "*":
            tag = dirname
            note_tag = "tag derived from directory name (legacy *)"
        elif legacy_tag == "":
            worklist.append(Worklist(
                "empty-tag",
                f"legacy row {dirname!r} has an empty release tag (non-release "
                "directory) — no canonical release row produced; if this directory "
                "IS a release, supply a tag", row=ri, field_name="release tag"))
            continue
        else:
            tag = legacy_tag
            note_tag = None

        # §11.1 message: every '|' → LF (DT2SG separator), strip
        msg = stripped[_L_MSG].replace("|", "\n").strip()
        msg_note = "legacy '|' separators converted to line breaks" if "|" in raw[_L_MSG] else None

        # §11.2/§11.3 date
        pd, dinfo = convert_legacy_date(stripped[_L_DATE])
        if dinfo["ambiguous"]:
            diags.append(Diagnostic(
                CSV_AMBIGUOUS_US_DATE, WARN,
                f"ambiguous slash date {stripped[_L_DATE]!r}: applied US MM/DD "
                f"(alternate reading {dinfo['alt_iso']})", "§11.3", row=ri,
                field_name="date", extra={"alternate": dinfo["alt_iso"]}))
        if pd is None:
            worklist.append(Worklist("undated", dinfo["worklist"], row=ri, field_name="date"))
            continue

        # candidate canonical values; validate each non-date field (§8). Any
        # canonical-grammar violation routes to the worklist (never a FAIL): the
        # converter exits 0 (§11.4).
        cand = [dirname, stripped[_L_DATE], aname, aemail, cname, cemail, tag, msg]
        blocking = False
        for idx in range(N_FIELDS):
            if idx == 1:
                continue
            for code, m_, section, ci, cp in validate_field(idx, cand[idx]):
                blocking = True
                worklist.append(Worklist(
                    "needs-repair", f"{FIELD_NAMES[idx]}: {m_} ({section})", row=ri,
                    field_name=FIELD_NAMES[idx], extra={"code": code}))

        # non-blocking PI-1 flags: real (non-placeholder) emails (§5.1, crit-M15)
        for label, em in (("author email", aemail), ("curator email", cemail)):
            if em and not _is_placeholder(em, placeholder_domains):
                worklist.append(Worklist(
                    "real-email",
                    f"{label} {em!r} is a real address — PI-1 review (canonical "
                    "default is a placeholder/opt-in)", row=ri, field_name=label))

        if blocking:
            continue

        notes = []
        if note_tag:
            notes.append(note_tag)
        if msg_note:
            notes.append(msg_note)
        notes.extend(dinfo["notes"])
        if pd.precision == "day":
            notes.append("time-of-day not asserted (precision: day)")
        elif pd.precision == "year":
            notes.append("month/day not asserted; inferred (precision: year)")

        rows.append(Row(
            directory_name=dirname, date=pd, author_name=aname, author_email=aemail,
            curator_name=cname, curator_email=cemail, release_tag=tag,
            commit_message=msg, row_number=ri, date_raw=stripped[_L_DATE],
            provenance="computed", notes=tuple(notes)))

    return ParseResult("legacy", rows, diags, worklist)
