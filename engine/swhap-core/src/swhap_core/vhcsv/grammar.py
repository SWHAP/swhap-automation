"""Canonical-profile parser / validator / writer (csv-contract §2–§10).

The single implementation of the canonical ``version_history.csv`` grammar
(``swhap_core.vhcsv``, core T4). The validator never re-implements this; its only
local CSV logic is the byte-exact header check (CSV-1). Everything here is
stdlib-only.

Public entry points:
  * :func:`parse_canonical` — strict parse/validate → :class:`ParseResult`
  * :func:`write` — the canonical (sole) writer; byte-identical output (§2.5)
  * :func:`validate_field` — the §8 field allowlist (reused by the legacy reader)
  * :func:`validate_tag` — §6 tag grammar (pure-Python ``check-ref-format``)
  * :func:`git_check_ref_format` — optional argv-only git cross-check
"""

from __future__ import annotations

import subprocess
import unicodedata
from dataclasses import dataclass

from .dates import parse_date
from .model import (
    CSV_DATE,
    CSV_DUP_DIR,
    CSV_DUP_TAG,
    CSV_DATE_ORDER,
    CSV_FIELD,
    CSV_HEADER,
    CSV_TAG,
    FAIL,
    INFO,
    WARN,
    Diagnostic,
    ParseResult,
    ParsedDate,
    Row,
)

import re as _re

# --- header (§2.1) ----------------------------------------------------------
CANONICAL_HEADER = (
    "directory name,date,author name,author email,"
    "curator name,curator email,release tag,commit message"
)
HEADER_BYTES = CANONICAL_HEADER.encode("ascii")
HEADER_SHA256 = "d8f5ae1f40f10667baa8f436b3fcfacc151d641d2fe26eb66650a6fb106e0b81"
BOM = b"\xef\xbb\xbf"

FIELD_NAMES = [
    "directory name",
    "date",
    "author name",
    "author email",
    "curator name",
    "curator email",
    "release tag",
    "commit message",
]
N_FIELDS = 8
_DATE_IDX = 1
_TAG_IDX = 6
_MESSAGE_IDX = 7
_NAME_IDXS = (2, 4)
_EMAIL_IDXS = (3, 5)
_DIR_IDX = 0
# Length caps in UTF-8 bytes (§8.1); date (idx 1) has its own grammar, no cap.
_LEN_CAPS = {0: 255, 2: 255, 3: 254, 4: 255, 5: 254, 6: 128, 7: 16384}

# Legacy header tokens (§11.0.1) — only used to add a canonical-profile hint.
_LEGACY_TOKENS = {
    "unipisa": ["directory name", "author name", "author email", "date",
                "curator name", "curator email", "release tag", "commit message"],
    "guide": ["directory name", "author name", "author email", "date original",
              "curator name", "curator email", "release tag", "commit message"],
}

# RFC 5322 bare addr-spec (§5.3); domain requires at least one dot.


_ADDR_SPEC = _re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)

# Forbidden characters in a tag (git check-ref-format consequences, §6.1).
_TAG_FORBIDDEN = set(" ~^:?*[\\\x7f") | {chr(c) for c in range(0x20)}


# ---------------------------------------------------------------------------
# RFC 4180 tokenizer (§2.4) — strict, byte-offset-free but row/column aware.
# ---------------------------------------------------------------------------
@dataclass
class RawField:
    value: str
    quoted: bool
    had_newline: bool  # an embedded line break occurred inside this quoted field


def _tokenize(body: str) -> tuple[list[list[RawField]], list[dict]]:
    """RFC 4180 record splitter. Returns ``(records, errors)`` where each error
    is ``{row, code, message, section}``. Embedded line breaks are accepted
    inside any quoted field at this layer and flagged per §2.4 by the caller
    (only ``commit message`` may carry them)."""
    records: list[list[RawField]] = []
    errors: list[dict] = []
    cur: list[RawField] = []
    val: list[str] = []
    in_q = False
    quoted = False
    had_nl = False
    started = False  # the current record has begun (content, comma, or quote)
    expect_sep = False  # we just closed a quoted field; only , or EOL may follow
    i, n = 0, len(body)

    def end_field() -> None:
        nonlocal val, quoted, had_nl, expect_sep
        cur.append(RawField("".join(val), quoted, had_nl))
        val = []
        quoted = False
        had_nl = False
        expect_sep = False

    def emit_record() -> None:
        nonlocal cur, started
        records.append(cur)
        cur = []
        started = False

    def err(code: str, msg: str, section: str) -> None:
        errors.append({"row": len(records) + 1, "code": code, "message": msg, "section": section})

    while i < n:
        c = body[i]
        if in_q:
            if c == '"':
                if i + 1 < n and body[i + 1] == '"':
                    val.append('"')
                    i += 2
                else:
                    in_q = False
                    expect_sep = True
                    i += 1
                continue
            if c == "\r":
                had_nl = True
                val.append("\n")
                i += 2 if (i + 1 < n and body[i + 1] == "\n") else 1
                continue
            if c == "\n":
                had_nl = True
                val.append("\n")
                i += 1
                continue
            val.append(c)
            i += 1
            continue

        # not in quotes
        if expect_sep:
            if c == ",":
                end_field()
                started = True
                i += 1
                continue
            if c == "\n":
                end_field()
                emit_record()
                i += 1
                continue
            if c == "\r":
                if i + 1 < n and body[i + 1] == "\n":
                    end_field()
                    emit_record()
                    i += 2
                    continue
                err(CSV_FIELD, "carriage return not followed by a line feed", "§2.3")
                end_field()
                emit_record()
                i += 1
                continue
            err(CSV_FIELD, "content between a closing quote and the next separator", "§2.4")
            expect_sep = False
            val.append(c)
            i += 1
            continue

        if c == '"':
            if not val and not quoted:
                in_q = True
                quoted = True
                started = True
                i += 1
                continue
            err(CSV_FIELD, "double quote inside an unquoted field", "§2.4")
            val.append(c)
            i += 1
            continue
        if c == ",":
            end_field()
            started = True
            i += 1
            continue
        if c == "\n":
            if not started and not val and not cur:
                err(CSV_FIELD, "blank line is not permitted", "§2.4")
            else:
                end_field()
                emit_record()
            i += 1
            continue
        if c == "\r":
            if i + 1 < n and body[i + 1] == "\n":
                if not started and not val and not cur:
                    err(CSV_FIELD, "blank line is not permitted", "§2.4")
                else:
                    end_field()
                    emit_record()
                i += 2
                continue
            err(CSV_FIELD, "carriage return not followed by a line feed", "§2.3")
            i += 1
            continue
        val.append(c)
        started = True
        i += 1

    if in_q:
        err(CSV_FIELD, "unterminated quoted field at end of file", "§2.4")
        end_field()
        emit_record()
    elif started or val or cur:
        end_field()
        emit_record()
    return records, errors


def quoting_needed(value: str) -> bool:
    return any(ch in value for ch in (",", '"', "\n", "\r"))


# ---------------------------------------------------------------------------
# §6 release-tag grammar
# ---------------------------------------------------------------------------
def validate_tag(tag: str) -> list[tuple[str, str]]:
    """Pure-Python ``git check-ref-format refs/tags/<tag>`` plus the reserved
    namespaces (§6.1–§6.2). Returns ``[(message, section)]`` of violations
    (code is always ``CSV-TAG``)."""
    errs: list[tuple[str, str]] = []
    if tag.startswith("candidate/") or tag.startswith("scratch/"):
        errs.append(("tag uses the reserved candidate/ or scratch/ namespace", "§6.2"))
    for ch in tag:
        if ch in _TAG_FORBIDDEN:
            disp = f"U+{ord(ch):04X}" if ord(ch) < 0x20 or ord(ch) == 0x7F else repr(ch)
            errs.append((f"tag contains a forbidden character {disp}", "§6.1"))
            break
    if tag == "@":
        errs.append(("tag may not be the single character '@'", "§6.1"))
    if ".." in tag:
        errs.append(("tag contains '..'", "§6.1"))
    if "@{" in tag:
        errs.append(("tag contains '@{'", "§6.1"))
    if tag.startswith("/") or tag.endswith("/") or "//" in tag:
        errs.append(("tag has a leading/trailing '/' or '//'", "§6.1"))
    if tag.endswith("."):
        errs.append(("tag ends with '.'", "§6.1"))
    for comp in tag.split("/"):
        if comp == "":
            continue
        if comp.startswith("."):
            errs.append((f"tag component {comp!r} starts with '.'", "§6.1"))
        if comp.endswith(".lock"):
            errs.append((f"tag component {comp!r} ends with '.lock'", "§6.1"))
    return errs


def git_check_ref_format(tag: str) -> bool:
    """Optional argv-only git cross-check (§6.1). Never the primary check (the
    pure-Python :func:`validate_tag` works without git); returns ``True`` if git
    is absent so it never overrides the pure-Python verdict."""
    try:
        p = subprocess.run(
            ["git", "check-ref-format", f"refs/tags/{tag}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, OSError):
        return True
    return p.returncode == 0


# ---------------------------------------------------------------------------
# §8 field allowlist (reused by the legacy reader)
# ---------------------------------------------------------------------------
def validate_field(idx: int, value: str) -> list[tuple[str, str, str, int | None, str | None]]:
    """Validate one field value against §3 / §5.3 / §8 (and §6 for the tag).
    Returns ``[(code, message, section, char_index, code_point)]``. The date
    column (idx 1) is validated separately via :func:`~.dates.parse_date`."""
    out: list[tuple[str, str, str, int | None, str | None]] = []
    is_message = idx == _MESSAGE_IDX

    if value == "":
        out.append((CSV_FIELD, "field is empty; all 8 fields are mandatory", "§3", None, None))
        return out

    # Cc / Cf scan (§8.1) — report the first offender, naming the code point.
    for k, ch in enumerate(value):
        cat = unicodedata.category(ch)
        if cat == "Cc":
            if is_message and ch == "\n":
                continue
            cp = _codepoint(ch)
            out.append((CSV_FIELD, f"control character {cp} is forbidden", "§8.1", k, cp))
            return out
        if cat == "Cf":
            cp = _codepoint(ch)
            out.append((CSV_FIELD, f"Unicode format character {cp} is forbidden", "§8.1", k, cp))
            return out

    if value != value.strip():
        out.append((CSV_FIELD, "field has leading or trailing whitespace", "§8.1", None, None))
        return out

    if idx != _MESSAGE_IDX and value.startswith("-"):
        out.append((CSV_FIELD, "leading '-' is forbidden (argv-injection hygiene)", "§8.1", 0, None))

    cap = _LEN_CAPS.get(idx)
    if cap is not None and len(value.encode("utf-8")) > cap:
        out.append((CSV_FIELD, f"field exceeds the {cap}-byte length cap", "§8.1", None, None))

    if idx == _DIR_IDX:
        out.extend(_check_dir(value))
    elif idx in _NAME_IDXS:
        if "<" in value or ">" in value:
            out.append((CSV_FIELD, "name contains '<' or '>' (git-ident-meaningful)", "§8.2", None, None))
    elif idx in _EMAIL_IDXS:
        if not _ADDR_SPEC.match(value):
            out.append((CSV_FIELD, "email is not a bare RFC 5322 addr-spec (local@domain)", "§5.3", None, None))
    elif idx == _TAG_IDX:
        for msg, section in validate_tag(value):
            out.append((CSV_TAG, msg, section, None, None))
    return out


def _check_dir(value: str) -> list[tuple[str, str, str, int | None, str | None]]:
    out: list[tuple[str, str, str, int | None, str | None]] = []
    if "/" in value or "\\" in value:
        out.append((CSV_FIELD, "directory name must be a single path component (no '/' or '\\')", "§8.2", None, None))
    if value in (".", ".."):
        out.append((CSV_FIELD, "directory name may not be '.' or '..'", "§8.2", None, None))
    if value.startswith("."):
        out.append((CSV_FIELD, "directory name may not start with '.' (hidden dir)", "§8.2", None, None))
    if ":" in value:
        out.append((CSV_FIELD, "directory name may not contain ':'", "§8.2", None, None))
    return out


def _codepoint(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        name = ""
    return f"U+{ord(ch):04X}" + (f" {name}" if name else "")


def _fold(value: str) -> str:
    """Collision-folding basis: ``casefold(NFC(value))`` (§7.1)."""
    return unicodedata.normalize("NFC", value).casefold()


# ---------------------------------------------------------------------------
# canonical profile parse (§2–§10)
# ---------------------------------------------------------------------------
def _legacy_match(tokens: list[str]) -> str | None:
    norm = [t.strip().casefold() for t in tokens]
    for name, ref in _LEGACY_TOKENS.items():
        if norm == [t.casefold() for t in ref]:
            return name
    return None


def _resolve_reference(reference_date) -> tuple[int | None, bool]:
    """Resolve the §4.5 reference timestamp. Returns ``(epoch_or_None,
    skipped)``. ``skipped`` is True iff no reference was supplied."""
    if reference_date is None:
        return None, True
    if isinstance(reference_date, ParsedDate):
        return reference_date.epoch_seconds, False
    if isinstance(reference_date, str):
        pd, errs = parse_date(reference_date)
        if pd is None or pd.precision != "second":
            raise ValueError("reference-date must be a full §4.1 timestamp (YYYY-MM-DDTHH:MM:SS±HH:MM)")
        return pd.epoch_seconds, False
    raise TypeError("reference_date must be None, a str timestamp, or a ParsedDate")


def parse_canonical(data: bytes, *, reference_date=None) -> ParseResult:
    """Parse and strictly validate canonical-profile CSV bytes (§2–§10)."""
    diags: list[Diagnostic] = []
    rows: list[Row] = []

    # §2.2 BOM — must be the first, actionable diagnostic.
    if data.startswith(BOM):
        diags.append(Diagnostic(
            CSV_HEADER, FAIL,
            "file starts with a UTF-8 BOM — remove it", "§2.2"))
        return ParseResult("canonical", rows, diags)

    # §2.2 UTF-8.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        diags.append(Diagnostic(
            CSV_FIELD, FAIL,
            f"file is not valid UTF-8 at byte offset {e.start}", "§2.2",
            byte_offset=e.start))
        return ParseResult("canonical", rows, diags)

    # §2.1 byte-exact header (compare raw bytes; tolerate a CRLF terminator).
    nl = data.find(b"\n")
    header_bytes = (data if nl < 0 else data[:nl]).rstrip(b"\r")
    if header_bytes != HEADER_BYTES:
        diags.append(_header_diag(header_bytes))
        return ParseResult("canonical", rows, diags)

    body = "" if nl < 0 else text.split("\n", 1)[1]
    records, tok_errors = _tokenize(body)
    for te in tok_errors:
        diags.append(Diagnostic(te["code"], FAIL, te["message"], te["section"], row=te["row"]))

    if not records:
        diags.append(Diagnostic(
            CSV_FIELD, FAIL,
            "header-only file: at least one data row is required", "§7"))
        return ParseResult("canonical", rows, diags)

    ref_epoch, skipped = _resolve_reference(reference_date)
    if skipped:
        diags.append(Diagnostic(
            CSV_DATE, INFO,
            "future-date check skipped: no reference timestamp — pass "
            "--reference-date or validate inside a workbench", "§4.5"))

    unnecessary_quote = False
    prev_epoch: int | None = None

    for ri, rec in enumerate(records, start=1):
        if len(rec) != N_FIELDS:
            diags.append(Diagnostic(
                CSV_FIELD, FAIL,
                f"record has {len(rec)} fields; exactly {N_FIELDS} are required",
                "§2.4", row=ri))
            continue

        for ci, fld in enumerate(rec):
            if fld.had_newline and ci != _MESSAGE_IDX:
                diags.append(Diagnostic(
                    CSV_FIELD, FAIL,
                    "embedded line break is only permitted in the commit message field",
                    "§2.4", row=ri, column=ci + 1, field_name=FIELD_NAMES[ci]))
            if fld.quoted and not quoting_needed(fld.value):
                unnecessary_quote = True

        vals = [f.value for f in rec]
        row_failed = False

        for idx in range(N_FIELDS):
            if idx == _DATE_IDX:
                continue
            for code, msg, section, ci_idx, cp in validate_field(idx, vals[idx]):
                row_failed = True
                diags.append(Diagnostic(
                    code, FAIL, msg, section, row=ri, column=idx + 1,
                    field_name=FIELD_NAMES[idx], char_index=ci_idx, code_point=cp))

        # §6.3 project-convention lint (INFO only; never a failure).
        if not vals[_TAG_IDX].startswith("-") and not _re.match(r"^v\d", vals[_TAG_IDX]):
            if not validate_tag(vals[_TAG_IDX]):
                diags.append(Diagnostic(
                    CSV_TAG, INFO,
                    f"tag {vals[_TAG_IDX]!r} does not use the v<version> convention "
                    "(valid; INFO only)", "§6.3", row=ri, column=_TAG_IDX + 1,
                    field_name=FIELD_NAMES[_TAG_IDX]))

        # date (§4)
        pd, date_errs = parse_date(vals[_DATE_IDX])
        if pd is None:
            row_failed = True
            for code, msg, section in date_errs:
                diags.append(Diagnostic(
                    code, FAIL, msg, section, row=ri, column=_DATE_IDX + 1,
                    field_name="date"))
        else:
            if ref_epoch is not None and pd.epoch_seconds > ref_epoch:
                row_failed = True
                diags.append(Diagnostic(
                    CSV_DATE, FAIL,
                    f"release date {vals[_DATE_IDX]!r} is in the future relative to "
                    "the reference timestamp", "§4.5", row=ri, column=_DATE_IDX + 1,
                    field_name="date"))
            else:
                # §7 date-monotonicity WARN (raises nothing).
                if prev_epoch is not None and pd.epoch_seconds < prev_epoch:
                    diags.append(Diagnostic(
                        CSV_DATE_ORDER, WARN,
                        f"date {vals[_DATE_IDX]!r} is earlier than the previous row "
                        "(suspicious but may be true history)", "§7", row=ri,
                        column=_DATE_IDX + 1, field_name="date"))
                prev_epoch = pd.epoch_seconds

        if row_failed or pd is None:
            continue

        notes: list[str] = []
        if pd.precision == "day":
            notes.append("time-of-day not asserted (precision: day)")
        elif pd.precision == "year":
            notes.append("month/day not asserted; inferred YYYY-01-01 (precision: year)")

        rows.append(Row(
            directory_name=vals[0], date=pd, author_name=vals[2], author_email=vals[3],
            curator_name=vals[4], curator_email=vals[5], release_tag=vals[6],
            commit_message=vals[7], row_number=ri, date_raw=vals[_DATE_IDX],
            provenance="user-provided", notes=tuple(notes)))

    if unnecessary_quote:
        diags.append(Diagnostic(
            CSV_FIELD, INFO,
            "not in canonical writer form — re-serialize with the vhcsv writer "
            "for diff-stable bytes", "§2.4"))

    _check_uniqueness(rows, diags)
    return ParseResult("canonical", rows, diags)


def _header_diag(header_bytes: bytes) -> Diagnostic:
    hint = ""
    try:
        tokens = next(__import__("csv").reader([header_bytes.decode("utf-8")]))
    except Exception:
        tokens = header_bytes.decode("utf-8", "replace").split(",")
    legacy = _legacy_match(tokens)
    if legacy:
        hint = " — legacy Unipisa/guide dialect: use `swhap csv convert --from unipisa`"
    return Diagnostic(
        CSV_HEADER, FAIL,
        "header is not byte-exact for the canonical profile" + hint, "§2.1")


def _check_uniqueness(rows: list[Row], diags: list[Diagnostic]) -> None:
    """§7 / §7.1 — collision folding, not byte equality."""
    for attr, code, label in (
        ("directory_name", CSV_DUP_DIR, "directory name"),
        ("release_tag", CSV_DUP_TAG, "release tag"),
    ):
        seen: dict[str, Row] = {}
        for r in rows:
            value = getattr(r, attr)
            folded = _fold(value)
            if folded in seen:
                first = seen[folded]
                diags.append(Diagnostic(
                    code, FAIL,
                    f"{label} collides under casefold(NFC(·)): row {first.row_number} "
                    f"{getattr(first, attr)!r} and row {r.row_number} {value!r}",
                    "§7.1", row=r.row_number,
                    extra={"other_row": first.row_number}))
            else:
                seen[folded] = r


# ---------------------------------------------------------------------------
# canonical writer (§2.5, §4.6) — the sole writer; byte-identical output
# ---------------------------------------------------------------------------
def _quote(value: str) -> str:
    if quoting_needed(value):
        return '"' + value.replace('"', '""') + '"'
    return value


def write(rows) -> bytes:
    """Serialize rows to canonical bytes: UTF-8, no BOM, LF terminator on every
    record including the last, minimal quoting, precision-preserving dates
    (§2.5). Two conforming writers produce byte-identical files."""
    lines = [CANONICAL_HEADER]
    for r in rows:
        lines.append(",".join(_quote(v) for v in r.fields()))
    return ("\n".join(lines) + "\n").encode("utf-8")
