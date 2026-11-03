"""Conformance suite for ``swhap_core.vhcsv`` against the FROZEN csv-contract.md.

Covers: the §12.1 valid file (V1–V6, every convention), the §12.3 invalid rows
(I1–I22 each hitting a named rule), the WARN rows (W1 monotonicity), the legacy
profile (§12.2 conversion fixture, W2 ambiguous, N1 unambiguous, N2 empty tag),
the INFO notes (INFO1/INFO2), determinism / round-trip laws (§2.5, §4.6), the
pre-1970 negative epoch (§4.4) and the real Wild_LIFE 0.90/0.91 same-date rows.
"""

from __future__ import annotations

import hashlib
import pytest

from swhap_core import errors, vhcsv
from swhap_core.vhcsv import model

# --- the §12.1 canonical valid file (real Wild_LIFE regeneration data) -------
VALID = (
    "directory name,date,author name,author email,curator name,curator email,release tag,commit message\n"
    "0.90,1993-08-09,Wild_LIFE authors,wildlife-authors@noreply.example.org,Roberto Di Cosmo,roberto@dicosmo.org,v0.90,Wild_LIFE 0.90 first public release\n"
    "0.91,1993-08-09,Wild_LIFE authors,wildlife-authors@noreply.example.org,Roberto Di Cosmo,roberto@dicosmo.org,v0.91,Wild_LIFE 0.91\n"
    '1.0,1994-03-24,Wild_LIFE authors,wildlife-authors@noreply.example.org,Roberto Di Cosmo,roberto@dicosmo.org,v1.0,"Wild_LIFE 1.0\n\nLicense copyright year updated 1992 -> 1993.\nCo-authored-by: Peter Van Roy <pvr@noreply.example.org>"\n'
    "1.02,1995,Wild_LIFE authors,wildlife-authors@noreply.example.org,Roberto Di Cosmo,roberto@dicosmo.org,v1.02,Wild_LIFE 1.02 (Ultrix port; author-supplied tarball via PR #1)\n"
    "Softi-1968,1968-07-01,Softi authors,softi-authors@noreply.example.org,Example Curator,example-curator@noreply.example.org,v1968,Softi for CEP pre-epoch author date exercise\n"
    '2.0-beta,1996-11-05T14:30:00+01:00,"Herve, Jean-Claude",jc-herve@noreply.example.org,Example Curator,example-curator@noreply.example.org,2.0-beta,- full timestamp with offset; quoted comma in author name; leading-dash message\n'
).encode("utf-8")

# A header-only mutation point: the canonical header bytes.
HEADER = vhcsv.CANONICAL_HEADER + "\n"


def _row(dirn="prj", date="1994-03-24", an="Prj authors", ae="prj-authors@noreply.example.org",
         cn="Curator", ce="curator@noreply.example.org", tag="v1.0", msg="release"):
    return f"{dirn},{date},{an},{ae},{cn},{ce},{tag},{msg}"


def _file(*rows):
    return (HEADER + "\n".join(rows) + "\n").encode("utf-8")


# ===========================================================================
# Header / encoding (§2.1, §2.2)
# ===========================================================================
def test_header_sha256_matches_contract():
    assert hashlib.sha256(vhcsv.HEADER_BYTES).hexdigest() == vhcsv.HEADER_SHA256
    assert len(vhcsv.HEADER_BYTES) == 98


def test_I1_seven_column_exemplar_header_fails():
    data = b"version,date,source_url,filename,sha256,authors,notes\n1,2,3,4,5,6,7\n"
    r = vhcsv.parse(data)
    assert not r.ok
    assert r.failures[0].code == vhcsv.CSV_HEADER


def test_I2_bom_header_fails_with_named_bom():
    data = b"\xef\xbb\xbf" + VALID
    r = vhcsv.parse(data)
    assert not r.ok
    d = r.failures[0]
    assert d.code == vhcsv.CSV_HEADER
    assert "BOM" in d.message


def test_I3_legacy_header_under_canonical_fails_with_hint():
    data = (
        "directory name,author name,author email,date,curator name,curator email,release tag,commit message\n"
        "1.1,A,a@noreply.example.org,1994-01-01,C,c@noreply.example.org,v1,msg\n"
    ).encode("utf-8")
    r = vhcsv.parse(data)
    assert r.failures[0].code == vhcsv.CSV_HEADER
    assert "convert --from unipisa" in r.failures[0].message


def test_I22_guide_dialect_header_under_canonical_fails_with_hint():
    data = (
        "directory name,author name,author email,date original,curator name,curator email,release tag,commit message\n"
        "1.1,A,a@noreply.example.org,1994-01-01,C,c@noreply.example.org,v1,msg\n"
    ).encode("utf-8")
    r = vhcsv.parse(data)
    assert r.failures[0].code == vhcsv.CSV_HEADER
    assert "convert --from unipisa" in r.failures[0].message


def test_non_utf8_is_csv_field_with_byte_offset():
    data = HEADER.encode("utf-8") + b"prj,1994-01-01,A\xff,a@noreply.example.org,C,c@noreply.example.org,v1,msg\n"
    r = vhcsv.parse(data)
    assert not r.ok
    assert r.failures[0].code == vhcsv.CSV_FIELD
    assert r.failures[0].byte_offset is not None


def test_header_only_file_fails():
    r = vhcsv.parse(HEADER.encode("utf-8"))
    assert not r.ok
    assert r.failures[0].code == vhcsv.CSV_FIELD
    assert "at least one data row" in r.failures[0].message


def test_crlf_terminators_tolerated_on_read():
    data = VALID.replace(b"\n", b"\r\n")
    r = vhcsv.parse(data)
    assert r.ok, [d.message for d in r.failures]
    assert len(r.rows) == 6


# ===========================================================================
# Valid file V1–V6 (§12.1)
# ===========================================================================
def test_valid_file_parses_clean():
    r = vhcsv.parse(VALID)
    assert r.ok, [d.to_json() for d in r.failures]
    assert len(r.rows) == 6


def test_V1_date_only_day_precision_flagged():
    r = vhcsv.parse(VALID)
    v1 = r.rows[0]
    assert v1.directory_name == "0.90"
    assert v1.date.precision == "day"
    assert v1.date.offset_minutes == 0
    assert any("time-of-day" in n for n in v1.notes)


def test_V2_same_date_as_V1_is_legal():
    r = vhcsv.parse(VALID)
    assert r.rows[0].date.epoch_seconds == r.rows[1].date.epoch_seconds
    # equal dates do NOT trip CSV-DATE-ORDER
    assert not any(d.code == vhcsv.CSV_DATE_ORDER and d.row == 2 for d in r.warnings)


def test_V3_multiline_quoted_message_with_trailer():
    r = vhcsv.parse(VALID)
    v3 = r.rows[2]
    assert "\n\n" in v3.commit_message
    assert v3.commit_message.startswith("Wild_LIFE 1.0")
    assert "Co-authored-by: Peter Van Roy" in v3.commit_message


def test_V4_year_only_inferred_and_roundtrips_to_year():
    r = vhcsv.parse(VALID)
    v4 = r.rows[3]
    assert v4.date.precision == "year"
    assert v4.date.inferred is True
    assert v4.date.serialize() == "1995"  # never expanded (§4.6)
    # internal instant is 1995-01-01T00:00:00+00:00
    assert model.ParsedDate(v4.date.epoch_seconds, 0, "second").serialize() == "1995-01-01T00:00:00+00:00"


def test_V5_pre1970_negative_epoch():
    r = vhcsv.parse(VALID)
    v5 = r.rows[4]
    assert v5.date.epoch_seconds < 0
    assert v5.date.git_author_date().startswith("@-")


def test_V6_full_timestamp_offset_and_quoted_comma_name():
    r = vhcsv.parse(VALID)
    v6 = r.rows[5]
    assert v6.author_name == "Herve, Jean-Claude"
    assert v6.date.precision == "second"
    assert v6.date.offset_minutes == 60
    assert v6.date.serialize() == "1996-11-05T14:30:00+01:00"
    # bare tag → INFO only, never FAIL
    assert any(d.severity == vhcsv.INFO and d.row == 6 for d in r.diagnostics)


# ===========================================================================
# Determinism / round-trip laws (§2.5, §4.6)
# ===========================================================================
def test_write_roundtrip_byte_stable():
    r = vhcsv.parse(VALID)
    out1 = vhcsv.write(r.rows)
    r2 = vhcsv.parse(out1)
    assert r2.ok
    assert vhcsv.write(r2.rows) == out1  # write→parse→write identity on bytes


def test_writer_uses_offset_not_Z():
    pd = vhcsv.parse_date("2000-01-01T00:00:00Z")[0]
    assert pd.serialize() == "2000-01-01T00:00:00+00:00"


def test_writer_minimal_quoting():
    r = vhcsv.parse(VALID)
    out = vhcsv.write(r.rows).decode("utf-8")
    # the simple author label is never quoted; the comma name always is
    assert "Wild_LIFE authors," in out
    assert '"Herve, Jean-Claude"' in out


def test_parse_write_parse_identity_on_triple():
    r = vhcsv.parse(VALID)
    out = vhcsv.write(r.rows)
    r2 = vhcsv.parse(out)
    for a, b in zip(r.rows, r2.rows):
        assert (a.date.epoch_seconds, a.date.offset_minutes, a.date.precision) == (
            b.date.epoch_seconds, b.date.offset_minutes, b.date.precision)


# ===========================================================================
# Invalid rows I4–I20 (§12.3) — each hits a named rule
# ===========================================================================
def test_I4_naive_timestamp_is_csv_tz():
    r = vhcsv.parse(_file(_row(date="1994-03-24T10:00:00")))
    assert any(d.code == vhcsv.CSV_TZ for d in r.failures)


def test_I5_us_form_date_is_csv_date():
    r = vhcsv.parse(_file(_row(date="08/09/1993")))
    assert any(d.code == vhcsv.CSV_DATE for d in r.failures)


def test_I6_impossible_calendar_date_is_csv_date():
    r = vhcsv.parse(_file(_row(date="1994-02-30")))
    assert any(d.code == vhcsv.CSV_DATE for d in r.failures)


def test_I7_duplicate_tag_is_csv_dup_tag():
    r = vhcsv.parse(_file(_row(dirn="a", tag="v1.0"), _row(dirn="b", tag="v1.0")))
    assert any(d.code == vhcsv.CSV_DUP_TAG for d in r.failures)


def test_I8_duplicate_dir_is_csv_dup_dir():
    r = vhcsv.parse(_file(_row(dirn="1.0", tag="v1.0"), _row(dirn="1.0", tag="v2.0")))
    assert any(d.code == vhcsv.CSV_DUP_DIR for d in r.failures)


@pytest.mark.parametrize("tag", ["v1.0..final", "candidate/v1.0", "scratch/x", "v1.0.lock", "v 1.0"])
def test_I9_bad_tags_are_csv_tag(tag):
    r = vhcsv.parse(_file(_row(tag=tag)))
    assert any(d.code == vhcsv.CSV_TAG for d in r.failures), tag


def test_I10_leading_dash_name_is_csv_field():
    r = vhcsv.parse(_file(_row(an="--exec=evil")))
    assert any(d.code == vhcsv.CSV_FIELD for d in r.failures)


def test_I11_angle_brackets_in_name_is_csv_field():
    r = vhcsv.parse(_file(_row(an="Roberto <roberto@dicosmo.org>")))
    assert any(d.code == vhcsv.CSV_FIELD and "<" in d.message for d in r.failures)


def test_I12_control_char_in_name_is_csv_field():
    r = vhcsv.parse(_file(_row(an="bad\x1b]0;pwned")))
    d = [d for d in r.failures if d.code == vhcsv.CSV_FIELD][0]
    assert d.code_point and d.code_point.startswith("U+001B")


@pytest.mark.parametrize("dirn", ["../../etc", "a/b", ".hidden", "C:evil", "."])
def test_I13_bad_directory_names_are_csv_field(dirn):
    r = vhcsv.parse(_file(_row(dirn=dirn)))
    assert any(d.code == vhcsv.CSV_FIELD for d in r.failures), dirn


def test_I14_empty_commit_message_is_csv_field():
    r = vhcsv.parse(_file(_row(msg="")))
    assert any(d.code == vhcsv.CSV_FIELD and d.column == 8 for d in r.failures)


def test_I15_bad_email_is_csv_field():
    r = vhcsv.parse(_file(_row(ae="not-an-email")))
    assert any(d.code == vhcsv.CSV_FIELD for d in r.failures)


def test_I16_wrong_arity_is_csv_field():
    data = (HEADER + "prj,1994-03-24,A,a@noreply.example.org,C,c@noreply.example.org,v1.0\n").encode("utf-8")
    r = vhcsv.parse(data)
    assert any(d.code == vhcsv.CSV_FIELD and "fields" in d.message for d in r.failures)


def test_I17_casefold_collision_tag_is_csv_dup_tag():
    r = vhcsv.parse(_file(_row(dirn="a", tag="v1.0"), _row(dirn="b", tag="V1.0")))
    assert any(d.code == vhcsv.CSV_DUP_TAG for d in r.failures)


def test_I18_nfc_nfd_collision_dir_is_csv_dup_dir():
    nfc = "café"  # café NFC
    nfd = "café"  # café NFD
    r = vhcsv.parse(_file(_row(dirn=nfc, tag="v1"), _row(dirn=nfd, tag="v2")))
    assert any(d.code == vhcsv.CSV_DUP_DIR for d in r.failures)


def test_I19_rlo_bidi_in_name_is_csv_field_named():
    r = vhcsv.parse(_file(_row(an="Peter‮yoR naV")))
    d = [d for d in r.failures if d.code == vhcsv.CSV_FIELD][0]
    assert d.code_point and d.code_point.startswith("U+202E")


def test_I20_zwsp_in_tag_is_csv_field_named():
    r = vhcsv.parse(_file(_row(tag="v1.0​")))
    d = [d for d in r.failures if d.code == vhcsv.CSV_FIELD][0]
    assert d.code_point and d.code_point.startswith("U+200B")


def test_I21_future_date_with_reference_is_csv_date():
    r = vhcsv.parse(_file(_row(date="2026-12-31")), reference_date="2026-06-05T00:00:00+00:00")
    assert any(d.code == vhcsv.CSV_DATE and "future" in d.message for d in r.failures)


def test_embedded_newline_outside_message_is_csv_field():
    data = (HEADER + 'prj,1994-03-24,"A\nB",a@noreply.example.org,C,c@noreply.example.org,v1.0,msg\n').encode("utf-8")
    r = vhcsv.parse(data)
    assert any(d.code == vhcsv.CSV_FIELD and "line break" in d.message for d in r.failures)


def test_unterminated_quote_is_csv_field():
    data = (HEADER + 'prj,1994-03-24,A,a@noreply.example.org,C,c@noreply.example.org,v1.0,"unterminated\n').encode("utf-8")
    r = vhcsv.parse(data)
    assert any(d.code == vhcsv.CSV_FIELD for d in r.failures)


def test_blank_line_is_csv_field():
    data = (HEADER + _row() + "\n\n" + _row(dirn="b", tag="v2") + "\n").encode("utf-8")
    r = vhcsv.parse(data)
    assert any(d.code == vhcsv.CSV_FIELD and "blank line" in d.message for d in r.failures)


# ===========================================================================
# WARN / INFO (§7, §2.4, §4.5)
# ===========================================================================
def test_W1_date_regression_is_warn_not_fail():
    data = _file(_row(dirn="a", date="1994-03-24", tag="v1"),
                 _row(dirn="b", date="1993-08-09", tag="v2"))
    r = vhcsv.parse(data)
    assert r.ok  # WARN never blocks
    assert any(d.code == vhcsv.CSV_DATE_ORDER and d.severity == vhcsv.WARN for d in r.warnings)


def test_INFO1_all_fields_quoted_parses_with_info():
    qrow = ",".join('"' + v + '"' for v in
                    ["prj", "1994-03-24", "A", "a@noreply.example.org", "C",
                     "c@noreply.example.org", "v1.0", "msg"])
    data = (HEADER + qrow + "\n").encode("utf-8")
    r = vhcsv.parse(data)
    assert r.ok
    assert any(d.severity == vhcsv.INFO and "canonical writer form" in d.message for d in r.infos)


def test_INFO2_future_without_reference_is_skipped_info():
    r = vhcsv.parse(_file(_row(date="2026-12-31")))  # no reference_date
    assert r.ok  # not counted as a future FAIL
    assert any(d.severity == vhcsv.INFO and "future-date check skipped" in d.message for d in r.infos)


# ===========================================================================
# raise_on_fail / exit mapping (§10)
# ===========================================================================
def test_raise_on_fail_raises_csv_contract_error():
    r = vhcsv.parse(_file(_row(date="1994-02-30")))
    with pytest.raises(errors.CsvContractError) as ei:
        r.raise_on_fail()
    assert ei.value.code == vhcsv.CSV_DATE
    assert ei.value.exit_code == errors.EXIT_CSV


def test_warn_codes_never_raise():
    data = _file(_row(dirn="a", date="1994-03-24", tag="v1"),
                 _row(dirn="b", date="1993-08-09", tag="v2"))
    r = vhcsv.parse(data)
    r.raise_on_fail()  # must not raise; CSV-DATE-ORDER is WARN-only


# ===========================================================================
# Legacy profile (§11, §12.2)
# ===========================================================================
LEGACY_HEADER = ("directory name,author name,author email,date,"
                 "curator name,curator email,release tag,commit message\n")


def test_legacy_122_conversion_fixture():
    data = (LEGACY_HEADER +
            '1.1,Giuseppe Attardi,attardi@di.unipi.it,10/27/1994 12:26:20,'
            'CMM Curation Team,guido.scatena@unipi.it,*,'
            '"|Contributors mentioned in Changelog :| - Giuseppe Attardi @attardi."\n'
            ).encode("utf-8")
    r = vhcsv.convert_legacy(data)
    assert r.ok  # conversion exits 0
    assert len(r.rows) == 1
    row = r.rows[0]
    # date: byte-exactly the offset form, never Z (§4.6); unambiguous MM/DD
    assert row.date.serialize() == "1994-10-27T12:26:20+00:00"
    assert not any(d.code == vhcsv.CSV_AMBIGUOUS_US_DATE for d in r.diagnostics)
    # tag derived from directory name (legacy *)
    assert row.release_tag == "1.1"
    assert row.provenance == "computed"
    # message '|' → LF
    assert "\n" in row.commit_message
    assert "|" not in row.commit_message
    # both real emails PI-1 flagged on the worklist
    real = [w for w in r.worklist if w.kind == "real-email"]
    assert len(real) == 2


def test_W2_ambiguous_us_date_warns_but_converts():
    data = (LEGACY_HEADER +
            "1.1,A,a@noreply.example.org,04/05/1994,C,c@noreply.example.org,v1,msg\n").encode("utf-8")
    r = vhcsv.convert_legacy(data)
    assert r.ok  # exit 0
    assert len(r.rows) == 1
    assert r.rows[0].date.serialize() == "1994-04-05"  # US MM/DD applied
    w = [d for d in r.diagnostics if d.code == vhcsv.CSV_AMBIGUOUS_US_DATE][0]
    assert w.severity == vhcsv.WARN
    assert w.extra.get("alternate") == "1994-05-04"


def test_N1_unambiguous_ddmm_no_flag():
    data = (LEGACY_HEADER +
            "1.1,A,a@noreply.example.org,27/10/1994,C,c@noreply.example.org,v1,msg\n").encode("utf-8")
    r = vhcsv.convert_legacy(data)
    assert r.rows[0].date.serialize() == "1994-10-27"
    assert not any(d.code == vhcsv.CSV_AMBIGUOUS_US_DATE for d in r.diagnostics)


def test_N2_guide_dialect_empty_tag_no_row_worklist():
    guide = ("directory name,author name,author email,date original,"
             "curator name,curator email,release tag,commit message\n")
    data = (guide +
            "docs,A,a@noreply.example.org,1994-01-01,C,c@noreply.example.org,,just docs\n").encode("utf-8")
    r = vhcsv.convert_legacy(data)
    assert r.ok
    assert len(r.rows) == 0  # non-release directory → no canonical row
    assert any(w.kind == "empty-tag" for w in r.worklist)


def test_legacy_unrecognized_header_fails():
    data = b"a,b,c,d,e,f,g,h\n1,2,3,4,5,6,7,8\n"
    r = vhcsv.convert_legacy(data)
    assert not r.ok
    assert r.failures[0].code == vhcsv.CSV_HEADER


def test_legacy_star_tag_invalid_dirname_goes_to_worklist():
    # '*' → tag = directory name; if that fails §6, worklist, no row
    data = (LEGACY_HEADER +
            "bad..name,A,a@noreply.example.org,1994-01-01,C,c@noreply.example.org,*,msg\n").encode("utf-8")
    r = vhcsv.convert_legacy(data)
    # directory name 'bad..name' is fine as a dir, but tag 'bad..name' has '..'
    assert len(r.rows) == 0
    assert any(w.kind == "needs-repair" for w in r.worklist)


def test_legacy_two_digit_year_goes_to_worklist():
    data = (LEGACY_HEADER +
            "1.1,A,a@noreply.example.org,10/27/94,C,c@noreply.example.org,v1,msg\n").encode("utf-8")
    r = vhcsv.convert_legacy(data)
    assert len(r.rows) == 0
    assert any(w.kind == "undated" for w in r.worklist)


def test_legacy_never_writes():
    # the module exposes no legacy writer; only the canonical writer exists.
    assert not hasattr(vhcsv, "write_legacy")
    assert "write" in vhcsv.__all__


# ===========================================================================
# Date grammar unit coverage (§4)
# ===========================================================================
@pytest.mark.parametrize("s,prec,off", [
    ("1994-03-24T10:00:00+00:00", "second", 0),
    ("1994-03-24T10:00:00Z", "second", 0),
    ("1996-11-05T14:30:00+01:00", "second", 60),
    ("1996-11-05T14:30:00-05:00", "second", -300),
    ("1993-08-09", "day", 0),
    ("1995", "year", 0),
    ("1968-07-01", "day", 0),
])
def test_date_forms(s, prec, off):
    pd, errs = vhcsv.parse_date(s)
    assert errs == []
    assert pd.precision == prec
    assert pd.offset_minutes == off


@pytest.mark.parametrize("s,code", [
    ("1994-03-24T10:00:00", vhcsv.CSV_TZ),
    ("1994-13-01", vhcsv.CSV_DATE),
    ("1994-02-30", vhcsv.CSV_DATE),
    ("08/09/1993", vhcsv.CSV_DATE),
    ("1994-03-24 10:00:00+00:00", vhcsv.CSV_DATE),  # space separator
    ("1994-03", vhcsv.CSV_DATE),  # month-only
    ("1994-03-24T10:00:00+15:00", vhcsv.CSV_DATE),  # offset out of range
])
def test_bad_date_forms(s, code):
    pd, errs = vhcsv.parse_date(s)
    assert pd is None
    assert errs[0][0] == code


def test_round_trip_each_precision():
    for s in ("1996-11-05T14:30:00+01:00", "1993-08-09", "1995", "1968-07-01"):
        pd, _ = vhcsv.parse_date(s)
        assert pd.serialize() == s


# ===========================================================================
# Real Wild_LIFE tarball-derived rows (the regeneration CSV)
# ===========================================================================
WILDLIFE = (
    HEADER +
    "0.90,1993-08-09,Wild_LIFE authors,wildlife-authors@noreply.example.org,Roberto Di Cosmo,roberto@dicosmo.org,v0.90,Wild_LIFE 0.90\n"
    "0.91,1993-08-09,Wild_LIFE authors,wildlife-authors@noreply.example.org,Roberto Di Cosmo,roberto@dicosmo.org,v0.91,Wild_LIFE 0.91\n"
    "1.0,1994-03-24,Wild_LIFE authors,wildlife-authors@noreply.example.org,Roberto Di Cosmo,roberto@dicosmo.org,v1.0,Wild_LIFE 1.0\n"
    "1.02,1994,Wild_LIFE authors,wildlife-authors@noreply.example.org,Roberto Di Cosmo,roberto@dicosmo.org,v1.02,Wild_LIFE 1.02 Ultrix\n"
).encode("utf-8")


def test_wildlife_regeneration_rows_valid_and_ordered():
    r = vhcsv.parse(WILDLIFE)
    assert r.ok, [d.to_json() for d in r.failures]
    assert [row.directory_name for row in r.rows] == ["0.90", "0.91", "1.0", "1.02"]
    # 0.90 and 0.91 share the listing date (the real same-date case) — no order WARN
    assert r.rows[0].date.epoch_seconds == r.rows[1].date.epoch_seconds
    assert not any(d.code == vhcsv.CSV_DATE_ORDER and d.row == 2 for d in r.warnings)
    # 1.02 year-only inferred per the 1.02 date-evidence note (year→Jan 1 precedes
    # 1.0's March date: a legitimate precision-driven order WARN, never a FAIL)
    assert r.rows[3].date.precision == "year" and r.rows[3].date.inferred


def test_wildlife_rows_match_manifest_directories():
    import os
    base = "/home/dicosmo/code/swhap-toolkit/fixtures/wildlife/manifests"
    if not os.path.isdir(base):
        pytest.skip("wildlife manifests not present")
    present = {f[:-5] for f in os.listdir(base) if f.endswith(".json")}
    r = vhcsv.parse(WILDLIFE)
    for row in r.rows:
        assert row.directory_name in present, row.directory_name
