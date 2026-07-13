"""Error taxonomy stability + CLI surface."""

from __future__ import annotations

import json

import pytest

from swhap_core import errors
from swhap_core.cli import main
from swhap_core.inspect import bsafe


def test_inspect_codes_map_to_exit_codes():
    for c in ["EX-TRAVERSAL", "EX-ABS", "EX-SYMLINK-ESCAPE", "EX-HARDLINK-OUT",
              "EX-DEVICE", "EX-DUP", "EX-CASE-COLLISION", "EX-FORMAT"]:
        assert errors.exit_code_for_code(c) == errors.EXIT_EXTRACTION
    for c in ["BG-MEMBERS", "BG-BYTES", "BG-RATIO", "BG-FILESIZE", "BG-PATH"]:
        assert errors.exit_code_for_code(c) == errors.EXIT_BUDGET


def test_inspect_code_set_frozen():
    assert errors.INSPECT_CODES == (
        "EX-FORMAT", "EX-ABS", "EX-TRAVERSAL", "EX-SYMLINK-ESCAPE",
        "EX-HARDLINK-OUT", "EX-DEVICE", "EX-DUP", "EX-CASE-COLLISION",
        "BG-MEMBERS", "BG-BYTES", "BG-RATIO", "BG-FILESIZE", "BG-PATH",
    )


def test_exit_code_precedence():
    assert errors.exit_code_for_codes(["BG-RATIO", "EX-ABS"]) == errors.EXIT_EXTRACTION
    assert errors.exit_code_for_codes(["BG-RATIO"]) == errors.EXIT_BUDGET
    assert errors.exit_code_for_codes([]) == errors.EXIT_OK


def test_error_families_and_templates():
    e = errors.error_for_code("EX-TRAVERSAL", "boom", path="../x")
    assert isinstance(e, errors.ExtractionContractError)
    assert e.code == "EX-TRAVERSAL"
    assert e.template_id == "tmpl.ex-traversal"
    assert e.fields["path"] == "../x"


def test_bsafe_surrogates_and_controls():
    # a latin-1 0xe9 byte decoded via surrogateescape -> \udce9 -> \xe9
    s = b"caf\xe9".decode("utf-8", "surrogateescape")
    assert bsafe(s) == "caf\\xe9"
    # control char and backslash
    assert bsafe("a\x01b\\c") == "a\\x01b\\\\c"
    # valid UTF-8 stays real
    assert bsafe("café") == "café"


def test_cli_inspect_json_stdout(corpus, capsys):
    rc = main(["inspect", corpus["pos-dotfiles.tar"], "--json"])
    out = capsys.readouterr().out
    report = json.loads(out)
    assert rc == 0
    assert report["schema"] == "swhap-core/inspect/v1"
    assert report["accepted"] is True


def test_cli_inspect_rejects_with_exit_10(corpus, capsys):
    rc = main(["inspect", corpus["neg-traversal-dotdot.tar"]])
    report = json.loads(capsys.readouterr().out)
    assert rc == 10
    assert any(x["code"] == "EX-TRAVERSAL" for x in report["rejections"])


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["--version"])
    assert ei.value.code == 0
    assert "swhap-core" in capsys.readouterr().out


def test_cli_no_command_is_usage(capsys):
    rc = main([])
    assert rc == errors.EXIT_USAGE


def test_cli_missing_file_is_usage(capsys, tmp_path):
    rc = main(["inspect", str(tmp_path / "nope.tar")])
    assert rc == errors.EXIT_USAGE


def test_cli_multi_archive_wraps(corpus, capsys):
    rc = main(["inspect", corpus["pos-dotfiles.tar"], corpus["neg-absolute-path.tar"]])
    report = json.loads(capsys.readouterr().out)
    assert "reports" in report
    assert len(report["reports"]) == 2
    # worst exit code across the batch
    assert rc == 10


def test_cli_policy_file(corpus, tmp_path, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"max_members": 10}))
    rc = main(["inspect", corpus["neg-bomb-members.tar"], "--policy", str(policy)])
    report = json.loads(capsys.readouterr().out)
    assert rc == 11
    assert any(x["code"] == "BG-MEMBERS" for x in report["rejections"])
