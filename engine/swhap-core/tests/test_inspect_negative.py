"""Negative/positive corpus: one assertion per crit-M6 rejection rule."""

from __future__ import annotations

import json

from swhap_core.inspect import ExtractionPolicy, inspect_archive


def _codes(report) -> set[str]:
    return {r["code"] for r in report["rejections"]}


# --- structural rejection rules --------------------------------------------
def test_traversal(corpus):
    r = inspect_archive(corpus["neg-traversal-dotdot.tar"])
    assert "EX-TRAVERSAL" in _codes(r)
    assert r["accepted"] is False
    assert r["exit_code"] == 10


def test_absolute_path(corpus):
    r = inspect_archive(corpus["neg-absolute-path.tar"])
    assert "EX-ABS" in _codes(r)
    assert r["exit_code"] == 10


def test_symlink_absolute_escape(corpus):
    r = inspect_archive(corpus["neg-symlink-escape.tar"])
    assert "EX-SYMLINK-ESCAPE" in _codes(r)
    # the symlink inventory must mark it as escaping
    assert any(s["escapes_root"] for s in r["symlinks"])


def test_symlink_relative_escape(corpus):
    r = inspect_archive(corpus["neg-symlink-rel-escape.tar"])
    assert "EX-SYMLINK-ESCAPE" in _codes(r)


def test_hardlink_outside(corpus):
    r = inspect_archive(corpus["neg-hardlink-outside.tar"])
    assert "EX-HARDLINK-OUT" in _codes(r)


def test_device_fifo(corpus):
    r = inspect_archive(corpus["neg-device-fifo.tar"])
    assert "EX-DEVICE" in _codes(r)
    assert r["summary"]["special_files"] == 1


def test_device_char(corpus):
    r = inspect_archive(corpus["neg-device-char.tar"])
    assert "EX-DEVICE" in _codes(r)


def test_duplicate_member(corpus):
    r = inspect_archive(corpus["neg-duplicate-member.tar"])
    assert "EX-DUP" in _codes(r)


def test_case_collision(corpus):
    r = inspect_archive(corpus["neg-case-collision.tar"])
    assert "EX-CASE-COLLISION" in _codes(r)
    coll = [x for x in r["rejections"] if x["code"] == "EX-CASE-COLLISION"][0]
    assert sorted(coll["paths"]) == ["pkg/README", "pkg/readme"]


def test_format_error_zip(corpus):
    r = inspect_archive(corpus["neg-zip-central-dir-mismatch.zip"])
    assert "EX-FORMAT" in _codes(r)
    assert r["accepted"] is False
    assert r["exit_code"] == 10


# --- budget rules -----------------------------------------------------------
def test_long_path(corpus):
    r = inspect_archive(corpus["neg-long-path.tar"])
    assert "BG-PATH" in _codes(r)
    assert r["exit_code"] == 11


def test_deep_tree(corpus):
    r = inspect_archive(corpus["neg-deep-tree.tar"])
    assert "BG-PATH" in _codes(r)


def test_bomb_ratio(corpus):
    r = inspect_archive(corpus["neg-bomb-ratio.tgz"])
    assert "BG-RATIO" in _codes(r)
    assert r["exit_code"] == 11
    assert float(r["summary"]["compression_ratio"]) > 200


def test_bomb_members_with_policy(corpus):
    policy = ExtractionPolicy(max_members=10)
    r = inspect_archive(corpus["neg-bomb-members.tar"], policy)
    assert "BG-MEMBERS" in _codes(r)
    # default policy must NOT flag 50 members
    r2 = inspect_archive(corpus["neg-bomb-members.tar"])
    assert "BG-MEMBERS" not in _codes(r2)


def test_extraction_precedence_over_budget():
    # a single archive with both an EX-* and a BG-* must exit 10, not 11
    import io
    import os
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("/abs/and/" + "a" * 4100)
        ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "both.tar")
        with open(p, "wb") as fh:
            fh.write(buf.getvalue())
        r = inspect_archive(p)
    codes = _codes(r)
    assert "EX-ABS" in codes and "BG-PATH" in codes
    assert r["exit_code"] == 10


# --- positive corpus: must inspect cleanly ---------------------------------
def test_pos_dotfiles_clean(corpus):
    r = inspect_archive(corpus["pos-dotfiles.tar"])
    assert r["accepted"] is True
    assert r["rejections"] == []
    # dotfiles are enumerated as ordinary members (not lost)
    assert r["summary"]["files"] == 3


def test_pos_symlinks_clean(corpus):
    r = inspect_archive(corpus["pos-symlinks.tgz"])
    assert r["accepted"] is True
    assert r["summary"]["symlinks"] == 1
    assert all(not s["escapes_root"] for s in r["symlinks"])


def test_pos_latin1_byte_preservation(corpus):
    r = inspect_archive(corpus["pos-latin1-names.tar"])
    assert r["accepted"] is True
    assert r["summary"]["non_utf8_names"] == 1
    rec = r["non_utf8_names"][0]
    # latin-1 'é' is byte 0xe9; the lossless authority is bytes_hex
    assert "e9" in rec["bytes_hex"]
    assert rec["declared_encoding"] == "latin-1"
    assert "Caf" in rec["decoded"]


def test_pos_emptydirs(corpus):
    r = inspect_archive(corpus["pos-emptydirs-nested.tar"])
    assert r["accepted"] is True
    # only the truly-empty leaf gets a .emptydir; pkg/empty contains
    # alsoempty so it is not itself empty after extraction.
    assert set(r["empty_dirs"]) == {"pkg/empty/alsoempty"}


def test_pos_wrapper_single(corpus):
    r = inspect_archive(corpus["pos-wrapper-single.tar"])
    assert r["wrapper"]["detected"] is True
    assert r["wrapper"]["name"] == "Wrap1.0/"


def test_pos_wrapper_plus_stray(corpus):
    r = inspect_archive(corpus["pos-wrapper-plus-stray.tar"])
    assert r["wrapper"]["detected"] is False


def test_pos_two_dirs_no_wrapper(corpus):
    r = inspect_archive(corpus["pos-two-dirs-no-wrapper.tar"])
    assert r["wrapper"]["detected"] is False


def test_pos_hardlink_inside_clean(corpus):
    r = inspect_archive(corpus["pos-hardlink-inside.tar"])
    assert r["accepted"] is True
    assert "EX-HARDLINK-OUT" not in _codes(r)
    assert r["summary"]["hardlinks"] == 1


# --- determinism ------------------------------------------------------------
def test_deterministic_json(corpus):
    a = inspect_archive(corpus["pos-symlinks.tgz"])
    b = inspect_archive(corpus["pos-symlinks.tgz"])
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_no_absolute_host_paths_in_report(corpus):
    # report addresses the archive by basename + sha256, never abs host path
    r = inspect_archive(corpus["pos-dotfiles.tar"])
    blob = json.dumps(r)
    assert "/tmp" not in blob
    assert r["archive"] == "pos-dotfiles.tar"
    assert len(r["sha256"]) == 64
