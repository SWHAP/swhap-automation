"""Read-only archive format sniffing and member enumeration.

Produces a normalized ``Member`` list from tar (gz/bz2/xz/plain) and zip
archives **without writing a byte to disk**. Rule evaluation happens in
``inspect.py`` against this member list directly (core-pipeline.md §4.1 pass 1).

Security posture: names are bytes. We never follow a link, never read a member
body except a symlink's (tiny) target inside a zip, and never execute anything.
``tarfile``'s ``data`` filter is the semantic baseline for the tar rejection
rules; we re-assert the equivalent checks ourselves in ``inspect.py`` so zip
gets identical guarantees and so the verdict never depends on extraction.
"""

from __future__ import annotations

import tarfile
import zipfile
from dataclasses import dataclass

# member kinds
FILE = "file"
DIR = "dir"
SYMLINK = "symlink"
HARDLINK = "hardlink"
CHAR = "char"
BLOCK = "block"
FIFO = "fifo"
SOCKET = "socket"

SPECIAL_KINDS = frozenset({CHAR, BLOCK, FIFO, SOCKET})


@dataclass(frozen=True)
class Member:
    """One archive entry, normalized across tar and zip.

    ``name`` is the decoded display path (may carry surrogate code points for
    non-UTF-8 tar names — always rendered through ``bsafe`` before emission).
    ``name_bytes`` is the lossless on-archive path. ``linkname`` / ``link_bytes``
    are the symlink/hardlink target (``None`` otherwise).
    """

    name: str
    name_bytes: bytes
    kind: str
    size: int
    mode: int
    linkname: str | None = None
    link_bytes: bytes | None = None

    @property
    def is_utf8(self) -> bool:
        try:
            self.name_bytes.decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False


@dataclass(frozen=True)
class ArchiveInfo:
    container: str  # "tar" | "zip"
    compression: str  # "none" | "gzip" | "bzip2" | "xz"


class ArchiveFormatError(Exception):
    """Archive could not be opened / enumerated (maps to EX-FORMAT)."""


_MAGIC = [
    (b"\x1f\x8b", "tar", "gzip"),
    (b"BZh", "tar", "bzip2"),
    (b"\xfd7zXZ\x00", "tar", "xz"),
    (b"PK\x03\x04", "zip", "none"),
    (b"PK\x05\x06", "zip", "none"),  # empty zip
    (b"PK\x07\x08", "zip", "none"),  # spanned zip
]


def sniff(path: str) -> ArchiveInfo:
    """Best-effort container/compression sniff from magic bytes.

    Falls back to a plain-tar probe. Raises ``ArchiveFormatError`` if nothing
    recognizes the file.
    """
    with open(path, "rb") as fh:
        head = fh.read(512)
    for magic, container, compression in _MAGIC:
        if head.startswith(magic):
            return ArchiveInfo(container, compression)
    # uncompressed tar: the ustar magic sits at offset 257
    if len(head) >= 263 and head[257:262] in (b"ustar", b"ustar".ljust(5)):
        return ArchiveInfo("tar", "none")
    if tarfile.is_tarfile(path):
        return ArchiveInfo("tar", "none")
    raise ArchiveFormatError(f"unrecognized archive format: {path}")


def _tar_kind(ti: tarfile.TarInfo) -> str:
    if ti.isdir():
        return DIR
    if ti.issym():
        return SYMLINK
    if ti.islnk():
        return HARDLINK
    if ti.ischr():
        return CHAR
    if ti.isblk():
        return BLOCK
    if ti.isfifo():
        return FIFO
    # tarfile has no socket type; CONTTYPE/REGTYPE/AREGTYPE -> file
    return FILE


def _enumerate_tar(path: str) -> list[Member]:
    members: list[Member] = []
    # default encoding utf-8 + surrogateescape lets us recover exact bytes.
    try:
        tf = tarfile.open(path, mode="r:*", encoding="utf-8", errors="surrogateescape")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ArchiveFormatError(str(exc)) from exc
    try:
        try:
            infos = tf.getmembers()
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise ArchiveFormatError(str(exc)) from exc
        for ti in infos:
            name_bytes = ti.name.encode("utf-8", "surrogateescape")
            linkname = ti.linkname if (ti.issym() or ti.islnk()) else None
            link_bytes = (
                linkname.encode("utf-8", "surrogateescape") if linkname is not None else None
            )
            members.append(
                Member(
                    name=ti.name,
                    name_bytes=name_bytes,
                    kind=_tar_kind(ti),
                    size=ti.size,
                    mode=ti.mode,
                    linkname=linkname,
                    link_bytes=link_bytes,
                )
            )
    finally:
        tf.close()
    return members


def _zip_name_bytes(zi: zipfile.ZipInfo) -> bytes:
    # bit 11 (0x800) of the general-purpose flag => filename is UTF-8.
    if zi.flag_bits & 0x800:
        return zi.filename.encode("utf-8", "surrogateescape")
    try:
        return zi.filename.encode("cp437")
    except UnicodeEncodeError:
        return zi.filename.encode("utf-8", "surrogateescape")


def _enumerate_zip(path: str) -> list[Member]:
    members: list[Member] = []
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArchiveFormatError(str(exc)) from exc
    try:
        try:
            infos = zf.infolist()
        except (zipfile.BadZipFile, OSError) as exc:
            raise ArchiveFormatError(str(exc)) from exc
        for zi in infos:
            name = zi.filename
            name_bytes = _zip_name_bytes(zi)
            unix_mode = (zi.external_attr >> 16) & 0o170000
            is_symlink = unix_mode == 0o120000
            if zi.is_dir():
                kind = DIR
            elif is_symlink:
                kind = SYMLINK
            else:
                kind = FILE
            linkname = None
            link_bytes = None
            if is_symlink and zi.file_size <= 4096:
                # read the (tiny) target into memory only — no disk write.
                try:
                    link_bytes = zf.read(zi)
                except (zipfile.BadZipFile, OSError):
                    link_bytes = b""
                linkname = link_bytes.decode("utf-8", "surrogateescape")
            members.append(
                Member(
                    name=name.rstrip("/") if kind == DIR else name,
                    name_bytes=name_bytes.rstrip(b"/") if kind == DIR else name_bytes,
                    kind=kind,
                    size=zi.file_size,
                    mode=unix_mode or 0o644,
                    linkname=linkname,
                    link_bytes=link_bytes,
                )
            )
    finally:
        zf.close()
    return members


def enumerate_members(path: str, info: ArchiveInfo) -> list[Member]:
    """Enumerate members for an already-sniffed archive."""
    if info.container == "zip":
        return _enumerate_zip(path)
    return _enumerate_tar(path)
