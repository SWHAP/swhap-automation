#!/usr/bin/env python3
import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

# We rely on bsdtar (libarchive) for wide format support (.zip, .tar.*, .Z, .7z)
# Install in CI: apt-get install -y libarchive-tools p7zip-full ncompress

def is_archive(p: pathlib.Path) -> bool:
    exts = {
        ".zip", ".7z",
        ".tar", ".tgz", ".taz", ".tbz", ".tbz2", ".txz",
        ".tar.gz", ".tar.Z", ".tar.bz2", ".tar.xz",
        ".Z"
    }
    s = p.name.lower()
    return any(s.endswith(ext) for ext in exts)

def _single_top_dir(root: pathlib.Path) -> pathlib.Path | None:
    items = [p for p in root.iterdir() if p.name not in (".", "..")]
    if len(items) == 1 and items[0].is_dir():
        return items[0]
    return None

def extract_source(src: pathlib.Path, dest: pathlib.Path, strip_components: str|int = "auto") -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        # Copy tree as-is then maybe flatten
        with tempfile.TemporaryDirectory() as tmpd:
            tmp = pathlib.Path(tmpd)
            payload = tmp / "payload"
            shutil.copytree(src, payload, dirs_exist_ok=True)
            stage = payload
            if strip_components == "auto":
                top = _single_top_dir(stage)
                if top:
                    stage = top
            elif isinstance(strip_components, int) and strip_components > 0:
                cur = stage
                for _ in range(strip_components):
                    top = _single_top_dir(cur)
                    if not top:
                        break
                    cur = top
                stage = cur
            # Move into dest
            for p in stage.iterdir():
                shutil.move(str(p), dest / p.name)
        return

    # Archive extraction via bsdtar to a temp dir for safety
    with tempfile.TemporaryDirectory() as tmpd:
        tmp = pathlib.Path(tmpd)
        payload = tmp / "payload"
        payload.mkdir()

        # bsdtar is path traversal safe; extract to temp then move.
        cmd = ["bsdtar", "-xpf", str(src), "-C", str(payload)]
        subprocess.run(cmd, check=True)

        stage = payload
        if strip_components == "auto":
            top = _single_top_dir(stage)
            if top:
                stage = top
        elif isinstance(strip_components, int) and strip_components > 0:
            cur = stage
            for _ in range(strip_components):
                top = _single_top_dir(cur)
                if not top:
                    break
                cur = top
            stage = cur

        # Create .emptydir markers so empty dirs survive in Git
        for rootdir, dirnames, filenames in os.walk(stage):
            if not dirnames and not filenames:
                marker = pathlib.Path(rootdir) / ".emptydir"
                marker.touch()

        for p in stage.iterdir():
            shutil.move(str(p), dest / p.name)

def main():
    ap = argparse.ArgumentParser(description="Extract archive or directory safely and optionally flatten.")
    ap.add_argument("--src", required=True, help="Path to archive or directory")
    ap.add_argument("--dest", required=True, help="Destination directory")
    ap.add_argument("--strip-components", default="auto", help="'auto' or integer")
    args = ap.parse_args()

    src = pathlib.Path(args.src).resolve()
    dest = pathlib.Path(args.dest).resolve()

    if args.strip_components != "auto":
        try:
            sc = int(args.strip_components)
        except ValueError:
            print("--strip-components must be 'auto' or integer", file=sys.stderr)
            sys.exit(2)
    else:
        sc = "auto"

    if not src.exists():
        print(f"ERROR: {src} does not exist", file=sys.stderr)
        sys.exit(1)

    extract_source(src, dest, strip_components=sc)
    print(f"OK: extracted {src} -> {dest}")

if __name__ == "__main__":
    main()
