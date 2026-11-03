"""BP-1..5 — branch purity per profile (C3 / D1).

strict-P = brief §9 model (pure default branch + orphan SourceCode); strict-G =
current-guide model. additional_materials/ admission is a WARN until the D1
ruling (validator plan risk 5).
"""
from __future__ import annotations

from ..context import GitError
from ..profiles import STRICT_P
from ..report import FAIL, WARN, Finding

_ROLE = "curator"

# strict-P pure-default-branch allowlist (brief §9 / validator plan BP-2).
_MAIN_ALLOW = {"README.md", "Makefile", "codemeta.json", "metadata", "raw_materials", "scripts", "source_code",
               ".github"}  # codemeta.json: SWH indexes it only at the default-branch root (B5 promotion, W1).
# .github: a provisioned workbench carries its own CI (a thin caller of the versioned
# reusable engine, C5/S2); it is workbench infrastructure and belongs on the workbench
# branch, never on SourceCode (W2).
_MAIN_WARN = {"additional_materials"}  # pending D1


def run(report, ctx, *, profile, release_tags):
    default = ctx.default_branch()
    sc = "refs/heads/SourceCode" if ctx.ref_exists("refs/heads/SourceCode") else None

    _bp1(report, ctx, profile, default, sc)
    _bp2(report, ctx, profile, default, sc)
    _bp3(report, ctx, sc, release_tags)
    _bp5(report, ctx, release_tags)


def ctx_ls_tree_top(ctx, ref):
    from ..context import git
    raw = git(ctx.repo, "ls-tree", "-z", ref)
    names = []
    for rec in raw.split(b"\x00"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        names.append(path.decode("utf-8", "surrogateescape"))
    return names


def _bp1(report, ctx, profile, default, sc):
    report.ran("BP-1")
    if profile != STRICT_P:
        return
    if sc is None:
        report.add(Finding(
            "BP-1", FAIL, {"ref": "refs/heads/SourceCode"}, ["ref"],
            "This model requires a separate SourceCode branch holding the "
            "reconstructed source, but it is missing.",
            required_approver_role=_ROLE))
        return
    # orphan: root commit of SourceCode is parentless AND not reachable from default
    commits = ctx.commits_on("refs/heads/SourceCode")
    root = commits[-1]
    if ctx.parents(root):
        report.add(Finding(
            "BP-1", FAIL, {"ref": "refs/heads/SourceCode"}, ["ref"],
            "The SourceCode branch is not an orphan branch: its first commit has "
            "a parent.",
            message_technical=f"root commit {root[:12]} has parents",
            required_approver_role=_ROLE))
    if default and _is_ancestor(ctx, "refs/heads/SourceCode",
                                f"refs/heads/{default}"):
        report.add(Finding(
            "BP-1", FAIL, {"ref": "refs/heads/SourceCode"}, ["ref"],
            "The SourceCode branch shares history with the workbench branch; they "
            "must be independent.",
            required_approver_role=_ROLE))


def _is_ancestor(ctx, anc, desc):
    import subprocess
    p = subprocess.run(["git", "-C", ctx.repo, "merge-base", "--is-ancestor",
                        anc, desc], capture_output=True)
    return p.returncode == 0


def _bp2(report, ctx, profile, default, sc):
    report.ran("BP-2")
    if profile == STRICT_P and default:
        top = set(ctx_ls_tree_top(ctx, f"refs/heads/{default}"))
        for name in sorted(top - _MAIN_ALLOW - _MAIN_WARN):
            report.add(Finding(
                "BP-2", FAIL, {"ref": f"refs/heads/{default}", "path": name},
                ["ref", "path"],
                f"The workbench branch contains '{name}', which is not allowed on "
                "the pure workbench branch.",
                required_approver_role=_ROLE))
        for name in sorted(top & _MAIN_WARN):
            report.add(Finding(
                "BP-2", WARN, {"ref": f"refs/heads/{default}", "path": name},
                ["ref", "path"],
                f"The workbench branch contains '{name}'; whether this is allowed "
                "is pending the branch-model decision (D1).",
                required_approver_role=_ROLE))
    # SourceCode must hold source only (no metadata/raw_materials)
    if sc:
        top = set(ctx_ls_tree_top(ctx, "refs/heads/SourceCode"))
        for forbidden in ("metadata", "raw_materials", "additional_materials", ".github"):
            if forbidden in top:
                report.add(Finding(
                    "BP-2", FAIL,
                    {"ref": "refs/heads/SourceCode", "path": forbidden},
                    ["ref", "path"],
                    f"The SourceCode branch contains '{forbidden}', but it must "
                    "hold only reconstructed source.",
                    required_approver_role=_ROLE))


def _bp3(report, ctx, sc, release_tags):
    report.ran("BP-3")
    if sc is None:
        return
    commits = ctx.commits_on("refs/heads/SourceCode")
    if release_tags and len(commits) != len(release_tags):
        report.add(Finding(
            "BP-3", FAIL,
            {"commits": len(commits), "rows": len(release_tags)},
            ["commits", "rows"],
            f"The SourceCode branch has {len(commits)} commit(s) but the history "
            f"lists {len(release_tags)} release(s); there must be exactly one "
            "commit per release.",
            required_approver_role=_ROLE))
    sc_present = ctx.ref_exists("refs/heads/SourceCode")
    for tag in release_tags:
        if not ctx.ref_exists(f"refs/tags/{tag}"):
            # No annotated tag for this release. On the published exemplar every
            # release is identified ONLY by its SourceCode commit message (the
            # release->commit mapping the validator had to fall back to); the
            # brief requires one annotated tag per release, so this is a
            # SWHAP-compliance defect, recorded rather than fatal.
            extra = (" The release is identified only by its SourceCode commit "
                     "message, with no tag to mark it.") if sc_present else ""
            report.add(Finding(
                "BP-3", FAIL, {"tag": tag}, ["tag"],
                f"Release '{tag}' has no annotated tag.{extra}",
                message_technical=f"no refs/tags/{tag}; brief requires one "
                "annotated tag per release",
                required_approver_role=_ROLE,
                remediation=f"Create an annotated tag '{tag}' on the release "
                "commit on SourceCode."))
        elif not ctx.is_annotated_tag(tag):
            report.add(Finding(
                "BP-3", FAIL, {"tag": tag}, ["tag"],
                f"Release tag '{tag}' is a lightweight tag; it must be annotated.",
                required_approver_role=_ROLE))


def _bp5(report, ctx, release_tags):
    report.ran("BP-5")
    for tag in release_tags:
        if not ctx.ref_exists(f"refs/tags/{tag}"):
            continue
        try:
            top = ctx_ls_tree_top(ctx, f"refs/tags/{tag}")
        except GitError:
            continue
        # wrapper smell: the whole release is a single top-level directory
        if len(top) == 1:
            entries = ctx.ls_tree(f"refs/tags/{tag}")
            if entries and all("/" in e.path for e in entries):
                report.add(Finding(
                    "BP-5", FAIL, {"tag": tag, "wrapper": top[0]}, ["tag"],
                    f"Release '{tag}' has an artificial top-level wrapper "
                    f"directory '{top[0]}' that should have been stripped.",
                    message_technical=(
                        f"refs/tags/{tag}: tree root is the single directory "
                        f"{top[0]!r} and every entry lives under it — the wrapper "
                        "was not stripped on acquisition (brief wrapper-stripping "
                        "invariant)"),
                    required_approver_role=_ROLE,
                    remediation=f"Re-acquire release '{tag}' with the wrapper "
                    f"directory '{top[0]}' stripped so its contents sit at the "
                    "release root."))
