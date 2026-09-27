"""Reads the STAGED (git index) snapshot -- never the working tree.

Working tree  = whatever is currently on disk, including edits not yet
                staged with `git add`.
Staged content = the exact snapshot `git add` recorded in the index; this
                is what `git commit` will actually record.
Committed content = what already exists in a previous commit's history.

This module only ever reads the staged snapshot, via `git show :<path>`
(the ":" prefix means "the index version of this path", not the file on
disk), because that is the only version that answers "what is about to be
committed" correctly.
"""

import subprocess


class GitCommandError(Exception):
    pass


def _run_git(args: list[str]) -> bytes:
    result = subprocess.run(["git", *args], capture_output=True)
    if result.returncode != 0:
        raise GitCommandError(result.stderr.decode(errors="replace").strip())
    return result.stdout


def list_staged_files() -> list[tuple[str, str]]:
    """(status, path) pairs for every file staged in the index. Uses the
    NUL-separated form (`-z`) so filenames containing spaces or unusual
    characters are parsed safely, not split incorrectly."""
    raw = _run_git(["diff", "--cached", "--name-status", "-z"])
    if not raw:
        return []
    parts = [p for p in raw.decode(errors="replace").split("\0") if p]

    files: list[tuple[str, str]] = []
    i = 0
    while i < len(parts):
        status = parts[i]
        if status[0] in ("R", "C"):  # rename/copy: old path, then new path follow
            new_path = parts[i + 2]
            files.append((status, new_path))
            i += 3
        else:
            files.append((status, parts[i + 1]))
            i += 2
    return files


def get_staged_content(path: str) -> bytes:
    """The staged (index) blob content for `path` -- the version that will
    actually be committed, regardless of what's currently on disk."""
    return _run_git(["show", f":{path}"])


def is_binary(content: bytes) -> bool:
    # Same well-established heuristic Git and many other tools use: a NUL
    # byte essentially never appears in genuine text content, but is common
    # in binary formats. Simple, fast, no format-specific decoding needed.
    return b"\x00" in content[:8192]
