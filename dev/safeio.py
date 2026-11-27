"""Create a new file without following a planted link.

A predictable temp name (`out.json.tmp`) can be pre-created by another user as a symlink, and a plain
`open(path, "w")` then truncates whatever the link points at. `create_new` removes a stale file of that name
(unlink never follows a link) and creates the file with O_EXCL | O_NOFOLLOW, so a racing plant fails loudly.
The mode is 0o666 before the umask, the same as `open`, so output files keep their usual permissions."""
import os


def create_new(path, mode="w", **kw):
    """Open `path` for writing as a brand-new file. `mode` is "w" or "wb"; other keywords go to os.fdopen."""
    if mode not in ("w", "wb"):
        raise ValueError("create_new writes only: mode must be 'w' or 'wb'")
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o666)
    return os.fdopen(fd, mode, **kw)
