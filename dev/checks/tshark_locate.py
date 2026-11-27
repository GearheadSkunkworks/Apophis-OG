"""Find tshark on any platform, for the checks, tools and tests that dissect captures with it.

Order: the ``TSHARK`` environment variable, the macOS Wireshark.app bundle (which is not on PATH), then PATH
(Linux packages, Homebrew). Returns None when tshark is not installed, so callers skip with a clear message instead of
assuming a macOS path.
"""
import os
import shutil

MACOS_APP = "/Applications/Wireshark.app/Contents/MacOS/tshark"


def find_tshark(env=None, which=shutil.which, exists=os.path.exists):
    """Path of a usable tshark, or None."""
    env = os.environ if env is None else env
    explicit = env.get("TSHARK")
    if explicit:
        return explicit if exists(explicit) else None
    if exists(MACOS_APP):
        return MACOS_APP
    return which("tshark")
