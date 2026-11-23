"""The npm-web-degradation pool helpers save and restore every random generator. A process that has
imported `secrets` holds a SystemRandom, which has no state; a full generation must still work and
leave the rest of the capture untouched (the AEB tailoring tools import `secrets`)."""
import os
import random
import secrets  # noqa: F401  -- must be imported before generating
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netgen import incidents  # noqa: E402

gens, saved = incidents._isolated_rng()
assert gens and len(gens) == len(saved)
assert not any(isinstance(g, random.SystemRandom) for g in gens), "SystemRandom has no state to save"

import opengenerator_build  # noqa: E402

with tempfile.TemporaryDirectory() as d:
    sys.argv = ["opengenerator_build.py", "--scale", "0.0005", "--module", "npm-web-degradation",
                "--out", os.path.join(d, "t.pcap"), "--no-certs", "--no-iocs"]
    opengenerator_build.main()
    assert os.path.getsize(os.path.join(d, "t.pcap")) > 1_000_000
print("isolated random state works with secrets imported; npm-web-degradation generates")
