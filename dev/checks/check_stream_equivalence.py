"""The generator's hot helpers must stay exactly what they were: same bytes out AND same random stream left behind.

_rand_bytes (every ESP payload), text_blob (HTTP/FTP filler) and csum (every packet) were rewritten to run faster. A build is
reproducible because every draw from a seeded generator happens in the same order; one extra or missing draw shifts everything after
it and changes the capture (the pinned baseline). So each is compared with the straightforward original it replaced, over many seeds
and sizes: same result, and the generator left in the same state. If a Python release changes randrange, choice or randint, this fails
before a capture quietly changes."""
import array
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netgen import core, protocols  # noqa: E402 - sys.path is set up before the import

fails = []
WORDS = ("shipment manifest pallet carrier dock lane tracking invoice consignee origin destination weight kg "
         "hazmat customs broker eta etd container seal trailer route driver depot hub scan exception delivered").split()


def old_rand_bytes(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def old_text_blob(rng, n):
    out, size = [], 0
    while size < n:
        w = " ".join(rng.choice(WORDS) for _ in range(rng.randint(6, 14))).capitalize() + ".\n"
        out.append(w)
        size += len(w)
    return "".join(out).encode()[:n]


def old_csum(data):
    if len(data) & 1:
        data += b"\x00"
    s = sum(array.array("H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


for seed in range(40):
    for n in (0, 1, 2, 15, 16, 17, 255, 256, 1000, 1400, 6000):
        for new, old, name in ((protocols._rand_bytes, old_rand_bytes, "_rand_bytes"), (protocols.text_blob, old_text_blob, "text_blob")):
            protocols.rng.seed(seed)
            a = new(n)
            state_new = protocols.rng.getstate()
            ref = random.Random(seed)
            if a != old(ref, n) or state_new != ref.getstate():
                fails.append("%s(%d) seed %d: output or generator state differs from the original" % (name, n, seed))

shapes = (0, 1, 2, 3, 20, 33, 54, 60, 100, 1400, 1500)
for i in range(100000):
    d = os.urandom(random.choice(shapes))
    r = i % 20
    if r == 0:
        d = bytes(len(d))                           # all zero: checksum 0xFFFF
    elif r == 1:
        d = b"\xff" * len(d)                        # words that sum to a multiple of 65535
    elif r == 2:
        d = b"\x00\x00\xff\xff" * (len(d) // 4)
    if core.csum(d) != old_csum(d):
        fails.append("csum differs for %r" % d[:16])
        break

for f in fails[:10]:
    print("FAIL", f)
print("stream equivalence: %d checks failed" % len(fails))
sys.exit(1 if fails else 0)
