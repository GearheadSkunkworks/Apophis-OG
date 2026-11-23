"""python3 -m intel list | parse FILE | fetch FEED [--limit N] [--offline] [--no-cache] [--param k=v]

Prints one JSON object per line. Keys come from OTX_API_KEY / ABUSECH_AUTH_KEY, never from flags.
"""
import argparse
import json
import sys

from . import parsers, sources


def main(argv=None):
    ap = argparse.ArgumentParser(prog="intel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    p = sub.add_parser("parse")
    p.add_argument("file")
    f = sub.add_parser("fetch")
    f.add_argument("feed")
    f.add_argument("--limit", type=int, default=50)
    f.add_argument("--offline", action="store_true")
    f.add_argument("--no-cache", action="store_true")
    f.add_argument("--param", action="append", default=[], metavar="K=V")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "list":
            for feed in sources.FEEDS.values():
                print(json.dumps(feed.public()))
            return 0
        if a.cmd == "parse":
            with open(a.file, "rb") as fh:
                data = fh.read(parsers.MAX_BYTES + 1)
            iocs = parsers.parse_any(data, source=a.file.rsplit("/", 1)[-1])
        else:
            params = dict(kv.split("=", 1) for kv in a.param if "=" in kv)
            iocs = sources.fetch(a.feed, limit=a.limit, cache=not a.no_cache, offline=a.offline, **params)
        for i in iocs:
            print(json.dumps(i))
        return 0
    except (sources.FeedError, ValueError, OSError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
