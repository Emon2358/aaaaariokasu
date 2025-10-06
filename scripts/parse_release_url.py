#!/usr/bin/env python3
# scripts/parse_release_url.py
# Usage:
#   python3 scripts/parse_release_url.py "https://github.com/owner/repo/releases/tag/TAG"
# Behavior:
#   prints two lines:
#     owner/repo
#     tag    (or "latest")
# Robust: uses argv[1] if present, else environment variable RELEASE_URL, else stdin.

import sys
import re
import urllib.parse
import os

def fail(msg):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(2)

def main():
    url = None
    if len(sys.argv) > 1 and sys.argv[1]:
        url = sys.argv[1]
    else:
        url = os.environ.get("RELEASE_URL")
        if not url:
            # try stdin
            data = sys.stdin.read().strip()
            if data:
                url = data
    if not url:
        fail("no URL provided (argv, RELEASE_URL or stdin)")

    # Normalize: allow full URL or just owner/repo@tag etc.
    # Parse URL
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        fail("failed to parse URL: " + repr(url))

    path = p.path or url  # fallback to raw string
    # Try common patterns:
    # /owner/repo/releases/tag/TAG
    m = re.match(r'^/([^/]+)/([^/]+)/releases/(?:tag|download)/(.+)$', path)
    if m:
        owner, repo, tag = m.group(1), m.group(2), m.group(3)
    else:
        # support /owner/repo/releases/latest
        m2 = re.match(r'^/([^/]+)/([^/]+)/releases/?(latest)?$', path)
        if m2:
            owner, repo = m2.group(1), m2.group(2)
            tag = 'latest'
        else:
            # also allow formats like owner/repo@tag or owner/repo:tag
            m3 = re.match(r'^([^/@:]+/[^/@:]+)[@\:](.+)$', url)
            if m3:
                owner_repo = m3.group(1)
                owner, repo = owner_repo.split('/',1)
                tag = m3.group(2)
            else:
                # try if input was "owner/repo" -> default to latest
                m4 = re.match(r'^([^/]+/[^/]+)$', url)
                if m4:
                    owner, repo = m4.group(1).split('/',1)
                    tag = 'latest'
                else:
                    fail("couldn't parse release URL: " + url)

    owner_repo = owner + "/" + repo
    print(owner_repo)
    print(tag)

if __name__ == "__main__":
    main()
