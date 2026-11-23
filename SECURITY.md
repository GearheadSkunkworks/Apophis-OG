# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's "Report a vulnerability" button on this repository's Security tab. Do not open a public issue for a vulnerability. Include what you found, how to reproduce it, and the version (see `dev/VERSION`).

You can expect an acknowledgement within a few days. This is a one-maintainer project, so fixes are made as time allows; critical problems in the update path are handled first.

If the private reporting button is ever unavailable, open an issue that says only that you have a security report and asks for a private way to send it. Do not put details in it.

## Scope

The local web server (127.0.0.1 only), the update mechanism (`dev/updater.py`, `dev/overlay.py`), and the build and release tooling. Updates are verified with an Ed25519 signature before they are installed; a report that bypasses that check is the highest priority.

## Not vulnerabilities

The generated captures intentionally contain traffic that emulates attacks. That is the product, not a flaw.

## How the local server is protected

The server listens on 127.0.0.1 only, checks the Host and Origin of every request, refuses to be framed by another page, and limits request sizes. It does not use a per-session token: any program already running as you can read the page and use the app, so a token would not stop it, and the Origin check already stops other websites. If you disagree, please report it.
