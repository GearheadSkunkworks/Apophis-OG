# Releases and updates

## Versions

Versions are `MAJOR.MINOR.PATCH`.

- **A full release (X.Y.0)** is a new download: the Mac app zip, attached to a [GitHub Release](https://github.com/GearheadSkunkworks/Apophis-OG/releases). Download it, unzip it, and run it.
- **A patch (X.Y.Z, where Z is above 0)** is an update the app installs by itself. It replaces the app's own code and data, never Python or the libraries inside the app, so anything that needs those ships as a full release.

Release notes for each full release are in this folder (for example `release-notes-5.3.0.md`).

## The Update button

In the Mac app, the **Update** button in the top bar checks this repository's GitHub Releases for a newer patch on your version's line (the same X.Y). If there is one it shows the signed release notes and asks before installing; installing restarts the app. If a newer full release exists, the button points you to the Releases page instead.

Running from source, the app cannot update itself; use `git pull`.

The only thing the check contacts is GitHub. Nothing about you or your captures is sent.

## How an update is verified

Each patch comes with a manifest listing its version, its release notes, the checksum of the update file and the checksum of every file inside it. The manifest is signed with an Ed25519 key, and the matching public key is built into the app.

- The app only reads release files from GitHub hosts, and only accepts an update that is signed, newer, and on its own X.Y line.
- Before installing, it checks that the files match the signed list exactly.
- On every start it checks again. If any installed file was changed, added or removed, or the signature is missing, the update is set aside and the bundled app runs instead.
- If a patched start never finishes, the next start also sets the patch aside. The previous patch is kept.

## If the signing key is lost or exposed

The maintainer stops publishing patches and publishes a new full release whose app contains a new public key. Users then install that release by hand. Old installs keep trusting the old key until they do, which is why the key is kept encrypted and off GitHub.
