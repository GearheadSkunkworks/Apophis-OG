# Building the macOS app

**PyInstaller is the build.** It is the path that has actually been built and tested here — see
"The build that works", below, which is a verbatim, verified recipe. (py2app was dropped: its latest release
predates Python 3.14, it was never exercised on this project, and a second packaging list only drifts.)

Do the build on macOS, in a clean venv.

## Running it without building anything

`./run.command` (double-click in Finder) is the supported way to run the app from source. It
checks for a usable Python and `cryptography`, offers to install the dependency if it is
missing, reports whether `tcpreplay` is present, verifies the application files, and keeps the
Terminal window open if anything fails. Build an `.app` only when you need to hand the tool to
someone who will not run a script.

## 0. Prerequisites
- macOS 12+ and the matching Python 3.11+ (python.org or Homebrew).
- Command Line Tools: `xcode-select --install`.
- `tcpreplay` for the replay feature: `brew install tcpreplay`. It is **not** bundled into the
  `.app` — it stays an external dependency, and the UI reports it as missing if absent.
- For distribution (not just your own machine): an Apple Developer account for signing +
  notarization.

## The build that works (verified)

Built and verified on **macOS 15.7.9 / arm64 / Python 3.14.5** with **PyInstaller 6.22.3** and
**cryptography 50.0.1**. Produces a **36 MB** `.app` in about 100 seconds.

```
# 1. a build venv OUTSIDE the project folder, so the folder stays self-contained/portable
python3 -m venv /tmp/og-build-venv
/tmp/og-build-venv/bin/pip install --upgrade pip
/tmp/og-build-venv/bin/pip install cryptography tzdata pyinstaller

# 2. build. P must be an ABSOLUTE path to this folder (see the --specpath gotcha below)
P=<absolute path of the release/ folder>     # build from the tested release candidate
B=/tmp/og-build
cd "$P"
# PYTHONPATH matters: the spec PyInstaller writes runs collect_submodules() before --paths is applied, so without it
# the netgen/intel/diagrams submodules are silently NOT collected and the app starts with only some campaign actions.
PYTHONPATH="$P" /tmp/og-build-venv/bin/pyinstaller --noconfirm --windowed \
  --name "OpenGenerator" --icon "$P/assets/gearhead.icns" \
  --osx-bundle-identifier com.example.trafficgen \
  --distpath "$B/dist" --workpath "$B/build" --specpath "$B" \
  --add-data "$P/ui:ui"                  --add-data "$P/assets:assets" \
  --add-data "$P/opengenerator_build.py:."   --add-data "$P/replay.py:."   --add-data "$P/sensorops:sensorops" \
  --add-data "$P/deps.py:."              --add-data "$P/make_diagram.py:." \
  --add-data "$P/inventory.py:."         --add-data "$P/inventory.json:." \
  --add-data "$P/VERSION:." \
  --add-data "$P/modules:modules" \
  --add-data "$P/campaign_api.py:."      --add-data "$P/sessions_api.py:." \
  --add-data "$P/scenario_meta.py:."     --add-data "$P/scenario_meta.json:." --add-data "$P/scenario_scale.json:." \
  --add-data "$P/docs/redesign/meta-verification.json:docs/redesign" \
  --hidden-import settings_store --hidden-import overlay --hidden-import updater --hidden-import captures_store --hidden-import page_template --hidden-import build_manifest \
  --collect-submodules intel \
  --add-data "$P/geo:geo"  --collect-submodules diagrams \
  --add-data "$P/netgen/campaign/attack.json:netgen/campaign" \
  --add-data "$P/netgen/campaign/campaign.schema.json:netgen/campaign" \
  --add-data "$P/netgen/campaign/actions/specs:netgen/campaign/actions/specs" \
  --paths "$P" --collect-submodules netgen --collect-all cryptography --collect-data tzdata \
  "$P/server.py"

# 2b. verify the bundle before going on: launch it with `--no-browser --no-autoquit`, then
#     curl http://127.0.0.1:<port>/api/campaign/actions  must list every action (50 at 5.1.0), not a handful.

# 3. PyInstaller's --name sets CFBundleName too, and macOS truncates that in the menu bar
#    past ~16 characters. Give the menu bar the short form; Finder keeps the full name.
/usr/libexec/PlistBuddy -c "Set :CFBundleName 'OpenGenerator'" \
  "$B/dist/OpenGenerator.app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleDisplayName string 'OpenGenerator'" \
  "$B/dist/OpenGenerator.app/Contents/Info.plist" 2>/dev/null || true
# PyInstaller leaves both at 0.0.0. VERSION (shipped in the bundle, and read by make_diagram for
# the About page) is the single source: the bundle, the About page and the zip name all follow it.
V="$(tr -d '[:space:]' < "$P/VERSION")"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString '$V'" \
  "$B/dist/OpenGenerator.app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion '$V'" "$B/dist/OpenGenerator.app/Contents/Info.plist" 2>/dev/null \
  || /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string '$V'" "$B/dist/OpenGenerator.app/Contents/Info.plist"

# 4. ad-hoc sign LAST -- editing Info.plist after signing invalidates the signature
#    (adequate for your own Mac; see below for handing it to others)
codesign --force --deep --sign - "$B/dist/OpenGenerator.app"
codesign --verify --deep --strict "$B/dist/OpenGenerator.app"

# 5. zip it for transfer -- --norsrc --noextattr is NOT optional, see below
cd "$B/dist"
ditto -c -k --keepParent --norsrc --noextattr \
      "OpenGenerator.app" "OpenGenerator-$V-app.zip"
```

### Zipping the .app for someone else: use --norsrc --noextattr

A plain `ditto -c -k --keepParent` stores extended attributes as **AppleDouble** entries. Any
extractor that does not understand those — `unzip(1)`, several third-party unarchivers, and any
round trip through a non-Mac system — writes them out as literal `._Contents`, `._Info.plist`,
`._Frameworks` files *inside the bundle*. Measured: 266 entries extracted with `ditto`, **530**
with `unzip`, the extra 264 all `._*`.

Those stray files are unsealed resources, so the signature fails:

```
codesign --verify --deep --strict  ->  a sealed resource is missing or invalid
```

and macOS refuses the bundle with **"The application ... can't be opened."** Note the wording:
that is the *broken bundle* error, not the Gatekeeper one ("Apple could not verify...", "is
damaged"). They have different causes and different fixes, so read the message before acting.

`--norsrc --noextattr` writes no AppleDouble at all, so the archive extracts identically with
`ditto` **and** `unzip`: 265 entries, 0 `._*` files, 40 symlinks preserved, signature intact.
The symlink count matters too — this bundle contains 40 symlinks (`Contents/Resources/Python`,
`Python.framework`, the OpenSSL dylibs); an archiver that flattens them produces a different
broken bundle with the same unhelpful error.

### The two failure modes are independent

| Symptom | Cause | Fix |
|---|---|---|
| "The application ... can't be opened." | `._*` files or flattened symlinks from a naive extraction | re-send a `--norsrc --noextattr` zip, or extract with `ditto -x -k` / double-click in Finder |
| "Apple could not verify..." / "is damaged" | ad-hoc signature, not notarized | `xattr -dr com.apple.quarantine <app>` then right-click > Open; properly, Developer ID + notarization |

A recipient can also repair a mangled copy in place, since the signature is ad-hoc anyway:

```
find "/path/to/OpenGenerator.app" -name '._*' -delete
codesign --force --deep --sign - "/path/to/OpenGenerator.app"
xattr -dr com.apple.quarantine "/path/to/OpenGenerator.app"
```

### Gotchas this build hit (all fixed in the source — do not reintroduce)

1. **`--specpath` re-bases relative `--add-data` sources.** With `--specpath` pointing outside
   the project, `--add-data "ui:ui"` is resolved against the *spec* directory and the build
   dies with `Unable to find '.../ui'`. Use absolute source paths, as above.
2. **`APP_DIR` must be frozen-aware.** `server.py`, `make_diagram.py` and `deps.py` compute
   `APP_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))`. Bundled
   data lives in `sys._MEIPASS`, so a plain `__file__` lookup finds neither `ui/index.html`,
   `assets/logo-color.svg`, `inventory.json` nor the engine.
3. **The campaign builder adds three things to the command above:** `campaign_api.py` (a data file the server imports), `--collect-submodules intel`, and the two JSON data files under `netgen/campaign` (`--collect-submodules` does not bring data files). `--add-data "$P/ui:ui"` already covers the new `ui/campaigns*.js`, `.css` and `geo-world.json`. The sensor-feedback and board work adds the `geo` folder (bundled country data, `--add-data "$P/geo:geo"`).

3b. **`netgen/` is embedded, not extracted.** `--collect-submodules netgen` puts it in the
   archive as importable modules, so there is no `netgen/__init__.py` on disk inside the
   bundle. `deps._check_engine()` skips its file-existence check when `sys.frozen` and relies
   on the import instead — otherwise the packaged app reports "the application folder is
   incomplete" and **disables its own Generate button**.
4. **`inventory.py` must never be respawned when frozen.** `sys.executable` is the app, so
   `subprocess.run([sys.executable, "inventory.py"])` would relaunch the GUI. `build()` raises
   a clear error instead; the server seeds the bundled `inventory.json` so it never fires.
5. **`modules/` must be added as data, not left to import analysis.** The v5b capability kernel
   discovers modules by reading `modules/<name>/manifest.json` off disk (`platform.MODULES_DIR`,
   which honours `sys._MEIPASS`) and imports `modules.<name>` dynamically at run time, so
   PyInstaller's static analysis never sees them. `--add-data "$P/modules:modules"` ships the
   tree as real files — importable (PyInstaller puts `_MEIPASS` on `sys.path`, and
   `modules/__init__.py` makes it a package) and discoverable. Each module's own imports
   (`opengenerator_build`, `branding`, `netgen.*`, `sensorops.*`, `make_diagram`) are already
   collected via `server.py`'s analysis + `--collect-submodules netgen` + the `sensorops` data
   add, so no per-module hidden-import flags are needed. The per-install `enabled.json` is left
   out of `/release`, and the bundle dir is read-only, so auto-load-on-startup does not persist
   inside a built `.app` (it degrades silently — `set_enabled` swallows the write error).

### Verified in the built .app

- All seven dependency chips green, including `cryptography` — the native `_rust.abi3.so`
  loads, which is the main packaging risk.
- Generated a real capture (400,000 packets, 123.5 MB, 55 cert files, threat collection,
  TLS key log): **0 bad checksums, 0 expert errors, 1,328 decryptable HTTPS requests**.
- **Stop** cancelled a scale-1.0 run and discarded the partial capture.
- Launched from **Finder**, `tcpreplay` / `tcprewrite` / `osascript` were all still found —
  the minimal-PATH trap is handled by `replay.find_tool()`.
- 29 selector rows, both top-level diagrams render with the bundled wordmark.

## PyInstaller, short form

```
cd <absolute path of the release/ folder>
python3 -m venv build-venv && source build-venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt tzdata pyinstaller
pyinstaller --windowed --name "OpenGenerator" \
    --add-data "ui:ui" \
    --add-data "assets:assets" \
    --add-data "opengenerator_build.py:." \
    --add-data "replay.py:." \
    --add-data "sensorops:sensorops" \
    --add-data "deps.py:." \
    --add-data "make_diagram.py:." \
    --add-data "inventory.py:." \
    --add-data "inventory.json:." \
    --add-data "scenario_meta.py:." \
    --add-data "scenario_meta.json:." \
    --add-data "VERSION:." \
    --collect-submodules netgen \
    --collect-all cryptography \
    --collect-data tzdata \
    server.py
# -> "dist/OpenGenerator.app"
```

`--collect-all cryptography` bundles its native libraries; `--collect-data tzdata` bundles the time-zone database (the app never relies on the system one); `--collect-submodules netgen`
pulls the whole generator package.

## Handing the .app to someone else

The build here is **ad-hoc signed** (`Signature=adhoc`, `TeamIdentifier=not set`) because this
Mac has no Developer ID certificate. It is a valid signature — `codesign --verify --deep
--strict` passes — but `spctl` rejects it, so **Gatekeeper will block it on another Mac**. That
is expected, not a broken build.

Two ways round it, in order of preference:

**1. Notarize it properly** (needs a paid Apple Developer account). Once a *Developer ID
Application* certificate is in the keychain, re-sign and notarize — see the commands below.
This is the only option that gives a colleague a clean double-click.

**2. Ship it unsigned and have them clear the quarantine flag.** The zip is built with
`ditto -c -k --keepParent`, which preserves the bundle structure and its signature:

```
ditto -c -k --keepParent "OpenGenerator.app" OpenGenerator-app.zip
```

The recipient unzips, then either:

- **right-clicks the app → Open**, and confirms once at the warning dialog (macOS then
  remembers the choice); or
- runs `xattr -dr com.apple.quarantine "/Applications/OpenGenerator.app"` after
  moving it into place.

Tell them which you expect — a colleague who just double-clicks will see *"Apple could not
verify..."* and reasonably assume the app is broken. They also need `brew install tcpreplay`
for the replay panel; everything else is inside the bundle.

## Signing & notarization (for sharing the .app)

To give it to others without Gatekeeper blocking it:

```
# 1) sign with a Developer ID Application certificate (hardened runtime)
codesign --deep --force --options runtime \
    --sign "Developer ID Application: Your Name (TEAMID)" \
    "dist/OpenGenerator.app"

# 2) zip and submit for notarization (store credentials once with notarytool)
ditto -c -k --keepParent "dist/OpenGenerator.app" NWTG.zip
xcrun notarytool submit NWTG.zip --keychain-profile "AC_PASSWORD" --wait

# 3) staple the ticket
xcrun stapler staple "dist/OpenGenerator.app"
```

Verify: `spctl -a -vvv "dist/OpenGenerator.app"` should report "accepted".

## Notes
- The app opens a browser tab to a local `127.0.0.1` port; no inbound network is used.
- Output files are large at `--scale 1` — a full day is **~8.2 GB** (10.1 M packets) and takes
  about 2½ minutes — and that is now the UI's default. Lower the scale for a smaller sample
  (0.05 ≈ 580 MB / 1.12 M packets). Measured 2026-09-17; the older ~6.3 GB / 7.87 M figure
  predates the cloud-egress and OS-patching traffic added in Phase 3s.
- `tcpreplay` / Wireshark are **not** bundled. `tcpreplay` is required for the replay panel
  (`brew install tcpreplay`); Wireshark is only for validating captures.

## Replay inside the built .app — check these

1. **PATH.** A Finder-launched bundle inherits a minimal `PATH` that usually lacks
   `/opt/homebrew/bin`. `replay.py` searches the Homebrew and sbin directories explicitly, so
   the dependency chips should still show `tcpreplay` in green. If they do not, that lookup is
   the first thing to check.
2. **The administrator prompt.** Replay elevates via `osascript ... with administrator
   privileges`. Confirm the native macOS dialog appears from the signed, hardened-runtime
   build, and that the replay actually starts after authorizing. No password is ever handled
   by the app itself, so nothing needs to be stored or entitled for credentials.
3. **Spawning.** The privileged launch runs `/bin/sh`, *not* a Python interpreter — the
   `sys.executable`-is-the-app trap that applies to the generator does not apply here, and must
   not be reintroduced.
