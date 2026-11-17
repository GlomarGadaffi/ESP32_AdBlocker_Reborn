# Releasing

Releases are cut by pushing a `v*` tag. `.github/workflows/release.yml` builds
the three boards in the `espressif/idf:release-v6.0` container, signs them with
the real OTA key, stages the artifacts with `tools/stage_release.py`, creates a
**draft** GitHub release, and opens a pull request that adds
`docs/firmware/<version>/` and updates `docs/firmware/index.json`. Nothing is
pushed to `main` directly.

## One-time setup

1. Add the repository secret `OTA_SIGNING_KEY_PEM`: the full contents of the
   RSA-3072 `secure_boot_signing_key.pem` that boards in the field trust. The
   workflow writes it to `secure_boot_signing_key.pem` for the build only, never
   prints it, and deletes it afterwards. If the secret is empty the build fails
   immediately; release builds never fall back to a throwaway key.
2. Settings > Actions > General > Workflow permissions: tick "Allow GitHub
   Actions to create and approve pull requests", or the PR step fails.

## Each release

1. Bump `version.txt` (e.g. `1.6.0`).
2. In `CHANGELOG.md`, rename `[Unreleased]` content into a `## [1.6.0] — YYYY-MM-DD`
   section. The draft's notes are that section; the workflow fails if it is missing.
3. Merge to `main`, then tag that commit and push the tag:
   `git tag v1.6.0 && git push origin v1.6.0`. The tag must equal
   `v$(cat version.txt)` or the build fails.
4. Wait for the Release workflow. Review the draft release (assets, notes,
   `SHA256SUMS`) and publish it.
5. Merge the `release/firmware-<version>` PR so the browser flasher serves the
   new images. PRs created with the workflow token do not trigger CI; close and
   reopen the PR if you need checks to run.

Re-running the workflow for the same tag fails at `gh release create` if the
draft already exists; delete the draft first. The PR branch is force-updated.

## What stage_release.py refuses

It exits 1, before writing anything, if:

- a build's `config/` has a non-empty `CONFIG_ADBLOCK_WIFI_SSID` or `_PASSWORD`
  (the 1.2.0 release leaked a home Wi-Fi PSK this way), or has no config files;
- `version.txt` differs from `--version`;
- an app image's embedded `esp_app_desc` version is not `<version>+<board>`;
- a board's build is missing or `flash_args` names a file that does not exist.

Offsets, flash mode/freq/size are read from each build's `flash_args`, so the
manifest follows the partition table. Run `python tools/stage_release.py -h`.
Use `--out-root <dir>` to stage somewhere other than the repo (tests do).

## make-release.ps1

`tools/make-release.ps1` is the local/offline fallback: same staging, run from
a laptop against local `build*` directories, printing a `gh release create`
command instead of running it. Prefer the tag workflow; a laptop build uses
whatever key and sdkconfig happen to be on that machine. Note the script
rewrites `index.json` with only the current release, while `stage_release.py`
merges into the existing list.
