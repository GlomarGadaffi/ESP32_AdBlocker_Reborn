# `docs/firmware/` — same-origin firmware for the browser flasher

Generated. **Do not hand-edit**; `tools/make-release.ps1` writes this directory
each time it packages a release.

## Why it exists

A browser cannot fetch a GitHub Release asset. `browser_download_url` 302s to
`release-assets.githubusercontent.com`, and neither the redirect nor the final
response carries `Access-Control-Allow-Origin`, so every download fails CORS.
`api.github.com` *is* CORS-enabled, which is what made this so easy to miss:
listing the release worked and only the downloads failed, so the flasher looked
healthy right up until someone pressed **Flash** (#116).

Serving the images from `docs/` puts them on the same origin as the flasher, so
CORS never applies.

The GitHub Release stays the source of truth and keeps every asset. Pages
carries only what the page actually downloads: the `.bin` images and
`manifest.json`.

## Layout

```
docs/firmware/
  index.json          # {latest, releases:[{version, tag, date, files:[{name,size}]}]}
  1.3.0/
    manifest.json     # boards -> parts[{offset,file,role,size}] + flash settings
    t-eth-elite-1.3.0-bootloader.bin
    t-eth-elite-1.3.0-partition-table.bin
    t-eth-elite-1.3.0-ota_data_initial.bin
    t-eth-elite-1.3.0-app.bin
    ...               # same four images per board
```

`index.json` carries an explicit `files` array because GitHub Pages serves no
directory listing — it is what lets the page rebuild the asset map it used to
get from the API without a second round trip.
