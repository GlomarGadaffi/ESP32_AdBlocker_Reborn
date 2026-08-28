# Browser flasher

`index.html` is a single, dependency-free page that installs this firmware onto
a board over USB, using the [Web Serial API][webserial] to drive
[esptool-js][esptool-js] entirely inside the browser. It is served from GitHub
Pages at:

**<https://glomargadaffi.github.io/ESP32_AdBlocker_Reborn/flasher/>**

Nothing is uploaded anywhere. The page fetches firmware images from this
repository's latest GitHub Release and writes them to the board from the user's
own machine.

## Requirements

* **Chrome, Edge, or Opera on desktop.** Web Serial exists nowhere else — not
  Firefox, not Safari, not any mobile browser. The page detects this and shows
  an explanation instead of a broken UI.
* **HTTPS or `localhost`.** Web Serial requires a secure context. GitHub Pages
  serves over HTTPS, so the published URL is fine; `file://` is also a secure
  context but is a worse test target (see *Local development*).
* **No other program holding the serial port.** This bites Windows users
  constantly: `idf.py monitor`, PuTTY, the Arduino IDE, and VS Code serial
  terminals all take exclusive ownership of a COM port. The page says so up
  front, and translates the resulting error into that advice.

## How it works

1. **Connect.** `navigator.serial.requestPort()` → `Transport` → `ESPLoader`.
   `loader.main()` syncs with the ROM bootloader, identifies the chip, uploads
   the flasher stub, and raises the baud rate to 921600. Everything afterwards
   runs against the stub, on one connection — the page never reconnects between
   detecting and flashing.

2. **Detect the board.** Both supported boards are ESP32-S3 with 16 MB flash, so
   nothing about the chip distinguishes them. The firmware instead stamps the
   board into its own version string: `CMakeLists.txt` sets
   `PROJECT_VER` to `"<semver>+<board>"`, which lands in `esp_app_desc_t.version`.

   The page reads that descriptor back off the flash with `loader.readFlash()`.
   The descriptor sits at **app partition + 0x20** (after the 24-byte image
   header and the 8-byte first segment header), so it reads `0x100` bytes from
   `0x20020` (ota_0) and `0x1d0020` (ota_1). Relevant fields:

   | Offset | Type       | Field          |
   | -----: | ---------- | -------------- |
   |      0 | `u32` LE   | magic `0xABCD5432` |
   |      4 | `u32`      | `secure_version` |
   |      8 | `u32[2]`   | `reserv1` |
   |     16 | `char[32]` | `version` &larr; the board tag lives here |
   |     48 | `char[32]` | `project_name` (`"dns-sink"`) |
   |     80 | `char[16]` | `time` |
   |     96 | `char[16]` | `date` |
   |    112 | `char[32]` | `idf_ver` |
   |    144 | `u8[32]`   | `app_elf_sha256` |

   **Both slots are read unconditionally**, because either one's tag answers the
   board question. `otadata` (two 32-byte entries at `0xf000` and `0xf000+0x1000`,
   each starting with a `u32 ota_seq`; highest valid seq wins, mapped to a slot
   with `(seq - 1) % 2`, both `0xFFFFFFFF` meaning ota_0) is used only to label
   which build is *running*, so a confusing otadata can't break detection.

   Auto-selection is deliberately conservative. `0xABCD5432` is the generic
   ESP-IDF app-descriptor magic — **every** IDF application has it, so its
   presence proves nothing. A board is only auto-selected when the descriptor is
   valid **and** `project_name == "dns-sink"` **and** the version carries a `+`
   suffix **and** that suffix is a board id the page knows. Anything else — a
   blank chip, foreign firmware, an untagged older build, or a `readFlash` that
   fails — falls back to the manual picker, and the user can always override the
   detection anyway.

3. **Fetch the release.** The page calls
   `https://api.github.com/repos/GlomarGadaffi/ESP32_AdBlocker_Reborn/releases/latest`,
   finds the `manifest.json` asset, and fetches it via `browser_download_url`.
   Both work as plain unauthenticated `fetch` calls: the API sends CORS headers,
   and asset downloads redirect to `objects.githubusercontent.com`, which sends
   `Access-Control-Allow-Origin: *`.

   Missing release, missing manifest, and the unauthenticated 60-requests-per-hour
   rate limit are all handled as explained states that steer the user to the
   local-file panel, not as a dead page.

4. **Flash.** Every image is downloaded *before* the first byte is written, so a
   network failure can't leave the board half-written. `writeFlash` is called with
   `eraseAll: false` — this is what preserves NVS, and therefore the saved
   Wi-Fi credentials, settings, and blocklists — and `compress: true`. Flash
   mode, frequency, and size come from the manifest, which
   `tools/make-release.ps1` derives from the build's own `flash_args`.

5. **Reset.** `loader.after("hard_reset", usingUsbOtg)`. The second argument
   matters on these boards: the ESP32-S3's native USB-Serial-JTAG (CDC-ACM)
   needs the USB-OTG reset path rather than DTR/RTS toggling. The page decides
   by comparing `transport.getPid()` against `loader.USB_JTAG_SERIAL_PID` rather
   than hardcoding a PID, so it also does the right thing on a board wired
   through a USB-UART bridge.

## Flash modes

| Mode | Writes | When |
| ---- | ------ | ---- |
| **Full flash** | bootloader `0x0`, partition table `0x8000`, otadata `0xf000`, app `0x20000` | First install, and after any partition-table or bootloader change |
| **App only** | otadata `0xf000`, app `0x20000` | Upgrading firmware already running on this board — the same regions the OTA path touches |

Neither mode erases the whole chip, so NVS survives both.

There is also a **Flash your own build** panel: a file input per region with an
editable offset, for people building locally who don't want to install a
toolchain's flasher.

## Release contract

`tools/make-release.ps1` produces everything the page consumes. Run it after
building both boards, then attach the whole `release/` directory to a GitHub
Release; the page always reads whichever release is *latest*.

Asset names are `<board>-<version>-<part>.bin`, where part is one of
`bootloader`, `partition-table`, `ota_data_initial`, `app`. Alongside them,
`manifest.json`:

```json
{
  "version": "1.1.0",
  "boards": {
    "t-eth-elite": {
      "name": "LilyGO T-ETH-Elite",
      "parts": [
        { "offset": 0,      "file": "t-eth-elite-1.1.0-bootloader.bin",       "role": "bootloader",      "size": 19904 },
        { "offset": 32768,  "file": "t-eth-elite-1.1.0-partition-table.bin",  "role": "partition-table", "size": 3072 },
        { "offset": 61440,  "file": "t-eth-elite-1.1.0-ota_data_initial.bin", "role": "ota-data",        "size": 8192 },
        { "offset": 131072, "file": "t-eth-elite-1.1.0-app.bin",              "role": "app",             "size": 1187152 }
      ]
    },
    "waveshare-s3-eth": { "name": "Waveshare ESP32-S3-ETH", "parts": [ "..." ] }
  },
  "flash": { "size": "16MB", "mode": "dio", "freq": "80m" }
}
```

Offsets are decimal in JSON (`61440` = `0xf000`). `role` and `size` are additions
beyond the minimum: **`role`** is what lets App-only mode pick its two parts
without re-hardcoding `0xf000`/`0x20000` in the page — exactly the offsets the
script just finished parsing out of `flash_args`. Older manifests without `role`
still work; the page falls back to matching on offset.

Board ids (`t-eth-elite`, `waveshare-s3-eth`) are load-bearing in three places
that must stay in sync: `ADBLOCK_BOARD_TAG` in `CMakeLists.txt`, the `$Boards`
table in `tools/make-release.ps1`, and the `BOARDS` table in `index.html`.

## Local development

Serve over `http://localhost` rather than opening the file directly — localhost
counts as a secure context, so Web Serial works, and you avoid the opaque-origin
problems that can make an ESM import from a CDN fail on `file://` for reasons
unrelated to your code:

```powershell
python -m http.server 8000
# then open http://localhost:8000/docs/flasher/
```

esptool-js is imported as an ES module from jsDelivr at a **pinned exact
version** (currently `0.6.1`). Bump it deliberately: the library's API has
changed shape across releases — notably `FlashOptions.fileArray[].data` is a
`Uint8Array` in 0.6.x, whereas the project's own README example still shows the
older binary-string form.

`docs/.nojekyll` disables Jekyll for the Pages build. Without it, Liquid
templating runs over the source and would eat any `{{` or `{%` appearing in the
JavaScript.

[webserial]: https://developer.mozilla.org/docs/Web/API/Web_Serial_API
[esptool-js]: https://github.com/espressif/esptool-js
