# Security Policy

## Supported versions

Only the latest release receives security fixes. The current release is 1.5.0
(`version.txt`; see `CHANGELOG.md`). Releases before 1.5.0 do not carry signed
OTA images and are not patched; upgrade instead.

## Reporting a vulnerability

Use GitHub's private reporting: open the **Security** tab of this repository,
choose **Advisories**, and click **Report a vulnerability**.

Please do not put exploit details, proof-of-concept code or crash dumps that
reveal credentials in public issues, pull requests or discussions. If you are
unsure whether something is a vulnerability, report it privately first; it can
be made public later.

## In scope

* The web UI and its HTTP API (authentication, sessions, CSRF, input handling,
  XSS, request parsing).
* The DNS server on UDP/TCP 53, including the Layer 2 Ethernet fast path.
* The OTA update path and image signature check.
* The USB recovery console, where it can be reached without physical access.
* The browser flasher in `docs/flasher/` and the binaries published in
  `docs/firmware/`.

Out of scope: attacks that need physical or USB access to the board (see the
threat model below), denial of service from a host already allowed to send
traffic to the device, and vulnerabilities in ESP-IDF or upstream blocklists
themselves (report those to their maintainers).

## Threat model

The device is designed for a trusted home or office LAN. It is not meant to be
exposed to the internet.

What it does:

* The web UI is served over HTTPS only, with a self-signed ECDSA P-256
  certificate generated on first boot. Port 80 only redirects.
* Admin login uses PBKDF2-HMAC-SHA256 password hashing, sessions with idle and
  absolute timeouts (`HttpOnly; Secure; SameSite=Strict` cookie), and CSRF
  tokens (`main/web_auth.c`, `main/web_ui.cpp`).
* From 1.5.0, OTA images must carry an RSA-3072 signature from the project key
  (`CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT` in `sdkconfig.defaults`). An
  admin session alone cannot install arbitrary firmware over the network.

What it does not do:

* **There is no Secure Boot and no flash encryption.** The signature check
  runs in the application, not in the ROM bootloader, so it does not protect
  against someone who can write flash directly.
* Anyone with physical or USB access can read the flash and NVS, which holds
  the Wi-Fi password, the admin password hash, the setup passphrase and the TLS
  private key, and can reflash the board with any image.
* The USB console has recovery commands (for example `admin-reset`) that need
  no login; treat the USB port as a trusted interface.
* Serial flashing (esptool, the web flasher) is not restricted by the app
  signature.

If your threat model includes an attacker with hands on the device, this
firmware does not defend against that.
