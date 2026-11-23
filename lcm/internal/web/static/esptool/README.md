# esptool-js (vendored)

`esptool.js` is `bundle.js` of the npm package `esptool-js` 0.7.1 (Espressif, Apache-2.0),
unmodified. It bundles `pako` 2.1.0 (MIT) and `atob-lite` 2.0.0 (MIT); their licenses are next to it.
Used only by `../flash.js` (admin UI → Прошивка USB). Served from the server itself: the CSP
(`default-src 'self'`) forbids CDNs.

sha256 d6a4b0b7c9b747a7370cfa976164a962f56332d5faa7c3b45cdb95a2a8b1d456

Update: `npm pack esptool-js@<version>`, copy `package/bundle.js` here as `esptool.js`, update the
version and hash above, check `flash.js` against the API (`ESPLoader.main`, `writeFlash`, `after`).
