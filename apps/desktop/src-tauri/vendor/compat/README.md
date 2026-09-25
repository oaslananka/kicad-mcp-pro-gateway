# GTK3 / glib 0.20 compatibility set

This directory is a temporary compatibility layer for Tauri 2.11.x on Linux.
The published Tauri stack still constrains GTK3 bindings to the gtk-rs 0.18
package line, which in turn resolves `glib` 0.18 and triggers
`RUSTSEC-2024-0429` / `GHSA-wrw7-89jp-8q8g`.

The vendored crates retain their published package versions so existing Tauri
semver constraints continue to resolve, but their gtk-rs-core dependency
requirements are rebased to the maintained `0.20` line. Source changes are
limited to API moves required by that rebase (for example `IsA`, `Cast`,
`ObjectExt` moving into `glib::prelude`) plus the Linux event-channel adaptation
needed because the old glib channel API is no longer available. No vulnerable
`glib` source is vendored here.

Provenance of package baselines:

- Tauri `2.11.6`
- tauri-runtime `2.11.3`
- tauri-runtime-wry `2.11.4`
- tao `0.35.3`
- wry `0.55.1`
- gtk/gdk/atk `0.18.2`
- webkit2gtk `2.0.2`
- javascriptcore-rs `1.1.2`
- soup3 `0.5.0`
- libappindicator `0.9.0`

The compatibility result is verified with both the default toolchain and the
repository MSRV (`cargo +1.88.0 check --all-targets --locked`). The lockfile must
contain `glib >= 0.20` and no `glib 0.18.x`. OSV remains fail-closed; the glib
advisory is deliberately not listed in `osv-scanner.toml`.

Security hardening applied while vendored: GDK user-data lookup returns `None`
for a null native pointer instead of dereferencing it, and native cookies read
from WebKit/WebView2/WKWebView are normalized to `Secure=true` before they are
exposed through Wry. The Gateway shell does not support insecure-cookie
round-trips, so this prevents a read/modify/write path from downgrading cookie
transport security.

Remove this directory when upstream Tauri publishes a release whose Linux GTK3
stack resolves to maintained gtk-rs/glib packages without compatibility patches.
