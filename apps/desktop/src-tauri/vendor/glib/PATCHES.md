# Local glib compatibility patch

This directory is the crates.io `glib` 0.18.5 source used by the desktop
workspace. It is kept local because Tauri 2.x's GTK3 bindings require the
0.18 API, while the `VariantStrIter` soundness fix was first released in
`glib` 0.20.0.

The only source change from the published 0.18.5 crate is the upstream fix
from [gtk-rs/gtk-rs-core commit
`b5a4071e439bef2b5eea76c3aa25e5ae84839e34`](https://github.com/gtk-rs/gtk-rs-core/commit/b5a4071e439bef2b5eea76c3aa25e5ae84839e34):

```diff
- let p: *mut libc::c_char = std::ptr::null_mut();
+ let mut p: *mut libc::c_char = std::ptr::null_mut();
...
- &p,
+ &mut p,
```

`g_variant_get_child` writes through its output pointer. Passing `&p` to
that write violates Rust's aliasing rules and can leave the pointer null when
optimized; the upstream change passes `&mut p` instead. No API or behavior
outside this soundness fix is changed.

The published source checksum used as the comparison baseline is
`233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5`.
Keep this patch until the Tauri dependency can move to a maintained GTK
binding line with `glib >= 0.20`; then remove the local `[patch.crates-io]`
entry and this directory together.
