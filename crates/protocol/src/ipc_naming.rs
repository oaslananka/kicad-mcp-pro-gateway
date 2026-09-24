//! Derives the local IPC endpoint name (named pipe on Windows, Unix domain
//! socket elsewhere) from a data directory, so the daemon and its clients
//! always agree on where to connect without either side hard-coding a
//! global name that could collide across two Gateway installs pointed at
//! different data directories.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;

pub fn socket_name(data_dir: &Path) -> String {
    let mut hasher = DefaultHasher::new();
    data_dir.hash(&mut hasher);
    format!("kicad-mcp-gateway-{:x}.sock", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_data_dir_produces_the_same_name() {
        let path = Path::new("/tmp/gateway-data");
        assert_eq!(socket_name(path), socket_name(path));
    }

    #[test]
    fn different_data_dirs_produce_different_names() {
        let a = Path::new("/tmp/gateway-data-a");
        let b = Path::new("/tmp/gateway-data-b");
        assert_ne!(socket_name(a), socket_name(b));
    }
}
