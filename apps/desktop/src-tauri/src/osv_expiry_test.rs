#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn current_date_utc() -> (i32, u32, u32) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Days since Epoch (1970-01-01)
        let days = (secs / 86400) as i64;

        // Howard Hinnant's algorithm for converting days since 1970-01-01 to Y/M/D
        let z = days + 719468;
        let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
        let doe = (z - era * 146097) as u32;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = (yoe as i64) + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        (y as i32, m, d)
    }

    #[test]
    fn glib_advisory_is_fixed_without_suppression() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let osv_toml = fs::read_to_string(manifest_dir.join("osv-scanner.toml"))
            .expect("apps/desktop/src-tauri/osv-scanner.toml must exist");
        assert!(
            !osv_toml.contains("RUSTSEC-2024-0429"),
            "the glib VariantStrIter advisory must be fixed, not suppressed"
        );

        let lock = fs::read_to_string(manifest_dir.join("Cargo.lock"))
            .expect("apps/desktop/src-tauri/Cargo.lock must exist");
        let glib = lock
            .split("[[package]]")
            .find(|section| section.contains("name = \"glib\""))
            .expect("Cargo.lock must contain glib");
        assert!(
            glib.contains("version = \"0.20.")
                || glib.contains("version = \"0.21.")
                || glib.contains("version = \"0.22."),
            "glib must resolve to a patched >=0.20 release; lock section was: {glib}"
        );
        assert!(
            !lock.contains("name = \"glib\"\nversion = \"0.18."),
            "the vulnerable glib 0.18 line must not remain in Cargo.lock"
        );
    }

    #[test]
    fn osv_scanner_exceptions_have_not_expired() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let osv_toml_path = manifest_dir.join("osv-scanner.toml");
        let content = fs::read_to_string(&osv_toml_path)
            .expect("apps/desktop/src-tauri/osv-scanner.toml must exist");

        let (cur_y, cur_m, cur_d) = current_date_utc();
        let cur_formatted = format!("{cur_y:04}-{cur_m:02}-{cur_d:02}");

        let mut current_id = None;
        let mut current_until = None;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("id =") {
                if let Some(id) = line.split('=').nth(1) {
                    current_id = Some(id.trim().trim_matches('"').to_string());
                }
            } else if line.starts_with("ignoreUntil =") {
                if let Some(until) = line.split('=').nth(1) {
                    let date_str = until.trim().trim_matches('"');
                    current_until = Some(date_str.to_string());
                }
            }

            if let (Some(id), Some(until)) = (&current_id, &current_until) {
                assert!(
                    until.as_str() >= cur_formatted.as_str(),
                    "OSV exception for {id} expired on {until} (current date: {cur_formatted})"
                );
                current_id = None;
                current_until = None;
            }
        }
    }
}
