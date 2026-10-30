//! Product directory discovery. Resolution never creates or moves directories.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

// LIVE-MIGRATION BRIDGE arn:lmig:smalltalk:2026-10-16-state-dirs-fractal — DELETE at contraction — #3032
/// A destination-local receipt: exact migration ID followed by a newline.
/// Only the later migration's independently verified completion may write it.
pub const RECEIPT_FILE: &str = ".fractal-migration-completed";
pub const MIGRATION_ID: &str = "arn:lmig:smalltalk:2026-10-16-state-dirs-fractal";
static WARNED: AtomicBool = AtomicBool::new(false);

/// Locate completed migrated data; unreceipted destinations never become authoritative.
/// With neither directory present, callers still create the legacy directory.
pub fn resolve(old: PathBuf, new: PathBuf) -> PathBuf {
    if !new.exists() {
        return old;
    }
    if !completed(&new) {
        if !WARNED.swap(true, Ordering::Relaxed) {
            eprintln!(
                "st: {} has no completed migration receipt; using {}",
                new.display(), old.display()
            );
        }
        return old;
    }
    new
}

fn completed(directory: &Path) -> bool {
    std::fs::read_to_string(directory.join(RECEIPT_FILE))
        .is_ok_and(|receipt| receipt.strip_suffix('\n') == Some(MIGRATION_ID))
}

