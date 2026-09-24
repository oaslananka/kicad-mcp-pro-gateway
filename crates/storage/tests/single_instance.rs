use companion_storage::{Storage, StorageError};

#[test]
fn second_open_against_same_directory_is_rejected_while_first_is_alive() {
    let dir = tempfile::tempdir().unwrap();
    let first = Storage::open(dir.path()).expect("first open succeeds");

    let second = Storage::open(dir.path());
    assert!(matches!(second, Err(StorageError::AnotherInstanceRunning)));

    drop(first);
}

#[test]
fn open_succeeds_again_after_prior_handle_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let first = Storage::open(dir.path()).expect("first open succeeds");
    drop(first);

    let second = Storage::open(dir.path());
    assert!(
        second.is_ok(),
        "expected second open to succeed after first handle dropped: {second:?}"
    );
}
