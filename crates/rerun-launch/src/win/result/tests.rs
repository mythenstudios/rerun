//! The result file writer on real Windows, in a fresh folder under `target/` (never
//! `LocalAppData`). Junctions are made with `cmd /c mklink /J` (no admin needed).

#![expect(
    clippy::disallowed_methods,
    reason = "test fixtures: a scratch folder under target/, junctions through cmd.exe"
)]

use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::write;
use crate::os::OsError;
use rerun_proto::profile::ProfileId;

const ID: ProfileId = ProfileId([0x5a; 16]);

/// A fresh folder `target/rerun-launch-tests/<name>-<pid>-<nanos>`, removed on drop.
struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        let exe = std::env::current_exe().unwrap();
        let target = exe
            .ancestors()
            .find(|p| p.join("CACHEDIR.TAG").is_file())
            .expect("the test binary lies below target/")
            .to_path_buf();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = target
            .join("rerun-launch-tests")
            .join(format!("{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn base(&self) -> Vec<u16> {
        self.0.as_os_str().encode_wide().collect()
    }

    fn launch(&self) -> PathBuf {
        self.0.join("Rerun").join("launch")
    }

    fn result(&self) -> PathBuf {
        self.launch().join(format!("{ID}.result"))
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        // `remove_dir_all` removes a junction itself, never its target.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn junction(link: &Path, target: &Path) {
    let out = Command::new(
        Path::new(&std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe"),
    )
    .arg("/c")
    .arg("mklink")
    .arg("/J")
    .arg(link)
    .arg(target)
    // No console window from a test (`CREATE_NO_WINDOW`).
    .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
    .output()
    .unwrap();
    assert!(out.status.success(), "mklink /J: {out:?}");
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn creates_launch_writes_and_replaces() {
    let root = Root::new("replace");
    std::fs::create_dir(root.0.join("Rerun")).unwrap();
    write(&root.base(), &ID, b"one\n").unwrap();
    assert_eq!(std::fs::read(root.result()).unwrap(), b"one\n");
    // A reader holding the old file open shared for delete (std's default share mode) does not
    // block the replace (POSIX semantics). `rerun status` shares for read only: see the docs.
    let reader = std::fs::File::open(root.result()).unwrap();
    write(&root.base(), &ID, b"two\n").unwrap();
    drop(reader);
    assert_eq!(std::fs::read(root.result()).unwrap(), b"two\n");
    // Nothing else is left: no temp file.
    assert_eq!(names(&root.launch()), [format!("{ID}.result")]);
}

#[test]
fn without_a_rerun_folder_nothing_is_created() {
    let root = Root::new("no-rerun");
    let e = write(&root.base(), &ID, b"x\n").unwrap_err();
    assert!(matches!(e, OsError::Win32(2 | 3)), "{e:?}");
    assert!(names(&root.0).is_empty());
}

#[test]
fn a_junction_at_rerun_or_launch_is_refused() {
    let root = Root::new("junction");
    let elsewhere = root.0.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();

    // `Rerun` itself a junction.
    junction(&root.0.join("Rerun"), &elsewhere);
    assert_eq!(
        write(&root.base(), &ID, b"x\n").unwrap_err(),
        OsError::ReparsePoint
    );
    assert!(names(&elsewhere).is_empty());
    std::fs::remove_dir(root.0.join("Rerun")).unwrap();

    // `launch` a junction.
    std::fs::create_dir(root.0.join("Rerun")).unwrap();
    junction(&root.launch(), &elsewhere);
    assert_eq!(
        write(&root.base(), &ID, b"x\n").unwrap_err(),
        OsError::ReparsePoint
    );
    assert!(names(&elsewhere).is_empty());
}

#[test]
fn a_result_that_is_a_link_or_a_folder_is_refused_and_no_temp_stays() {
    let root = Root::new("target");
    let elsewhere = root.0.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::create_dir_all(root.launch()).unwrap();

    junction(&root.result(), &elsewhere);
    assert_eq!(
        write(&root.base(), &ID, b"x\n").unwrap_err(),
        OsError::ReparsePoint
    );
    assert_eq!(names(&root.launch()), [format!("{ID}.result")]);
    assert!(names(&elsewhere).is_empty());
    std::fs::remove_dir(root.result()).unwrap();

    std::fs::create_dir(root.result()).unwrap();
    assert_eq!(
        write(&root.base(), &ID, b"x\n").unwrap_err(),
        OsError::NotAFile
    );
    assert_eq!(names(&root.launch()), [format!("{ID}.result")]);
}

#[test]
fn a_file_at_launch_is_refused_and_oversize_is_never_written() {
    let root = Root::new("file");
    std::fs::create_dir(root.0.join("Rerun")).unwrap();
    std::fs::write(root.launch(), b"not a folder").unwrap();
    assert_eq!(
        write(&root.base(), &ID, b"x\n").unwrap_err(),
        OsError::NotAFile
    );
    let big = vec![b'x'; rerun_proto::launch::MAX_RESULT_BYTES + 1];
    assert_eq!(write(&root.base(), &ID, &big).unwrap_err(), OsError::Encode);
}

/// The assumption of step 2: while the `launch` handle is held (no `FILE_SHARE_DELETE`),
/// neither `launch` nor the folders above it can be renamed, so a path below them resolves
/// to the folders checked.
#[test]
fn held_folders_cannot_be_renamed() {
    let root = Root::new("pinned");
    std::fs::create_dir_all(root.launch()).unwrap();
    let launch: Vec<u16> = root.launch().as_os_str().encode_wide().collect();
    let held = super::open_dir(&launch).unwrap();
    assert!(std::fs::rename(root.launch(), root.0.join("Rerun").join("moved")).is_err());
    assert!(std::fs::rename(root.0.join("Rerun"), root.0.join("moved")).is_err());
    drop(held);
    std::fs::rename(root.0.join("Rerun"), root.0.join("moved")).unwrap();
}

/// The layout `rename` writes by offset: `Flags` (the union) first, a pointer-sized
/// `RootDirectory`, then the length and the name.
#[test]
fn rename_info_layout() {
    use std::mem::offset_of;
    use windows_sys::Win32::Storage::FileSystem::FILE_RENAME_INFO;
    assert_eq!(offset_of!(FILE_RENAME_INFO, Anonymous), 0);
    assert_eq!(
        offset_of!(FILE_RENAME_INFO, RootDirectory),
        size_of::<usize>()
    );
    assert_eq!(
        offset_of!(FILE_RENAME_INFO, FileNameLength),
        2 * size_of::<usize>()
    );
    assert_eq!(
        offset_of!(FILE_RENAME_INFO, FileName),
        2 * size_of::<usize>() + 4
    );
}

/// Makes the existing, empty folder `dir` a mount point to `target` (`FSCTL_SET_REPARSE_POINT`
/// with `IO_REPARSE_TAG_MOUNT_POINT`), through a handle of its own: what any process of the
/// user can do while the writer holds `dir` (security review S1).
fn make_mount_point(dir: &[u16], target: &Path) {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;

    let h = super::create(
        dir,
        FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .unwrap();
    let mut sub: Vec<u16> = r"\??\".encode_utf16().collect();
    sub.extend(target.as_os_str().encode_wide());
    let print: Vec<u16> = target.as_os_str().encode_wide().collect();
    let sub_len = u16::try_from(sub.len() * 2).unwrap();
    let print_len = u16::try_from(print.len() * 2).unwrap();
    let mut path = Vec::new();
    for u in sub
        .iter()
        .chain([0u16].iter())
        .chain(print.iter())
        .chain([0u16].iter())
    {
        path.extend_from_slice(&u.to_le_bytes());
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(&0xA000_0003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
    buf.extend_from_slice(&u16::try_from(8 + path.len()).unwrap().to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
    buf.extend_from_slice(&sub_len.to_le_bytes());
    buf.extend_from_slice(&(sub_len + 2).to_le_bytes()); // PrintNameOffset
    buf.extend_from_slice(&print_len.to_le_bytes());
    buf.extend_from_slice(&path);
    let mut returned = 0u32;
    // SAFETY: `h` is a live directory handle with FILE_WRITE_ATTRIBUTES; `buf` is a readable
    // REPARSE_DATA_BUFFER of `buf.len()` bytes alive for the call; no output buffer; `returned`
    // is valid for a write; synchronous (no OVERLAPPED).
    let ok = unsafe {
        DeviceIoControl(
            h.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            buf.as_ptr().cast(),
            u32::try_from(buf.len()).unwrap(),
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(ok, 0, "FSCTL_SET_REPARSE_POINT: {}", super::last_error());
}

/// Security review S1: the held handles keep `launch` from being renamed, not from becoming a
/// mount point while it is empty. The final-path check after the create catches it before the
/// first byte; the temp file is deleted wherever it landed.
#[test]
fn an_empty_launch_made_a_mount_point_while_held_is_escaped() {
    let root = Root::new("mount");
    let elsewhere = root.0.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::create_dir(root.0.join("Rerun")).unwrap();
    let mut done = false;
    let e = super::write_with(&root.base(), &ID, b"x\n", &mut |launch| {
        make_mount_point(launch, &elsewhere);
        done = true;
    })
    .unwrap_err();
    assert!(done);
    assert_eq!(e, OsError::Escaped);
    assert!(names(&elsewhere).is_empty(), "{:?}", names(&elsewhere));
}

/// A reader that shares for read only (as `rerun status` opens files through core's
/// `sys::win`) makes the replace fail with a sharing violation; the old result stays and no
/// temp file is left. Harmless: the start is recorded as `Written::Failed`.
#[test]
fn a_reader_without_share_delete_blocks_the_replace_harmlessly() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = Root::new("share");
    std::fs::create_dir(root.0.join("Rerun")).unwrap();
    write(&root.base(), &ID, b"one\n").unwrap();
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .open(root.result())
        .unwrap();
    let e = write(&root.base(), &ID, b"two\n").unwrap_err();
    drop(reader);
    assert!(matches!(e, OsError::Win32(32 | 5)), "{e:?}");
    assert_eq!(std::fs::read(root.result()).unwrap(), b"one\n");
    assert_eq!(names(&root.launch()), [format!("{ID}.result")]);
}
