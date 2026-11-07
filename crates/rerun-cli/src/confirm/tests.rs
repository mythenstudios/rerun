//! The answer line of the confirmation.

use super::{Answer, is_yes, read_answer};

#[test]
fn only_y_and_yes_are_yes() {
    for yes in [&b"y\n"[..], b"Y\r\n", b" yes \n", b"YES", b"\ty\t\n"] {
        assert!(is_yes(yes), "{yes:?}");
    }
    for no in [
        &b"n\n"[..],
        b"\n",
        b"",
        b"yess\n",
        b"y y\n",
        b"ja\n",
        "\u{ff59}\n".as_bytes(),
    ] {
        assert!(!is_yes(no), "{no:?}");
    }
}

#[test]
fn an_answer_is_one_bounded_line() {
    assert_eq!(read_answer(&b"y\nmore"[..]), Answer::Yes);
    assert_eq!(read_answer(&b""[..]), Answer::No);
    assert_eq!(read_answer(&b"no\n"[..]), Answer::No);
    let mut long = vec![b' '; 300];
    long.extend_from_slice(b"y\n");
    assert_eq!(read_answer(&long[..]), Answer::No, "longer than 256 bytes");
    let mut edge = vec![b' '; 254];
    edge.extend_from_slice(b"y\n");
    assert_eq!(read_answer(&edge[..]), Answer::Yes, "exactly 256 bytes");
}
