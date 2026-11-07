//! P2-15: the `.old` files a step of Rerun leaves while a process maps them as an image, by
//! sequence index in the journal (`RevertDone.old_left`), and what `status` names.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::tests::{Env, NEW, base, finish};
use super::{Outcome, txn_status};
use crate::prim::tests::{GAME, app, entry, spec};
use crate::sys::Fs;
use crate::sys::fake::{FakeFs, FakeHold, Prim};

/// Maps every `.tmp.old` that appears in a folder as an image of process 4242 while a step of
/// Rerun runs (the hook looks before every rename, so the `.old` of step 6 is mapped before
/// step 8 tries to delete it), until [`Self::release`].
pub(crate) struct Mapper {
    held: Arc<Mutex<Vec<(String, FakeHold)>>>,
}

impl Mapper {
    /// From now on, in the folder `abs` of `env`.
    pub(crate) fn arm(env: &Env, abs: &str) -> Self {
        let held: Arc<Mutex<Vec<(String, FakeHold)>>> = Arc::new(Mutex::new(Vec::new()));
        let slot = Arc::clone(&held);
        let dir = PathBuf::from(abs);
        env.sys.fake_fs().on_step(move |f, ev| {
            if ev.call == Some(Prim::Rename) {
                map_olds(f, &dir, &slot);
            }
        });
        Self { held }
    }

    /// The game folder of the fixtures.
    pub(crate) fn game(env: &Env) -> Self {
        Self::arm(env, GAME)
    }

    /// No more new mappings (the ones made stay).
    pub(crate) fn stop(env: &Env) {
        env.sys.fake_fs().clear_on_step();
    }

    /// The names mapped so far.
    pub(crate) fn names(&self) -> Vec<String> {
        self.held
            .lock()
            .unwrap()
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// Every mapping goes (the game was closed).
    pub(crate) fn release(&self) {
        self.held.lock().unwrap().clear();
    }
}

fn map_olds(f: &FakeFs, dir: &Path, slot: &Mutex<Vec<(String, FakeHold)>>) {
    #[expect(clippy::disallowed_methods, reason = "test: list the fixture folder")]
    let Ok(d) = f.open_dir(dir) else {
        return;
    };
    let Ok(entries) = d.read_dir(None) else {
        return;
    };
    let mut held = slot.lock().unwrap();
    for e in entries.iter().filter(|e| e.name.ends_with(".tmp.old")) {
        if held.iter().any(|(n, _)| *n == e.name) {
            continue;
        }
        if let Ok(h) = f.map_image_as(4242, &dir.join(&e.name)) {
            held.push((e.name.clone(), h));
        }
    }
}

/// The plan that replaces `d3d9.dll`.
pub(crate) fn replace_env() -> (Env, crate::plan::PlanHash) {
    let env = Env::new(finish(base()));
    let h = env.plan(&spec(vec![entry("d3d9.dll", "d3d9.dll", NEW)]));
    (env, h)
}

/// The `.old` names `status` shows for op 0 of `t`.
pub(crate) fn status_names(env: &Env, t: &crate::journal::TxnId) -> Vec<String> {
    let a = app(&env.sys);
    let st = txn_status(&a, t).unwrap();
    st.ops
        .iter()
        .find(|o| o.op == 0)
        .map(|o| o.cleanup.iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

/// CL-T9 (P2-15, the display bug of `status`): `status` names exactly the `.old` files the
/// journal says are left. `Done.old_left` whose `X.old` the revert deleted: nothing; an `X.old`
/// still mapped after the restore: `X.old`, not the restore's `Y.old`.
#[test]
fn cl_t9_status_names_exactly_what_the_journal_says_is_left() {
    // The apply leaves `X.old` (mapped), the game is closed, the revert deletes it.
    let (env, h) = replace_env();
    let m = Mapper::game(&env);
    let t = match env.apply(&h) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    Mapper::stop(&env);
    let x_old = m.names();
    assert_eq!(x_old.len(), 1, "X.old mapped: {x_old:?}");
    assert_eq!(status_names(&env, &t), x_old, "Done.old_left");
    m.release();
    let r = env.revert(&t).unwrap();
    assert!(r.ops[0].left.is_empty(), "{r:?}");
    assert!(
        status_names(&env, &t).is_empty(),
        "X.old was deleted: {:?}",
        status_names(&env, &t)
    );

    // `X.old` stays mapped through the revert: the restore's `Y.old` goes, `X.old` is named.
    let (env, h) = replace_env();
    let m = Mapper::game(&env);
    let t = match env.apply(&h) {
        Ok(Outcome::Applied(t)) => t,
        other => panic!("{other:?}"),
    };
    Mapper::stop(&env);
    let x_old = m.names();
    let r = env.revert(&t).unwrap();
    assert_eq!(r.ops[0].observed, crate::journal::Observed::After, "{r:?}");
    let a = app(&env.sys);
    let j = crate::journal::Journal::new(&a, crate::journal::InstanceTag::fixed(3));
    let v = j.load(&t, crate::journal::VerifyBackups::Length).unwrap();
    let rd = v.ops[&0].reverted.clone().unwrap();
    assert_eq!(rd.old_left, vec![0], "only X.old (sequence 0)");
    assert_eq!(status_names(&env, &t), x_old, "X.old, not Y.old");
    m.release();
}
