//! File system contract, writing race (`docs/09-testing.md`): while an attacker thread swaps,
//! moves and plants entries by path, `replace`, `delete`, `create_new` and `lock` run through
//! a write handle. Core rule 2: nothing outside our own names is ever overwritten, deleted or
//! renamed, and every outcome is a row of the phase tables (ADR 0017, A3) with `Before` or
//! `After`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::{
    ContractResult, FsContractResult, FsFixture, Skipped, ensure, names, ok, open_write, rel,
};
use crate::sys::fs::{Attrs, DirWrite, Fs, NewFile, TmpName};
use crate::sys::{SysError, SysErrorKind, SysResult};

const CANARY: &[u8] = b"CANARY";
const VICTIM: &[u8] = b"VICTIM";
const INTRUDER: &[u8] = b"INTRUDER";
/// Instance tag of the temp names of this contract.
const TAG: u64 = 0x0bad_c0de;
/// How long the attacker retries a rename refused because of our handles (`AccessDenied`
/// for a folder with a handle below it, A5; `Busy` for a sharing conflict), and how long the
/// main thread waits for the attacker to finish a cycle.
const PATIENCE: Duration = Duration::from_secs(10);
/// Iterations at least: every attacker move meets every operation (3 × 4).
const MIN_ROUNDS: u64 = 12;

/// An operation of the writing race contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOp {
    /// Guard and `replace` of `t.bin`.
    Replace,
    /// Guard and `delete` of `t.bin`.
    Delete,
    /// `create_new` of `n.bin`.
    CreateNew,
    /// `lock` of `l.lock`.
    Lock,
}

impl WriteOp {
    /// Every operation, in the order the contract cycles through them.
    pub const ALL: [Self; 4] = [Self::Replace, Self::Delete, Self::CreateNew, Self::Lock];
}

/// A small xorshift generator for the delays of one run: seeded per run, so attempts against a
/// naive control never replay the same schedule (found in review: deterministic delays made
/// every attempt hit the same timing). The seed is in every failure message.
struct Rng(u64);

impl Rng {
    /// A seed from the clock and a process-wide counter (never 0).
    fn seeded() -> Self {
        static RUNS: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |t| t.subsec_nanos());
        let run = RUNS.fetch_add(1, Ordering::Relaxed);
        Self((u64::from(nanos) ^ run.wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A delay of 0 to `max_us` microseconds.
    fn micros(&mut self, max_us: u64) -> Duration {
        Duration::from_micros(self.next() % (max_us + 1))
    }
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The paths of the race.
struct Tree {
    /// `root`: holds `d` and the junction `d.link`.
    root: PathBuf,
    /// `root\d`: the folder of the write handle.
    d: PathBuf,
    /// `root\d.real`: where the real `d` is while the junction stands at `d`.
    d_real: PathBuf,
    /// `root\d.link`: a junction to `outside`.
    d_link: PathBuf,
    /// `outside`: holds only `canary.txt`; nothing may ever appear or change there.
    outside: PathBuf,
}

impl Tree {
    fn in_d(&self, name: &str) -> PathBuf {
        self.d.join(name)
    }
}

/// An attacker move of one cycle.
#[derive(Debug, Clone, Copy)]
enum Move {
    /// `d` is swapped for the junction to `outside` and back.
    Flip,
    /// The target `t.bin` is moved aside and `victim.bin` put in its place, then back.
    Swap,
    /// `intruder.bin` is planted at `n.bin` (the name `create_new` writes), then taken back.
    Plant,
}

/// The attacker's moves are by path through the fixture. A rename refused because of our
/// handles is retried; a rename that finds the tree not as the attacker left it means the
/// implementation touched a name that is not ours: a violation (`RACE_LEAK`). Anything else is
/// a harness problem ("write race flip:").
struct Attacker<'a> {
    fx: &'a dyn FsFixture,
    tree: &'a Tree,
}

/// The result of one attacker rename.
type Moved = Result<(), SysError>;

impl Attacker<'_> {
    fn mv(&self, from: &Path, to: &Path) -> Moved {
        let since = Instant::now();
        loop {
            match self.fx.rename(from, to) {
                Err(e)
                    if matches!(e.kind, SysErrorKind::AccessDenied | SysErrorKind::Busy)
                        && since.elapsed() < PATIENCE =>
                {
                    thread::yield_now();
                }
                r => return r,
            }
        }
    }

    fn harness(what: &str, e: &SysError) -> String {
        format!("write race flip: {what}: {e}")
    }

    fn cycle(&self, m: Move, hold: Duration) -> ContractResult {
        let t = self.tree;
        match m {
            Move::Flip => {
                self.mv(&t.d, &t.d_real)
                    .map_err(|e| Self::harness("move d aside", &e))?;
                if let Err(e) = self.mv(&t.d_link, &t.d) {
                    let _ = self.mv(&t.d_real, &t.d);
                    return Err(Self::harness("put the junction at d", &e));
                }
                thread::sleep(hold);
                self.mv(&t.d, &t.d_link)
                    .map_err(|e| Self::harness("take the junction away", &e))?;
                self.mv(&t.d_real, &t.d)
                    .map_err(|e| Self::harness("put d back", &e))
            }
            Move::Swap => {
                let (target, aside, victim) =
                    (t.in_d("t.bin"), t.in_d("t.aside"), t.in_d("victim.bin"));
                match self.mv(&target, &aside) {
                    Ok(()) => {}
                    // No target right now (deleted by the operation): nothing to swap.
                    Err(e) if e.kind == SysErrorKind::NotFound => return Ok(()),
                    Err(e) => return Err(Self::harness("move t.bin aside", &e)),
                }
                if let Err(e) = self.mv(&victim, &target) {
                    let _ = self.mv(&aside, &target);
                    return Err(match e.kind {
                        SysErrorKind::AlreadyExists => {
                            "contract violated: write race leak: t.bin was created while the target \
                             was moved aside"
                                .to_owned()
                        }
                        SysErrorKind::NotFound => {
                            "contract violated: write race leak: victim.bin is gone".to_owned()
                        }
                        _ => Self::harness("put victim.bin at t.bin", &e),
                    });
                }
                thread::sleep(hold);
                if let Err(e) = self.mv(&target, &victim) {
                    let _ = self.mv(&aside, &target);
                    return Err(match e.kind {
                        SysErrorKind::NotFound => "contract violated: write race leak: the victim \
                                                   standing at t.bin was deleted or moved"
                            .to_owned(),
                        SysErrorKind::AlreadyExists => {
                            "contract violated: write race leak: victim.bin was recreated"
                                .to_owned()
                        }
                        _ => Self::harness("take victim.bin back", &e),
                    });
                }
                self.mv(&aside, &target).map_err(|e| match e.kind {
                    SysErrorKind::AlreadyExists => "contract violated: write race leak: t.bin was \
                                                    created while the target was moved aside"
                        .to_owned(),
                    _ => Self::harness("put t.bin back", &e),
                })
            }
            Move::Plant => {
                let (name, intruder) = (t.in_d("n.bin"), t.in_d("intruder.bin"));
                match self.mv(&intruder, &name) {
                    Ok(()) => {}
                    // Our n.bin stands there: nothing to plant.
                    Err(e) if e.kind == SysErrorKind::AlreadyExists => return Ok(()),
                    Err(e) if e.kind == SysErrorKind::NotFound => {
                        return Err(
                            "contract violated: write race leak: intruder.bin is gone".into()
                        );
                    }
                    Err(e) => return Err(Self::harness("plant intruder.bin", &e)),
                }
                thread::sleep(hold);
                self.mv(&name, &intruder).map_err(|e| match e.kind {
                    SysErrorKind::NotFound => "contract violated: write race leak: the intruder \
                                               planted at n.bin was deleted or moved"
                        .to_owned(),
                    SysErrorKind::AlreadyExists => {
                        "contract violated: write race leak: intruder.bin was recreated".to_owned()
                    }
                    _ => Self::harness("take the intruder back", &e),
                })
            }
        }
    }
}

/// What the main thread expects on disk once the attacker has finished its cycle.
struct Model {
    /// Content of `t.bin` (`None`: deleted).
    t: Option<Vec<u8>>,
    /// `n.bin` written by the last `create_new`.
    n: Option<Vec<u8>>,
    /// `l.lock` was created once.
    locked: bool,
}

/// The error kinds an operation may meet in the race (a gap between two renames, the victim
/// at the target, a planted name, a sharing conflict, the junction).
fn allowed(e: &SysError) -> bool {
    matches!(
        e.kind,
        SysErrorKind::NotFound
            | SysErrorKind::Mismatch
            | SysErrorKind::Busy
            | SysErrorKind::AlreadyExists
            | SysErrorKind::ReparsePoint
    )
}

fn new_file(n: u64, data: &[u8]) -> NewFile {
    NewFile {
        tmp: TmpName::new(TAG, n),
        attrs: Attrs::default(),
        sha256: sha(data),
        max_len: u64::try_from(data.len()).unwrap_or(u64::MAX),
    }
}

/// `Some` for success, `None` for an allowed error; any other error fails the contract.
fn outcome<T>(r: SysResult<T>, what: &str) -> Result<Option<T>, String> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if allowed(&e) => Ok(None),
        Err(e) => Err(format!(
            "contract violated: write race: {what}: unexpected error {e}"
        )),
    }
}

/// Runs `op` (round `i`) through `d` and updates the model by its result (A3: success is
/// `After`, an error `Before`).
fn operate(d: &dyn DirWrite, op: WriteOp, i: u64, m: &mut Model) -> ContractResult {
    let t = rel("t.bin")?;
    match op {
        WriteOp::Replace => {
            let cur =
                m.t.clone()
                    .ok_or("write race model: t.bin missing before a replace")?;
            let next = format!("t-{i}").into_bytes();
            let r = d
                .guard(&t)
                .and_then(|g| g.replace(&sha(&cur), &mut &next[..], &new_file(2 * i, &next)));
            if let Some(rep) = outcome(r, "replace")? {
                ensure(
                    rep.old_left.is_none(),
                    "write race leak: replace left the old file pending (nothing maps it)",
                )?;
                m.t = Some(next);
            }
        }
        WriteOp::Delete => {
            let cur =
                m.t.clone()
                    .ok_or("write race model: t.bin missing before a delete")?;
            let r = d.guard(&t).and_then(|g| g.delete(&sha(&cur)));
            if outcome(r, "delete")?.is_some() {
                m.t = None;
            }
        }
        WriteOp::CreateNew => {
            let data = format!("n-{i}").into_bytes();
            let r = d.create_new(&rel("n.bin")?, &mut &data[..], &new_file(2 * i, &data));
            if outcome(r, "create_new")?.is_some() {
                m.n = Some(data);
            }
        }
        WriteOp::Lock => {
            if outcome(d.lock(&rel("l.lock")?), "lock")?.is_some() {
                m.locked = true;
            }
        }
    }
    Ok(())
}

/// `f` retried while it is `Busy` (another program, a scanner, holds the fresh file for a
/// moment), at most [`PATIENCE`]: only for the reset between rounds, never for an operation
/// under test.
fn settled<T>(mut f: impl FnMut() -> SysResult<T>) -> SysResult<T> {
    let since = Instant::now();
    loop {
        match f() {
            Err(e) if e.kind == SysErrorKind::Busy && since.elapsed() < PATIENCE => {
                thread::sleep(Duration::from_millis(5));
            }
            r => return r,
        }
    }
}

/// With the attacker idle: the tree is exactly what the model says, nothing outside our names
/// changed; then our own leftovers of this round (`n.bin`, a deleted `t.bin`) are reset through
/// `d` for the next round.
fn check_and_reset(
    fs: &dyn Fs,
    d: &dyn DirWrite,
    tree: &Tree,
    i: u64,
    m: &mut Model,
) -> ContractResult {
    let out = ok(fs.open_dir(&tree.outside), "write race: open outside")?;
    ensure(
        names(&*out, None, "write race: outside")? == ["canary.txt"],
        "write race leak: nothing appears in the junction's target",
    )?;
    ensure(
        ok(out.read(&rel("canary.txt")?), "write race: canary")? == CANARY,
        "write race leak: the canary behind the junction is unchanged",
    )?;
    let root = ok(fs.open_dir(&tree.root), "write race: open root")?;
    ensure(
        names(&*root, None, "write race: root")? == ["d", "d.link"],
        "write race leak: d and the junction are back in place",
    )?;
    let chk = ok(fs.open_dir(&tree.d), "write race: open d")?;
    let mut want = vec!["intruder.bin".to_owned(), "victim.bin".to_owned()];
    want.extend(m.t.as_ref().map(|_| "t.bin".to_owned()));
    want.extend(m.n.as_ref().map(|_| "n.bin".to_owned()));
    if m.locked {
        want.push("l.lock".to_owned());
    }
    want.sort();
    let have = names(&*chk, None, "write race: d")?;
    ensure(
        have == want,
        &format!(
            "write race leak: d holds exactly our names and the attacker's (round {i}: {have:?}, \
             expected {want:?}; no temp file, no .old)"
        ),
    )?;
    let content = |name: &str| ok(chk.read(&rel(name)?), &format!("write race: read {name}"));
    ensure(
        content("victim.bin")? == VICTIM,
        "write race leak: victim.bin (swapped in at the target) is unchanged",
    )?;
    ensure(
        content("intruder.bin")? == INTRUDER,
        "write race leak: intruder.bin (planted at a created name) is unchanged",
    )?;
    if let Some(t) = &m.t {
        ensure(
            &content("t.bin")? == t,
            &format!("write race leak: t.bin holds what the last result says (round {i})"),
        )?;
    }
    if let Some(n) = m.n.take() {
        ensure(
            content("n.bin")? == n,
            &format!("write race leak: n.bin holds what create_new wrote (round {i})"),
        )?;
        let name = rel("n.bin")?;
        ok(
            settled(|| d.guard(&name).and_then(|g| g.delete(&sha(&n)))),
            "write race: reset n.bin",
        )?;
    }
    if m.t.is_none() {
        let data = format!("t-reset-{i}").into_bytes();
        let name = rel("t.bin")?;
        ok(
            settled(|| d.create_new(&name, &mut &data[..], &new_file(2 * i + 1, &data))),
            "write race: reset t.bin",
        )?;
        m.t = Some(data);
    }
    Ok(())
}

/// File system contract, writing race. An attacker thread runs one cycle per round (a junction
/// flip of the handle's folder, a swap of the target for a victim, a plant at the name
/// `create_new` writes), started together with one operation through the write handle
/// (`replace`, `delete`, `create_new`, `lock`), both after a random delay (0 to 2 ms for the
/// attacker, 0 to 1.5 ms for the operation; the swapped state holds 0 to 1.5 ms), seeded per
/// run. Once the attacker
/// is idle, the tree must be exactly what the results say: success is `After`, an error
/// `Before` (ADR 0017, A3), no temp file or `.old` is left, the victim, the intruder and the
/// junction's target are unchanged, and nothing appeared outside. Allowed errors: `NotFound`,
/// `Mismatch`, `Busy`, `AlreadyExists`, `ReparsePoint`; any other fails the contract.
///
/// `ops` are the operations it cycles through ([`WriteOp::ALL`] for the contract; the runner's
/// control check also asks for each one alone, so each operation is shown to be caught by at
/// least one assertion). Runs for at least `budget` and [`MIN_ROUNDS`] rounds. `work` must be an existing, empty
/// directory. Against `sys::win` the runner also runs a naive path-based implementation,
/// which this harness must catch, so a passing run means something.
pub fn fs_write_race_contract(
    fs: &dyn Fs,
    fx: &dyn FsFixture,
    work: &Path,
    budget: Duration,
    ops: &[WriteOp],
) -> FsContractResult {
    if ops.is_empty() {
        return Err("write race model: no operation".to_owned());
    }
    let tree = Tree {
        root: work.join("root"),
        d: work.join(r"root\d"),
        d_real: work.join(r"root\d.real"),
        d_link: work.join(r"root\d.link"),
        outside: work.join("outside"),
    };
    ok(
        fx.file(&tree.outside.join("canary.txt"), CANARY),
        "fixture canary",
    )?;
    ok(fx.junction(&tree.d_link, &tree.outside), "fixture junction")?;
    ok(fx.file(&tree.in_d("victim.bin"), VICTIM), "fixture victim")?;
    ok(
        fx.file(&tree.in_d("intruder.bin"), INTRUDER),
        "fixture intruder",
    )?;
    let first = b"t-initial".to_vec();
    ok(fx.file(&tree.in_d("t.bin"), &first), "fixture target")?;
    let d = open_write(fs, &tree.d, "write race: open d")?;
    let mut model = Model {
        t: Some(first),
        n: None,
        locked: false,
    };

    let mut rng = Rng::seeded();
    let seed = rng.0;
    // The attacker's delays of the requested round, set before the request.
    let attacker_delay_us = AtomicU64::new(0);
    let hold_us = AtomicU64::new(0);
    let requested = AtomicU64::new(0);
    let finished = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    let failure: Mutex<Option<String>> = Mutex::new(None);
    let attacker = Attacker { fx, tree: &tree };
    let result: ContractResult = thread::scope(|scope| {
        scope.spawn(|| {
            while !stop.load(Ordering::Acquire) {
                let n = requested.load(Ordering::Acquire);
                if n == finished.load(Ordering::Acquire) {
                    thread::yield_now();
                    continue;
                }
                thread::sleep(Duration::from_micros(
                    attacker_delay_us.load(Ordering::Acquire),
                ));
                let m = match n % 3 {
                    0 => Move::Flip,
                    1 => Move::Swap,
                    _ => Move::Plant,
                };
                let hold = Duration::from_micros(hold_us.load(Ordering::Acquire));
                if let Err(e) = attacker.cycle(m, hold) {
                    *failure
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(format!("{e} ({m:?}, round {n})"));
                }
                finished.store(n, Ordering::Release);
            }
        });
        let mut run = || -> ContractResult {
            let started = Instant::now();
            let mut i = 0u64;
            while i < MIN_ROUNDS || started.elapsed() < budget {
                i += 1;
                let pick = |r: &mut Rng, max| u64::try_from(r.micros(max).as_micros()).unwrap_or(0);
                attacker_delay_us.store(pick(&mut rng, 2000), Ordering::Release);
                hold_us.store(pick(&mut rng, 1500), Ordering::Release);
                let own_delay = rng.micros(1500);
                requested.store(i, Ordering::Release);
                thread::sleep(own_delay);
                let op = ops
                    .get(usize::try_from(i).unwrap_or(0) % ops.len())
                    .copied()
                    .unwrap_or(WriteOp::Replace);
                let op = operate(&*d, op, i, &mut model);
                let since = Instant::now();
                while finished.load(Ordering::Acquire) != i {
                    if since.elapsed() > PATIENCE * 4 {
                        return Err(format!("write race flip: the attacker hangs in round {i}"));
                    }
                    thread::yield_now();
                }
                if let Some(e) = failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    return Err(e);
                }
                op?;
                check_and_reset(fs, &*d, &tree, i, &mut model)?;
            }
            Ok(())
        };
        let r = run();
        stop.store(true, Ordering::Release);
        r
    });
    result.map_err(|e| format!("{e} [seed {seed:#x}]"))?;
    Ok(Skipped::new())
}
