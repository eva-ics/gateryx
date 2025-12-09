use std::collections::BTreeSet;
use std::sync::LazyLock;
use std::time::Duration;

use parking_lot::Mutex;

static CHILD_PIDS: LazyLock<Mutex<BTreeSet<libc::pid_t>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));

pub fn term_childs() {
    signal_childs(libc::SIGTERM);
}

fn signal_childs(signal: libc::c_int) {
    for &pid in CHILD_PIDS.lock().iter() {
        unsafe {
            libc::kill(pid, signal);
        }
    }
}

fn panic_handler(info: &std::panic::PanicHookInfo) {
    eprintln!("Panic occurred: {}", info);
    signal_childs(libc::SIGTERM);
    std::thread::sleep(Duration::from_secs(2));
    signal_childs(libc::SIGKILL);
    std::process::exit(5);
}

pub fn set() {
    std::panic::set_hook(Box::new(panic_handler));
}

pub fn register_pid(pid: libc::pid_t) {
    let mut pids = CHILD_PIDS.lock();
    pids.insert(pid);
}
