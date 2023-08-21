// use anyhow::Ok;
use anyhow::{anyhow, bail, Context, Result};
use core::time::Duration;
use libbpf_rs::PerfBufferBuilder;
use object::Object;
use object::ObjectSymbol;
use plain::Plain;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use structopt::StructOpt;

#[path = "bpf/.output/umleak.skel.rs"]
mod umleak;
// use libc::rlimit;
use umleak::*;


fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn get_symbol_address(so_path: &str, fn_name: &str) -> Result<usize> {
    let path = Path::new(so_path);
    let buffer =
        fs::read(path).with_context(|| format!("could not read file `{}`", path.display()))?;
    let file = object::File::parse(buffer.as_slice())?;
    let mut symbols = file.dynamic_symbols();
    let symbol = symbols.find(|symbol| {
        if let Ok(name) = symbol.name() {
            return name == fn_name;
        }
        false
    }) .ok_or(anyhow!("symbol not found"))?;

    Ok(symbol.address() as usize)
}


fn main() -> Result<()> {

    bump_memlock_rlimit()?;

    let skel_builder = UmleakSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;
    open_skel.rodata().target_pid = 123;
    let mut skel = open_skel.load()?;

    let address = get_symbol_address("/lib/x86_64-linux-gnu/libc.so.6", "malloc")?;

    skel.progs_mut()
        .malloc_enter()
        .attach_uprobe(false, 123, "/lib/x86_64-linux-gnu/libc.so.6", address)?;

    skel.progs_mut()
        .malloc_exit()
        .attach_uprobe(true, 123, "/lib/x86_64-linux-gnu/libc.so.6", address)?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        
    }


    Ok(())
}
