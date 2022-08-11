use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::{TcHookBuilder, TC_EGRESS};

#[path = "bpf/.output/netoken.skel.rs"]
mod netoken;
use netoken::*;

#[derive(Debug, Parser)]
struct Command {
    /// interface to attach to
    #[clap(short = 'i', long = "interface", default_value_t = String::from("eth0"))]
    iface: String,

    /// destroy all hooks on clsact
    #[clap(short = 'd', long = "destroy")]
    destroy: bool,    

    /// attach a hook
    #[clap(short, long)]
    attach: bool,
}

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
fn main() -> Result<()> {
    let opts = Command::parse();

    bump_memlock_rlimit()?;

    let builder = netokenSkelBuilder::default();
    let open = builder.open()?;
    let skel = open.load()?;
    let fd = skel.progs().handle_tc().fd();
    let ifidx = nix::net::if_::if_nametoindex(opts.iface.as_str())? as i32;

    let mut tc_builder = TcHookBuilder::new();
    tc_builder
        .fd(fd)
        .ifindex(ifidx)
        .replace(true)
        .handle(1)
        .priority(1);

    let mut egress = tc_builder.hook(TC_EGRESS);

    if opts.attach {
        if let Err(e) = egress.attach() {
            bail!("failed to attach egress hook {}", e);
        }
    }

    if opts.destroy {
        if let Err(e) = egress.detach() {
            println!("failed to detach egress hook {}", e);
        }

        if let Err(e) = egress.destroy() {
            println!("failed to destroy {}", e);
        }

        // we can create a TcHook w/o the builder
        // let mut destroy_all = libbpf_rs::TcHook::new(fd);
        // destroy_all
        //     .ifindex(ifidx)
        //     .attach_point(TC_EGRESS);

        // if let Err(e) = destroy_all.destroy() {
        //     println!("failed to destroy all {}", e);
        // }         
    }

    match egress.query() {
        Err(e) => println!("failed to find egress hook: {}", e),
        Ok(prog_id) => println!("found egress hook prog_id: {}", prog_id),
    }

    Ok(())
}
