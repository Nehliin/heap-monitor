use clap::Parser;
use futures::stream::StreamExt;
use std::boxed::Box;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::process;
use std::process::Command;
use std::ptr;
use std::sync::{Arc, Mutex};
use tokio::runtime;
use tokio::signal;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::{Loaded, Loader};
use redbpf::{BpfStackFrames, StackTrace};

use probes::malloc::MallocEvent;

struct AllocSize {
    size: u64,
    count: u64,
    frames: BpfStackFrames,
}

type Acc = Arc<Mutex<HashMap<i64, AllocSize>>>;

fn handle_malloc_event(acc: Acc, loaded: &Loaded, event: Box<[u8]>) {
    let mut acc = acc.lock().unwrap();
    let mev = unsafe { ptr::read(event.as_ptr() as *const MallocEvent) };
    if let Some(alloc_size) = acc.get_mut(&mev.stackid) {
        (*alloc_size).size += mev.size;
        (*alloc_size).count += 1;
    } else {
        let mut stack_trace = StackTrace::new(loaded.map("stack_trace").unwrap());
        if let Some(frames) = stack_trace.get(mev.stackid) {
            acc.insert(
                mev.stackid,
                AllocSize {
                    size: mev.size,
                    count: 1,
                    frames,
                },
            );
        }
    }
}

fn start_perf_event_handler(mut loaded: Loaded, acc: Acc) {
    tokio::spawn(async move {
        while let Some((name, events)) = loaded.events.next().await {
            match name.as_str() {
                "malloc_event" => {
                    for event in events {
                        handle_malloc_event(acc.clone(), &loaded, event);
                    }
                }
                _ => {}
            }
        }
    });
}

/// Monitor heap usage live usign bpf probes
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Pid of process to monitor
    #[clap(short, long)]
    pid: i32,
    // Name of process to monitor
    //#[clap(short, long)]
    // name: String,
}

fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::geteuid() } != 0 {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let args = Args::parse();
    let pid = args.pid;

    let acc: Acc = Arc::new(Mutex::new(HashMap::new()));
    let rt = runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _ = rt.block_on(async {
        let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");

        for prb in loaded.uprobes_mut() {
            prb.attach_uprobe(Some(&prb.name()), 0, "libc", Some(args.pid))
                .unwrap_or_else(|_| panic!("error attaching uprobe program {}", prb.name()));
        }
        start_perf_event_handler(loaded, acc.clone());

        println!(
            "Attaching to malloc in PID {}, Hit Ctrl-C to quit",
            args.pid
        );
        signal::ctrl_c().await
    });
    println!();

    let mut hashset = HashSet::new();
    let mut gdb = Command::new("gdb");
    //gdb.arg("--directory=/home/oskar/Desktop/ark/target/debug");
   // gdb.arg("--se=/home/oskar/Desktop/ark/target/debug/ark-client.d");
    gdb.arg(&format!("--pid={pid}"));
    gdb.arg("-batch");
    let acc = acc.lock().unwrap();
    for alloc_size in acc.values() {
        for src_addr in alloc_size.frames.ip.iter() {
            let src_addr = *src_addr;
            if src_addr == 0x0 || hashset.contains(&src_addr) {
                continue;
            }
            gdb.arg("-ex");
            gdb.arg(&format!("info line *{src_addr:#x}"));
            hashset.insert(src_addr);
        }
        println!(
            "{} bytes allocated, malloc called {} times at:",
            alloc_size.size, alloc_size.count
        );
        /*for ip in alloc_size.frames.ip.iter() {
            if *ip == 0x0 {
                break;
            }
            println!("{:#x}", ip);
        }*/
    }
    println!("{gdb:?}");
    let output = gdb.output().expect("Failed to start gdb");
    println!("Output: {}", String::from_utf8_lossy(&output.stdout));
    println!("Output stderr: {}", String::from_utf8_lossy(&output.stderr));
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/malloc/malloc.elf"
    ))
}
