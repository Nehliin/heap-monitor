use ahash::AHashMap;
use clap::Parser;
use futures::stream::StreamExt;
use std::env;
use std::process;
use std::ptr;
use tokio::signal;
use tokio::sync::mpsc::Sender;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::{Loaded, Loader};
use redbpf::{BpfStackFrames, StackTrace};

mod elf;
mod syms;

use probes::malloc::MallocEvent;

use crate::syms::SymLoader;

struct Allocation {
    stack_id: i64,
    size: u64,
    frames: BpfStackFrames,
}


fn start_perf_event_handler(mut loaded: Loaded, sender: Sender<Allocation>) {
    tokio::spawn(async move {
        while let Some((name, events)) = loaded.events.next().await {
            if name.as_str() == "malloc_event" {
                for event in events {
                    let m_event = unsafe { ptr::read(event.as_ptr() as *const MallocEvent) };
                    let mut stack_trace = StackTrace::new(loaded.map("stack_trace").unwrap());
                    if let Some(frames) = stack_trace.get(m_event.stackid) {
                        sender
                            .send(Allocation {
                                stack_id: m_event.stackid,
                                size: m_event.size,
                                frames,
                            })
                            .await
                            .map_err(|_err| "Failed to send allocation event")
                            .unwrap();
                    } else {
                        tracing::warn!("Stack trace not found for allocation: {}", m_event.stackid);
                    }
                }
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
    // demange: bool,
    // raw addrs:bool
}

#[tokio::main]
async fn main() {
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

    let (tx, mut rc) = tokio::sync::mpsc::channel(512);

    let event_handler = tokio::spawn(async move {
        let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");

        for prb in loaded.uprobes_mut() {
            prb.attach_uprobe(Some(&prb.name()), 0, "libc", Some(pid))
                .unwrap_or_else(|_| panic!("error attaching uprobe program {}", prb.name()));
        }
        start_perf_event_handler(loaded, tx);

        println!(
            "Attaching to malloc in PID {}, Hit Ctrl-C to quit!",
            args.pid
        );
        signal::ctrl_c().await
    });

    tokio::spawn(async move {
        let mut symloader = SymLoader::new(pid);
        let mut symbols = symloader.load_modules();

        let mut cache = AHashMap::new();
        let stdout = std::io::stdout();

        let start = std::time::Instant::now();
        
        while let Some(allocation) = rc.recv().await {
            symbols.addr_to_line(&allocation.frames.ip, &mut cache, &stdout);
        }
        
        let duration = start.elapsed().as_millis();
        println!("Time taken {duration}");
    });

    let _ = event_handler.await.unwrap();
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/malloc/malloc.elf"
    ))
}
