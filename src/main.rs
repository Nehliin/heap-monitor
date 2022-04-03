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

enum BpfEvent {
    Allocation {
        ptr: u64,
        stack_id: i64,
        size: u64,
        frames: Box<BpfStackFrames>,
    },
    Free {
        ptr: u64,
    },
}

async fn event_handler(mut loaded: Loaded, sender: Sender<BpfEvent>) {
    while let Some((name, events)) = loaded.events.next().await {
        match name.as_str() {
            "malloc_event" => {
                for event in events {
                    let m_event = unsafe { ptr::read(event.as_ptr() as *const MallocEvent) };
                    let mut stack_trace = StackTrace::new(loaded.map("stack_trace").unwrap());
                    if let Some(frames) = stack_trace.get(m_event.stackid) {
                        sender
                            .send(BpfEvent::Allocation {
                                ptr: m_event.ptr,
                                stack_id: m_event.stackid,
                                size: m_event.size,
                                frames: Box::new(frames),
                            })
                            .await
                            .map_err(|_err| "Failed to send allocation event")
                            .unwrap();
                    } else {
                        tracing::warn!("Stack trace not found for allocation: {}", m_event.stackid);
                    }
                }
            }
            "free_event" => {
                for event in events {
                    let f_event = unsafe { ptr::read(event.as_ptr() as *const MallocEvent) };
                    sender
                        .send(BpfEvent::Free { ptr: f_event.ptr })
                        .await
                        .map_err(|_err| "Failed to send deallocation event")
                        .unwrap();
                }
            }
            _ => {}
        }
    }
}

/// Monitor heap usage live usign bpf probes
#[derive(Debug, Parser)]
#[clap(author, version, about)]
struct Args {
    /// Pid of process to monitor
    #[clap(short, long)]
    pid: i32,
    // demange: bool,
    // raw addrs:bool
    // language
    // verbose
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

    let event_handler_task = tokio::spawn(async move {
        let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");

        for prb in loaded.uprobes_mut() {
            prb.attach_uprobe(Some(&prb.name()), 0, "libc", Some(pid))
                .unwrap_or_else(|_| panic!("error attaching uprobe program {}", prb.name()));
        }

        println!("Monitoring heap in PID {}, Hit Ctrl-C to quit!", args.pid);
        tokio::select! {
            _ = signal::ctrl_c() => {},
            _ = event_handler(loaded, tx) => {}
        }
    });

    let event_proccesing_task = tokio::spawn(async move {
        let mut allocations = AHashMap::new();
        let mut stack_traces = AHashMap::new();
        let mut allocation_stats: AHashMap<i64, AllocationStat> = AHashMap::new();

        struct AllocationStat {
            alloc_count: u64,
            total_size: u64,
        }

        struct Allocation {
            size: u64,
            stack_id: i64,
        }

        while let Some(event) = rc.recv().await {
            match event {
                BpfEvent::Allocation {
                    ptr,
                    stack_id,
                    size,
                    frames,
                } => {
                    stack_traces.insert(stack_id, frames);
                    allocations.insert(ptr, Allocation { size, stack_id });
                    if let Some(stats) = allocation_stats.get_mut(&stack_id) {
                        stats.alloc_count += 1;
                        stats.total_size += size;
                    } else {
                        allocation_stats.insert(
                            stack_id,
                            AllocationStat {
                                alloc_count: 0,
                                total_size: size,
                            },
                        );
                    }
                }
                BpfEvent::Free { ptr } => {
                    if let Some(Allocation { size, stack_id }) = allocations.remove(&ptr) {
                        if let Some(stats) = allocation_stats.get_mut(&stack_id) {
                            stats.alloc_count -= 1;
                            stats.total_size += size;
                        }
                    }
                }
            }
        }

        let mut symloader = SymLoader::new(pid);
        let mut modules = symloader.load_modules();

        let mut cache = AHashMap::new();
        let stdout = std::io::stdout();

        println!("Proccessing..");
        let start = std::time::Instant::now();

        let mut largest_outstanding: Vec<(i64, AllocationStat)> =
            allocation_stats.into_iter().collect();
        largest_outstanding.sort_unstable_by(|(_, a), (_, b)| a.total_size.cmp(&b.total_size));

        for (stack_id, alloc_stat) in largest_outstanding.iter().take(10) {
            if let Some(frames) = stack_traces.get(stack_id) {
                println!(
                    "Allocated a total of {} bytes from {} separate allocation",
                    alloc_stat.total_size, alloc_stat.alloc_count
                );
                modules.addr_to_line(&frames.ip, &mut cache, &stdout);
            } else {
                tracing::error!("No stack trace found for {stack_id}");
            }
        }
        let duration = start.elapsed().as_millis();
        println!("Time taken {duration}");
    });

    let _ = event_handler_task.await.unwrap();
    let _ = event_proccesing_task.await.unwrap();
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/malloc/malloc.elf"
    ))
}
