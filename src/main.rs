use ahash::AHashMap;
use clap::ArgEnum;
use clap::Parser;
use futures::stream::StreamExt;
use owo_colors::OwoColorize;
use std::env;
use std::process;
use std::ptr;
use tokio::signal;
use tokio::sync::mpsc::Receiver;
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

struct AllocationStat {
    alloc_count: u64,
    total_size: u64,
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

async fn event_proccessor(
    mut event_rc: Receiver<BpfEvent>,
) -> (
    AHashMap<i64, Box<BpfStackFrames>>,
    AHashMap<i64, AllocationStat>,
) {
    let mut allocations = AHashMap::new();
    let mut stack_traces = AHashMap::new();
    let mut allocation_stats: AHashMap<i64, AllocationStat> = AHashMap::new();

    struct Allocation {
        size: u64,
        stack_id: i64,
    }

    while let Some(event) = event_rc.recv().await {
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
                            alloc_count: 1,
                            total_size: size,
                        },
                    );
                }
            }
            BpfEvent::Free { ptr } => {
                if let Some(Allocation { size, stack_id }) = allocations.remove(&ptr) {
                    let should_remove = if let Some(stats) = allocation_stats.get_mut(&stack_id) {
                        stats.alloc_count -= 1;
                        stats.total_size -= size;
                        stats.total_size == 0
                    } else {
                        false
                    };
                    if should_remove {
                        allocation_stats.remove(&stack_id);
                    }
                }
            }
        }
    }

    (stack_traces, allocation_stats)
}

/// Monitor heap usage using bpf probes
#[derive(Debug, Parser)]
#[clap(author, version, about)]
struct Args {
    /// Pid of process to monitor
    #[clap(short, long)]
    pid: i32,
    /// Sets the amount of stack traces to print out
    #[clap(short, long, default_value_t = 10)]
    traces: u32,
    /// Verbose tracing logs
    #[clap(short, long)]
    verbose: bool,
    /// Language expected when demangling
    #[clap(short, long, default_value = "unknown")]
    lang: symbolic::common::Language,
    /// Determines if colors should be used in the output
    #[clap(long, arg_enum, default_value = "auto")]
    color: Color,
}

#[derive(ArgEnum, Clone, Copy, Debug)]
enum Color {
    Always,
    Auto,
    Never,
}

impl Color {
    fn init(self) {
        match self {
            Color::Always => owo_colors::set_override(true),
            Color::Auto => {}
            Color::Never => owo_colors::set_override(false),
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    args.color.init();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(if args.verbose {
            Level::TRACE
        } else {
            Level::WARN
        })
        .finish();

    tracing::subscriber::set_global_default(subscriber).unwrap();

    if unsafe { libc::geteuid() } != 0 {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let pid = args.pid;

    let (event_sender, event_rc) = tokio::sync::mpsc::channel(512);

    let event_handler_task = tokio::spawn(async move {
        let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");

        for prb in loaded.uprobes_mut() {
            prb.attach_uprobe(Some(&prb.name()), 0, "libc", Some(pid))
                .unwrap_or_else(|_| panic!("error attaching uprobe program {}", prb.name()));
        }

        eprintln!(
            "{}",
            format!("Monitoring heap in PID {}, Hit Ctrl-C to quit!", args.pid)
                .if_supports_color(owo_colors::Stream::Stderr, |text| text.green())
        );
        tokio::select! {
            _ = signal::ctrl_c() => {},
            _ = event_handler(loaded, event_sender) => {}
        }
    });

    let event_proccesing_task = tokio::spawn(async move {
        let (stack_traces, allocation_stats) = event_proccessor(event_rc).await;

        let mut symloader = SymLoader::new(pid);
        let mut modules = symloader.load_modules();

        let mut cache = AHashMap::new();
        let stdout = std::io::stdout();

        eprintln!(
            "{}",
            "Processing...".if_supports_color(owo_colors::Stream::Stderr, |text| text.yellow())
        );
        let start = std::time::Instant::now();

        let mut largest_outstanding: Vec<(i64, AllocationStat)> =
            allocation_stats.into_iter().collect();
        largest_outstanding.sort_unstable_by(|(_, a), (_, b)| b.total_size.cmp(&a.total_size));

        for (stack_id, alloc_stat) in largest_outstanding.iter().take(args.traces as usize) {
            if let Some(frames) = stack_traces.get(stack_id) {
                println!(
                    "{}",
                    format!(
                        "Allocated a total of {} bytes from {} separate allocations",
                        alloc_stat.total_size, alloc_stat.alloc_count
                    )
                    .if_supports_color(owo_colors::Stream::Stdout, |text| text.bright_blue())
                );
                modules
                    .addr_to_line(&frames.ip, &mut cache, &stdout, args.lang)
                    .expect("Failed resolve stack frame");
            } else {
                tracing::error!("No stack trace found for {stack_id}");
            }
        }
        let duration = start.elapsed().as_millis();
        println!();
        eprintln!(
            "{}",
            format!("Time taken {duration}ms")
                .if_supports_color(owo_colors::Stream::Stderr, |text| text.yellow())
        );
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
