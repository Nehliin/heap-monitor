use ahash::AHashMap;
use anyhow::*;
use clap::Parser;
use futures::stream::StreamExt;
use std::borrow::Borrow;
use std::borrow::Cow;
use std::boxed::Box;
use std::env;
use std::io::Cursor;
use std::io::Stdout;
use std::io::Write;
use std::process;
use std::ptr;
use std::result::Result::Ok;
use std::sync::{Arc, Mutex};
use symbolic::symcache::SymCache;
use symbolic::symcache::SymCacheWriter;
use syms::Module;
use tokio::runtime;
use tokio::signal;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::{Loaded, Loader};
use redbpf::{BpfStackFrames, StackTrace};

use symbolic::common::{ByteView, Name};
use symbolic::debuginfo::{Function, Object};
use symbolic::demangle::{Demangle, DemangleOptions};

mod syms;

use probes::malloc::MallocEvent;

use crate::syms::ProcSyms;

struct AllocSize {
    size: u64,
    count: u64,
    frames: BpfStackFrames,
}

type Acc = Arc<Mutex<AHashMap<i64, AllocSize>>>;

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
    // demange: bool,
    // raw addrs:bool
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

    let acc: Acc = Arc::new(Mutex::new(AHashMap::new()));
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
            "Attaching to malloc in PID {}, Hit Ctrl-C to quit!",
            args.pid
        );
        signal::ctrl_c().await
    });
    println!();

    let acc = acc.lock().unwrap();

    let view = ByteView::open("/home/oskar/Desktop/helix/target/debug/hx").unwrap();
    let object = Object::parse(&view).unwrap();
    let test = Cursor::new(Vec::new());
    let writer = SymCacheWriter::write_object(&object, test).unwrap();
    let test = writer.into_inner();
    {
        let binary = BinaryObjectInfo::load(&object, pid, &test).unwrap();

        let mut cache = AHashMap::new();
        let stdout = std::io::stdout();

        let start = std::time::Instant::now();
        for alloc_size in acc.values() {
            println!(
                "{} bytes allocated, malloc called {} times at:",
                alloc_size.size, alloc_size.count
            );
            binary
                .addr_to_line(&alloc_size.frames.ip, &mut cache, &stdout)
                .unwrap();
        }
        let duration = start.elapsed().as_millis();
        println!("Time taken {duration}")
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/malloc/malloc.elf"
    ))
}

fn print_name<'a, N: Borrow<Name<'a>>>(name: Option<&'a N>, demangle: bool) -> Cow<'a, str> {
    match name.map(Borrow::borrow) {
        None => Cow::Owned(String::from("??")),
        Some(name) if name.as_str().is_empty() => Cow::Owned(String::from("??")),
        Some(name) if demangle => name.try_demangle(DemangleOptions::name_only()),
        Some(name) => Cow::Borrowed(name.as_str()),
    }
}


fn resolve<'a>(function: &'a Function<'_>, addr: u64, functions: bool) -> Result<Option<String>> {
    if function.address > addr || function.address + function.size <= addr {
        return Ok(None);
    }

    let mut result = String::default();

    if true {
        for il in &function.inlinees {
            if let Some(resolved) = resolve(il, addr, functions)? {
                result.push_str(&resolved);
            }
        }
    }

    for line in &function.lines {
        if line.address + line.size.unwrap_or(1) <= addr {
            continue;
        } else if line.address > addr {
            break;
        }

        if functions {
            result.push_str(&print_name(Some(&function.name), true));
            //result.push_str(&print_range(function.address, Some(function.size), true));
            result.push_str("\n  at ");
        }
        // basenames?
        let file = if false {
            line.file.name_str()
        } else {
            line.file.path_str().into()
        };
        result.push_str(&format!("{}:{}", file, line.line));
        //result.push_str(&print_range(line.address, line.size, true));
        result.push('\n');

        return Ok(Some(result));
    }

    Ok(None)
}

struct BinaryObjectInfo<'b> {
    proc_syms: ProcSyms,
    symcache: SymCache<'b>,
}

impl<'b> BinaryObjectInfo<'b> {
    fn load<'a: 'b>(object: &Object<'a>, pid: i32, test: &'b [u8]) -> Result<Self> {
        assert!(
            object.has_symbols(),
            "The given executable is missing symbols"
        );
        assert!(
            object.has_debug_info(),
            "The given executable is missing debug info"
        );

        println!("Fetching proc memory map");
        let mut proc_syms = ProcSyms::new(pid);
        proc_syms.load_modules();

        let symcache = SymCache::parse(test).unwrap();
        Ok(BinaryObjectInfo {
            proc_syms,
            //symbol_map,
            symcache,
            //symbuffer: &symbuffer,
        })
    }

    fn find_module_offset(&self, addr: u64) -> Option<(u64, &Module)> {
        for module in self.proc_syms.modules.iter() {
            if let Some(offset) = module.contains(addr) {
                return Some((offset, module));
            }
        }
        None
    }

    fn addr_to_line(
        &self,
        addrs: &[u64],
        cache: &mut AHashMap<u64, String>,
        stdout: &Stdout,
    ) -> Result<()> {
        let mut stdout = stdout.lock();
        for addr in addrs.iter() {
            let addr = *addr; //- 0x55c7d8e75040;
            if addr == 0x0 {
                continue;
            }
            if let Some(cached) = cache.get(&addr) {
                writeln!(stdout, "Cached: {cached}").unwrap();
                continue;
            }
            // Find memory region and convert virtual to address within binary
            if let Some((module_offset, module)) = self.find_module_offset(addr) {
                let offset_addr = addr - module_offset;
                // make it peekable
                if let Ok(mut lookup_result) = self.symcache.lookup(offset_addr) {
                    let mut found = false;
                    while let Some(Ok(symbol)) = lookup_result.next() {
                        let symbol_name = symbol.function_name();
                        let resolved_name = print_name(Some(&symbol_name), true);
                        writeln!(stdout, "{resolved_name}\n at unknown in {}", module.name)
                            .unwrap();
                        cache.insert(addr, resolved_name.into_owned());
                        found = true;
                        //let range = print_range(symbol.function_address(), Some(symbol_name.), true);
                        //writeln!(stdout, "{resolved_name}\n at {range} in {}", module.name)

                        //}
                    }
                    if !found {
                        writeln!(
                            stdout,
                            "FAILED TO FIND {offset_addr:x}\n at unknown in {}",
                            module.name
                        )
                        .unwrap();
                    }
                } else {
                    writeln!(
                        stdout,
                        "Failed to find symbol: {addr:x}, offset: {offset_addr:x}"
                    )
                    .unwrap();
                    println!("??:0");
                }
            } else {
                writeln!(stdout, "Failed to find module for {addr:x}").unwrap();
                writeln!(stdout, "??:0").unwrap();
                continue;
            }
        }
        Ok(())
    }
}
