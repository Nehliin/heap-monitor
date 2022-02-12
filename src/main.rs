use anyhow::*;
use clap::Parser;
use futures::stream::StreamExt;
use std::borrow::Borrow;
use std::borrow::Cow;
use std::boxed::Box;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::Cursor;
use std::io::Stdout;
use std::io::Write;
use std::path::Path;
use std::process;
use std::process::Command;
use std::ptr;
use std::sync::{Arc, Mutex};
use symbolic::debuginfo::dwarf::Dwarf;
use symbolic::symcache::SymCache;
use symbolic::symcache::SymCacheWriter;
use tokio::runtime;
use tokio::signal;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::{Loaded, Loader};
use redbpf::{BpfStackFrames, StackTrace};

use symbolic::common::{ByteView, Language, Name, NameMangling};
use symbolic::debuginfo::{Function, Object};
use symbolic::demangle::{Demangle, DemangleOptions};

mod syms;

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

        let mut cache = HashMap::new();
        let stdout = std::io::stdout();

        for alloc_size in acc.values() {
            println!(
                "{} bytes allocated, malloc called {} times at:",
                alloc_size.size, alloc_size.count
            );
            binary
                .addr_to_line(&alloc_size.frames.ip, &mut cache, &stdout)
                .unwrap();
        }
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
        Some(name) => name.clone().into_cow(),
    }
}

fn print_range(start: u64, len: Option<u64>, _ranges: bool) -> String {
    //if ranges {
    match len {
        Some(len) => format!("({:#x} - {:#x})", start, start + len),
        None => format!("({start:#x} - ??)"),
    }
    //}
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
            result.push_str(&print_range(function.address, Some(function.size), true));
            result.push_str("\n  at ");
        }
        // basenames?
        let file = if false {
            line.file.name_str()
        } else {
            line.file.path_str().into()
        };
        result.push_str(&format!("{}:{}", file, line.line));
        result.push_str(&print_range(line.address, line.size, true));
        result.push('\n');

        return Ok(Some(result));
    }

    Ok(None)
}

fn proc_memory_maps(pid: i32) -> Result<BTreeMap<u64, String>> {
    let pmap = Command::new("pmap").arg(format!("{pid}")).output()?;

    if !pmap.status.success() {
        bail!("pmap failed with status code: {}", pmap.status)
    } else {
        let stdout = String::from_utf8_lossy(&pmap.stdout);
        let mut proc_memory_maps = BTreeMap::new();
        for line in stdout.lines().skip(1) {
            let mut split_line = line.split(' ');
            let start: u64 = match u64::from_str_radix(split_line.next().unwrap(), 16) {
                std::result::Result::Ok(start) => start,
                Err(_) => continue,
            };
            let name = split_line.last().unwrap();

            if name != "]" {
                proc_memory_maps.insert(start, name.to_string());
            }
        }
        Ok(proc_memory_maps)
    }
}

struct ParsedModule {
    start_addr: u64,
    end_addr: u64,
    file_offset: u64,
    // dev major, minor
    inode: u64,
    name: String,
}

impl ParsedModule {
    // from str
    fn parse(line: &str) -> Option<Self> {
        let mut components = line.split_whitespace();
        let (start_addr, end_addr) = components.next().and_then(|c| c.split_once("-"))?;
        let (start_addr, end_addr) = dbg!((
            u64::from_str_radix(start_addr, 16).ok()?,
            u64::from_str_radix(end_addr, 16).ok()?,
        ));

        if !components.next().map(|c| c.contains('x')).unwrap_or(false) {
            // not an executable page ignore it
            return None;
        }

        let file_offset = dbg!(components
            .next()
            .and_then(|c| u64::from_str_radix(c, 16).ok())?);
        // Skip dev version
        dbg!(components.next()?);
        let inode = dbg!(components.next().and_then(|c| c.parse().ok())?);
        let name = dbg!(components.next()?.to_string());

        if !is_mapping_file_backed(&name) {
            return None;
        }

        println!("Parsed: {name}");
        // TODO: memfd

        Some(ParsedModule {
            start_addr,
            end_addr,
            file_offset,
            inode,
            name,
        })
    }
}

fn is_mapping_file_backed(name: &str) -> bool {
    !(name.starts_with("//anon")
        && name.starts_with("/dev/zero")
        && name.starts_with("/anon_hugepage")
        && name.starts_with("[stack")
        && name.starts_with("/SYSV")
        && name.starts_with("[heap]")
        && name.starts_with("[vsyscall]"))
}

enum SymName {
    NameIdx {
        section_idx: usize,
        str_table_idx: usize,
        str_len: usize,
        debug_file: bool,
    },
    Name(String),
}

struct Symbol {
    is_name_resolved: bool,
    start: u64,
    size: u64,
    data: SymName,
}

enum ModuleType {
    Unknown,
    Exec,
    So {
        elf_so_offset: u64,
        elf_so_addr: u64,
    },
    // PERF_MAP,
    Vdso,
}

#[derive(Debug)]
struct Range {
    start: u64,
    end: u64,
    offset: u64,
}

struct Module {
    name: String,
    path: String,
    ranges: Vec<Range>,
    loaded: bool,
    module_type: ModuleType,
    sym_names: HashSet<String>,
    syms: Vec<Symbol>,
}

impl Module {
    fn new(name: String, path: String) -> Self {
        let module_type = get_module_type(&path);
        Self {
            name,
            path,
            ranges: Default::default(),
            loaded: false,
            module_type,
            sym_names: Default::default(),
            syms: Default::default(),
        }
    }

    fn contains(&self, addr: u64) -> Option<u64> {
        //       dbg!(addr);
        for range in self.ranges.iter() {
            //            dbg!(range);
            if addr >= range.start && addr < range.end {
                let offset = range.start + range.offset;
                match self.module_type {
                    ModuleType::So {
                        elf_so_offset,
                        elf_so_addr,
                    } => return Some(offset + (elf_so_addr - elf_so_offset)),
                    ModuleType::Vdso => return Some(offset),
                    _ => return Some(addr),
                }
            }
        }
        None
    }
}

struct ProcSyms {
    pid: i32,
    modules: Vec<Module>,
}

impl ProcSyms {
    fn new(pid: i32) -> Self {
        Self {
            pid,
            modules: Vec::new(),
        }
    }

    fn load_modules(&mut self) {
        use std::io::Read;
        let mut buf = String::new();
        let pid = self.pid;
        // bcc_for_each_module ish,
        File::options()
            .read(true)
            .open(format!("/proc/{pid}/maps"))
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();

        // _procfs_maps_each_module
        for parsed_module in buf.lines().filter_map(ParsedModule::parse) {
            self.add_module(parsed_module);
        }
    }

    fn add_module(&mut self, parse_module: ParsedModule) {
        // check enter_ns which depends if module is perfmap which we ignore for now
        //let modpath = format!("/proc/{}/root{}", self.pid, parse_module.name);
        let modpath = parse_module.name.to_string();
        println!("Adding: {modpath}");

        if let Some(module) = self
            .modules
            .iter_mut()
            .find(|module| module.name == parse_module.name)
        {
            module.ranges.push(Range {
                start: parse_module.start_addr,
                end: parse_module.end_addr,
                offset: parse_module.file_offset,
            });
        } else {
            let range = Range {
                start: parse_module.start_addr,
                end: parse_module.end_addr,
                offset: parse_module.file_offset,
            };
            let mut module = Module::new(parse_module.name, modpath);
            module.ranges.push(range);

            self.modules.push(module);
            // construct new module etc
            // TRY to use the proc maps offset and read using symbolic first
        }
    }
}

fn get_module_type(modpath: &str) -> ModuleType {
    println!("Loading {modpath}");
    if let std::result::Result::Ok(buffer) = std::fs::read(Path::new(modpath)) {
        if let std::result::Result::Ok(Object::Elf(elf)) = Object::parse(&buffer) {
            // Kind is doing stuff I might not want to do
            return match dbg!(elf.kind()) {
                symbolic::debuginfo::ObjectKind::Executable => ModuleType::Exec,
                symbolic::debuginfo::ObjectKind::Library => {
                    if let Some(text_section) = elf.section("text") {
                        ModuleType::So {
                            elf_so_offset: text_section.offset,
                            elf_so_addr: text_section.address,
                        }
                    } else {
                        panic!("Failed to find  text section");
                    }
                }
                _ => ModuleType::Unknown,
            };
        }
        ModuleType::Unknown
    } else if modpath.contains("[vdso]") {
        ModuleType::Vdso
    } else {
        ModuleType::Unknown
    }
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

      /*  println!("Loading symbols...");
        let debug_session = object
            .debug_session()
            .context("Failed to process executable file")?;*/

        //let symbol_map = object.symbol_map();
        println!("Fetching proc memory map");
        //let proc_memory_maps = proc_memory_maps(pid)?;
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
        cache: &mut HashMap<u64, String>,
        stdout: &Stdout,
    ) -> Result<()> {
        let functions = true;
        let mut stdout = stdout.lock();
        'addrs: for  addr in addrs.iter() {
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
                /*writeln!(
                    stdout,
                    "Found {module_offset:x} for {addr:x} resulting in {:x} in module {}",
                    offset_addr, module.name
                )
                .unwrap();*/
                /*for function in self.debug_session.functions() {
                    let function = function.context("Failed to read function")?;
                    if let Some(resolved) = resolve(&function, offset_addr, functions)? {
                        writeln!(stdout, "{resolved}").unwrap();
                        cache.insert(addr, resolved);
                        continue 'addrs;
                    }
                }*/

                if functions {
                    if let std::result::Result::Ok(mut res) = self.symcache.lookup(offset_addr) {
                        while let Some(std::result::Result::Ok(symbol)) = res.next() {
                            let symbol_name = symbol.function_name();
                            //if let Some(symbol_name) = &symbol.function_name() {
                            /* let symbol_name = Name::new(
                                symbol_name.as_ref(),
                                NameMangling::Mangled,
                                Language::Unknown,
                            );*/
                            let resolved_name = print_name(Some(&symbol_name), false);
                            cache.insert(addr, resolved_name.to_string());
                            //let range = print_range(symbol.function_address(), Some(symbol_name.), true);
                            //writeln!(stdout, "{resolved_name}\n at {range} in {}", module.name)
                            writeln!(stdout, "{resolved_name}\n at unknown in {}", module.name)
                                .unwrap();
                            //}
                        }
                    } else {
                        writeln!(
                            stdout,
                            "Failed to find symbol: {addr:x}, offset: {offset_addr:x}"
                        )
                        .unwrap();
                        println!("??:0");
                    }
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
