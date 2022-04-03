use std::{
    borrow::{Borrow, Cow},
    collections::HashSet,
    fs::File,
    io::Stdout,
    io::Write,
};

use ahash::AHashMap;
use symbolic::{
    common::Name,
    demangle::{Demangle, DemangleOptions},
};

use crate::elf::ElfObject;

pub struct ParsedModule {
    start_addr: u64,
    end_addr: u64,
    file_offset: u64,
    // dev major, minor
    //inode: u64,
    name: String,
}

impl ParsedModule {
    // from str
    fn parse(line: &str) -> Option<Self> {
        let mut components = line.split_whitespace();
        let (start_addr, end_addr) = components.next().and_then(|c| c.split_once('-'))?;
        let (start_addr, end_addr) = (
            u64::from_str_radix(start_addr, 16).ok()?,
            u64::from_str_radix(end_addr, 16).ok()?,
        );

        if !components.next().map(|c| c.contains('x')).unwrap_or(false) {
            // not an executable page ignore it
            return None;
        }

        let file_offset = components
            .next()
            .and_then(|c| u64::from_str_radix(c, 16).ok())?;
        // Skip dev version
        components.next()?;
        // Skip inode
        components.next()?;
        let name = components.next()?.to_string();

        if !is_mapping_file_backed(&name) {
            return None;
        }

        println!("Parsed: {name}");
        // TODO: memfd

        Some(ParsedModule {
            start_addr,
            end_addr,
            file_offset,
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


#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: Option<String>,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug)]
pub enum ModuleType<'data> {
    Unknown,
    Exec {
        elf: ElfObject<'data>,
    },
    So {
        elf: ElfObject<'data>,
        elf_so_offset: u64,
        elf_so_addr: u64,
    },
    PerfMap,
    Vdso,
    Debug,
}

#[derive(Debug)]
pub struct Range {
    start: u64,
    end: u64,
    offset: u64,
}

pub struct Module<'data> {
    pub name: String,
    pub path: String,
    pub ranges: Vec<Range>,
    pub loaded: bool,
    pub module_type: ModuleType<'data>,
    pub sym_names: HashSet<String>,
    pub syms: Vec<Symbol>,
}

impl<'data> Module<'data> {
    fn new(path: String, data: &'data [u8]) -> Self {
        tracing::info!("Loading module: {path}");

        let elf = ElfObject::parse(data).ok();

        let module_type = elf.map(|elf| elf.kind()).unwrap_or_else(|| {
            if path.contains("[vdso]") {
                ModuleType::Vdso
            } else {
                ModuleType::Unknown
            }
        });

        Self {
            name: path.clone(),
            path,
            ranges: Default::default(),
            loaded: false,
            module_type,
            sym_names: Default::default(),
            syms: Default::default(),
        }
    }

    pub fn load_sym_table(&mut self) {
        if self.loaded {
            return;
        }

        match &self.module_type {
            ModuleType::Unknown => {
                tracing::error!("Unknown module {}", self.name);
            }
            ModuleType::Exec { elf } => {
                for_each_sym_core(&mut self.sym_names, &mut self.syms, elf, false);
                self.syms.sort_unstable_by(|a, b| a.address.cmp(&b.address));
            }
            ModuleType::So { elf, .. } => {
                for_each_sym_core(&mut self.sym_names, &mut self.syms, elf, false);
                self.syms.sort_unstable_by(|a, b| a.address.cmp(&b.address));
            }
            ModuleType::Vdso => tracing::warn!("VDSO symbols not yet supported"),
            _ => panic!("Unhandled ModuleType"),
        }
        self.loaded = true;
    }

    pub fn contains(&self, addr: u64) -> Option<u64> {
        for range in self.ranges.iter() {
            if addr >= range.start && addr < range.end {
                let offset = addr - range.start + range.offset;
                match self.module_type {
                    ModuleType::So {
                        elf_so_offset,
                        elf_so_addr,
                        ..
                    } => return Some(offset + (elf_so_addr - elf_so_offset)),
                    ModuleType::Vdso => {
                        tracing::warn!("VDSO not supported");
                        return None;
                        //return Some(offset);
                    }
                    _ => return Some(addr),
                }
            }
        }
        None
    }
}

// move into module itself
fn for_each_sym_core<'data>(
    symnames: &mut HashSet<String>,
    syms: &mut Vec<Symbol>,
    elf: &ElfObject<'data>,
    is_debug_file: bool,
) {
    // bcc_for_each_module ish,

    if !is_debug_file {
        if let Some(debug_file) = find_debug_file(elf) {
            use std::io::Read;
            let mut buf = Vec::new();
            File::options()
                .read(true)
                .open(debug_file)
                .unwrap()
                .read_to_end(&mut buf)
                .unwrap();
            if let Ok(debug_elf) = ElfObject::parse(&buf) {
                for_each_sym_core(symnames, syms, &debug_elf, true);
            } else {
                tracing::error!("Debug file not parseable!");
            }
        }
        tracing::warn!("No debug file found TODO");
    }
    syms.extend(elf.symbols());
}


fn find_debug_file(elf: &ElfObject) -> Option<String> {
    if let Some(debug_file) = find_debug_file_via_symfs(elf) {
        return Some(debug_file);
    }
    if let Some(debug_file) = find_debug_file_via_buildid(elf) {
        return Some(debug_file);
    }
    // TODO via debug link as well
    None
}

fn find_debug_file_via_symfs(_elf: &ElfObject) -> Option<String> {
    // TODO
    //let build_id = elf.find_build_id();
    //path.strip_prefix("/proc/").unwrap();
    //let post_pid = path.find('/').unwrap();
    //let ns_prefix_lengfpath[post_pid..].strip_prefix("/root/").unwrap();
    // This seems releated to when you have separate folder for symbols which
    // might be useful later on
    None
}

fn find_debug_file_via_buildid(elf: &ElfObject) -> Option<String> {
    let build_id = elf.find_build_id()?;
    let tmp = build_id[1..]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    tracing::info!("Build id {}", tmp);
    let debug_file_path = format!("/usr/lib/debug/.build-id/{:x}/{}.debug", build_id[0], &tmp);
    if std::fs::read(&debug_file_path).is_ok() {
        tracing::info!("Debug file_path: {debug_file_path}");
        Some(debug_file_path)
    } else {
        None
    }
}

pub struct SymLoader {
    pub pid: i32,
    pub modules: Vec<(ParsedModule, Vec<u8>)>,
}

impl SymLoader {
    pub fn new(pid: i32) -> Self {
        use std::io::Read;
        let mut buf = String::new();
        // bcc_for_each_module ish,
        File::options()
            .read(true)
            .open(format!("/proc/{pid}/maps"))
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();

        let mut modules = Vec::new();
        // _procfs_maps_each_module
        for parsed_module in buf.lines().filter_map(ParsedModule::parse) {
            let mut buf = Vec::new();
            // check enter_ns which depends if module is perfmap which we ignore for now
            let modpath = &parsed_module.name;
            let _ = File::options()
                .read(true)
                .open(modpath)
                .and_then(|mut file| file.read_to_end(&mut buf));

            modules.push((parsed_module, buf));
        }
        Self { pid, modules }
    }

    pub fn load_modules(&mut self) -> Symbols<'_> {
        let mut modules = Vec::new();
        for (parsed_module, buf) in self.modules.iter() {
            Self::add_module(&mut modules, parsed_module, buf);
        }
        Symbols { modules }
    }

    pub fn add_module<'a>(
        modules: &mut Vec<Module<'a>>,
        parsed_module: &ParsedModule,
        data: &'a [u8],
    ) {
        tracing::info!("Adding: {}", parsed_module.name);

        if let Some(module) = modules
            .iter_mut()
            .find(|module| module.name == parsed_module.name)
        {
            module.ranges.push(Range {
                start: parsed_module.start_addr,
                end: parsed_module.end_addr,
                offset: parsed_module.file_offset,
            });
        } else {
            let range = Range {
                start: parsed_module.start_addr,
                end: parsed_module.end_addr,
                offset: parsed_module.file_offset,
            };
            let mut module = Module::new(parsed_module.name.clone(), data);
            module.ranges.push(range);

            modules.push(module);
        }
    }
}

pub struct Symbols<'data> {
    modules: Vec<Module<'data>>,
}

fn print_name<'a, N: Borrow<Name<'a>>>(name: Option<&'a N>, demangle: bool) -> Cow<'a, str> {
    match name.map(Borrow::borrow) {
        None => Cow::Owned(String::from("??")),
        Some(name) if name.as_str().is_empty() => Cow::Owned(String::from("??")),
        Some(name) if demangle => name.try_demangle(DemangleOptions::name_only()),
        Some(name) => Cow::Borrowed(name.as_str()),
    }
}

impl<'data> Symbols<'data> {
    fn find_module_offset(&mut self, addr: u64) -> Option<(u64, &mut Module<'data>)> {
        for module in self.modules.iter_mut() {
            if let Some(offset) = module.contains(addr) {
                return Some((offset, module));
            }
        }
        None
    }

    pub fn addr_to_line(
        &mut self,
        addrs: &[u64],
        cache: &mut AHashMap<u64, String>,
        stdout: &Stdout,
    ) {
        let mut stdout = stdout.lock();
        'addr: for addr in addrs.iter() {
            let addr = *addr;
            if addr == 0x0 {
                continue;
            }
            if let Some(cached) = cache.get(&addr) {
                writeln!(stdout, "Cached: {cached}").unwrap();
                continue;
            }
            // Find memory region and convert virtual to address within binary
            if let Some((module_offset, module)) = self.find_module_offset(addr) {
                module.load_sym_table();
                match module
                    .syms
                    .binary_search_by(|a| a.address.cmp(&module_offset))
                {
                    // TODO?
                    Ok(index) => {
                        let symbol = module.syms.get(index).unwrap();
                        let symbol = symbol.name.as_ref().unwrap().clone();
                        let name = Name::new(
                            symbol,
                            symbolic::common::NameMangling::Unknown,
                            symbolic::common::Language::Unknown,
                        );
                        writeln!(stdout, "Found {module_offset:x}").unwrap();
                        let name = print_name(Some(&name), true);
                        writeln!(stdout, "{name}").unwrap();
                        continue 'addr;
                    }
                    Err(index) => {
                        let mut i = index - 1;
                        let limit = module.syms.get(i).map(|s| s.address).unwrap_or(u64::MAX);
                        while let Some(sym) = module.syms.get(i) {
                            // keep going as long as we are larger than the sym addr
                            if module_offset < sym.address {
                                break;
                            }
                            // if the offset_addr is GREATER than addr but less than addr + size
                            // it's a match
                            if module_offset < sym.address + sym.size {
                                // resolve here if done lazily
                                let symbol = sym.name.as_ref().unwrap().clone();
                                let name = Name::new(
                                    symbol,
                                    symbolic::common::NameMangling::Unknown,
                                    symbolic::common::Language::Unknown,
                                );
                                //        writeln!(stdout, "Found {offset_addr:x}").unwrap();
                                let name = print_name(Some(&name), true);
                                writeln!(stdout, "{name}").unwrap();
                                continue 'addr;
                            }
                            if limit > sym.address + sym.size {
                                break;
                            }
                            i -= 1;
                        }
                        writeln!(
                            stdout,
                            "FAILED TO FIND {module_offset:x}\n at unknown in {}",
                            module.name
                        )
                        .unwrap();
                    }
                }
            } else {
                writeln!(stdout, "Failed to find module for {addr:x}").unwrap();
                writeln!(stdout, "??:0").unwrap();
                continue;
            }
        }
    }
}
