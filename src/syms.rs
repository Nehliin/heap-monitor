use std::{borrow::Cow, collections::HashSet, fs::File, path::Path};

use crate::elf::ElfObject;

pub struct ParsedModule {
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
        let inode = components.next().and_then(|c| c.parse().ok())?;
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

pub enum SymName {
    NameIdx {
        section_idx: usize,
        str_table_idx: usize,
        str_len: usize,
        debug_file: bool,
    },
    Name(String),
}

pub struct Symbol {
    is_name_resolved: bool,
    start: u64,
    size: u64,
    data: SymName,
}

#[derive(Debug, Clone)]
pub struct TestSymbol {
    pub name: Option<String>,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleType {
    Unknown,
    Exec,
    So {
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

pub struct Module {
    pub name: String,
    pub path: String,
    pub ranges: Vec<Range>,
    pub loaded: bool,
    pub module_type: ModuleType,
    pub sym_names: HashSet<String>,
    pub syms: Vec<TestSymbol>,
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

    pub fn load_sym_table(&mut self) {
        if self.loaded {
            return;
        }

        match self.module_type {
            ModuleType::Unknown => {}
            ModuleType::Exec => {
                self.syms = for_each_sym_core(&self.path, false);
                self.syms.sort_by(|a,b| a.address.cmp(&b.address));
            }
            ModuleType::So {
                elf_so_offset,
                elf_so_addr,
            } => {
                self.syms = for_each_sym_core(&self.path, false);
                self.syms.sort_by(|a,b| a.address.cmp(&b.address));
            },
            ModuleType::Vdso => todo!(),
            _ => todo!(),
        }
        self.loaded = true;
    }

    pub fn contains(&self, addr: u64) -> Option<u64> {
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

fn for_each_sym_core(path: &str, is_debug_file: bool) -> Vec<TestSymbol> {
    use std::io::Read;
    let mut buf = Vec::new();
    // bcc_for_each_module ish,
    File::options()
        .read(true)
        .open(path)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();

    let elf = ElfObject::parse(&buf).unwrap();
    if !is_debug_file {
        if let Some(debug_file) = find_debug_file(&elf, path) {
            for_each_sym_core(&debug_file, true);
        }
    }

    println!("Should list symbols!");
    // THIS Could actually work with some tweaks
    elf.symbols().collect()
    //listsymbols(&elf, is_debug_file);
}

fn listsymbols(elf: &ElfObject, is_debug_file: bool) {

}

fn find_debug_file(elf: &ElfObject, path: &str) -> Option<String> {
    if let Some(debug_file) = find_debug_file_via_symfs(elf, path) {
        return Some(debug_file);
    }
    if let Some(debug_file) = find_debug_file_via_buildid(elf) {
        return Some(debug_file);
    }
    println!("No debug file found {path}");
    // TODO via debug link as well
    None
}

fn find_debug_file_via_symfs(elf: &ElfObject, path: &str) -> Option<String> {
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
    let tmp = build_id[1..].iter().map(|b| format!("{b:02x}")).collect::<String>();
    println!("Build id {}", tmp);
    let debug_file_path = format!(
        "/usr/lib/debug/.build-id/{:x}/{}.debug",
        build_id[0],
        &tmp,
    );
    if std::fs::read(&debug_file_path).is_ok() {
        println!("Debug file_path: {debug_file_path}");
        Some(debug_file_path)
    } else {
        None
    }
}

pub struct ProcSyms {
    pub pid: i32,
    pub modules: Vec<Module>,
}

impl ProcSyms {
    pub fn new(pid: i32) -> Self {
        Self {
            pid,
            modules: Vec::new(),
        }
    }

    pub fn load_modules(&mut self) {
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

    pub fn add_module(&mut self, parse_module: ParsedModule) {
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
        if let std::result::Result::Ok(elf) = ElfObject::parse(&buffer) {
            // Kind is doing stuff I might not want to do
            return elf.kind();
        }
        ModuleType::Unknown
    } else if modpath.contains("[vdso]") {
        ModuleType::Vdso
    } else {
        ModuleType::Unknown
    }
}
