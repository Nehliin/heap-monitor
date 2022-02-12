use std::{collections::HashSet, path::Path, fs::File};

use symbolic::debuginfo::{dwarf::Dwarf, Object};

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

pub enum ModuleType {
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
    pub syms: Vec<Symbol>,
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
