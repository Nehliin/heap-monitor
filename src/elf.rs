//! Support for the Executable and Linkable Format, used on Linux.

use std::borrow::Cow;
use std::fmt;
use thiserror::Error;

use core::cmp;
use flate2::{Decompress, FlushDecompress};
use goblin::elf::compression_header::{CompressionHeader, ELFCOMPRESS_ZLIB};
use goblin::elf::SectionHeader;
use goblin::elf64::sym::SymIterator;
use goblin::strtab::Strtab;
use goblin::{
    container::{Container, Ctx},
    elf, strtab,
};
use scroll::Pread;

use crate::syms::{ModuleType, TestSymbol};

const UUID_SIZE: usize = 16;
const PAGE_SIZE: usize = 4096;

const SHN_UNDEF: usize = elf::section_header::SHN_UNDEF as usize;
const SHF_COMPRESSED: u64 = elf::section_header::SHF_COMPRESSED as u64;

pub struct DwarfSection<'data> {
    pub address: u64,
    pub offset: u64,
    pub align: u64,
    pub data: Cow<'data, [u8]>,
}

/// This file follows the first MIPS 32 bit ABI
#[allow(unused)]
const EF_MIPS_ABI_O32: u32 = 0x0000_1000;
/// O32 ABI extended for 64-bit architecture.
const EF_MIPS_ABI_O64: u32 = 0x0000_2000;
/// EABI in 32 bit mode.
#[allow(unused)]
const EF_MIPS_ABI_EABI32: u32 = 0x0000_3000;
/// EABI in 64 bit mode.
const EF_MIPS_ABI_EABI64: u32 = 0x0000_4000;

/// Any flag value that might indicate 64-bit MIPS.
const MIPS_64_FLAGS: u32 = EF_MIPS_ABI_O64 | EF_MIPS_ABI_EABI64;

/// An error when dealing with [`ElfObject`](struct.ElfObject.html).
/*#[derive(Debug, Error)]
#[error("invalid ELF file")]
pub struct ElfError {
    #[source]
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}*/

/*impl ElfError {
    /// Creates a new ELF error from an arbitrary error payload.
    fn new<E>(source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        let source = Some(source.into());
        Self { source }
    }
}*/

/// Executable and Linkable Format, used for executables and libraries on Linux.
pub struct ElfObject<'data> {
    pub elf: elf::Elf<'data>,
    data: &'data [u8],
    is_malformed: bool,
    pub ctx: Ctx,
}

impl<'data> ElfObject<'data> {
    /// Tests whether the buffer could contain an ELF object.
    pub fn test(data: &[u8]) -> bool {
        data.get(0..elf::header::SELFMAG)
            .map_or(false, |data| data == elf::header::ELFMAG)
    }

    // Pulled from https://github.com/m4b/goblin/blob/master/src/elf/mod.rs#L393-L424 as it
    // currently isn't public, but we need this to parse an ELF.
    fn gnu_hash_len(bytes: &[u8], offset: usize, ctx: Ctx) -> goblin::error::Result<usize> {
        let buckets_num = bytes.pread_with::<u32>(offset, ctx.le)? as usize;
        let min_chain = bytes.pread_with::<u32>(offset + 4, ctx.le)? as usize;
        let bloom_size = bytes.pread_with::<u32>(offset + 8, ctx.le)? as usize;
        // We could handle min_chain==0 if we really had to, but it shouldn't happen.
        if buckets_num == 0 || min_chain == 0 || bloom_size == 0 {
            return Err(goblin::error::Error::Malformed(format!(
                "Invalid DT_GNU_HASH: buckets_num={} min_chain={} bloom_size={}",
                buckets_num, min_chain, bloom_size
            )));
        }
        // Find the last bucket.
        let buckets_offset = offset + 16 + bloom_size * if ctx.container.is_big() { 8 } else { 4 };
        let mut max_chain = 0;
        for bucket in 0..buckets_num {
            let chain = bytes.pread_with::<u32>(buckets_offset + bucket * 4, ctx.le)? as usize;
            if max_chain < chain {
                max_chain = chain;
            }
        }
        if max_chain < min_chain {
            return Ok(0);
        }
        // Find the last chain within the bucket.
        let mut chain_offset = buckets_offset + buckets_num * 4 + (max_chain - min_chain) * 4;
        loop {
            let hash = bytes.pread_with::<u32>(chain_offset, ctx.le)?;
            max_chain += 1;
            chain_offset += 4;
            if hash & 1 != 0 {
                return Ok(max_chain);
            }
        }
    }

    // Pulled from https://github.com/m4b/goblin/blob/master/src/elf/mod.rs#L426-L434 as it
    // currently isn't public, but we need this to parse an ELF.
    fn hash_len(
        bytes: &[u8],
        offset: usize,
        machine: u16,
        ctx: Ctx,
    ) -> goblin::error::Result<usize> {
        // Based on readelf code.
        let nchain = if (machine == elf::header::EM_FAKE_ALPHA || machine == elf::header::EM_S390)
            && ctx.container.is_big()
        {
            bytes.pread_with::<u64>(offset.saturating_add(4), ctx.le)? as usize
        } else {
            bytes.pread_with::<u32>(offset.saturating_add(4), ctx.le)? as usize
        };
        Ok(nchain)
    }

    /// Tries to parse an ELF object from the given slice. Will return a partially parsed ELF object
    /// if at least the program and section headers can be parsed.
    pub fn parse(data: &'data [u8]) -> anyhow::Result<Self> {
        let header = elf::Elf::parse_header(data)
            .map_err(|_| anyhow::format_err!("ELF header unreadable"))?;
        // dummy Elf with only header
        let mut obj = elf::Elf::lazy_parse(header)
            .map_err(|_| anyhow::format_err!("cannot parse ELF header"))?;

        let ctx = Ctx {
            container: if obj.is_64 {
                Container::Big
            } else {
                Container::Little
            },
            le: if obj.little_endian {
                scroll::Endian::Little
            } else {
                scroll::Endian::Big
            },
        };

        macro_rules! return_partial_on_err {
            ($parse_func:expr) => {
                if let Ok(expected) = $parse_func() {
                    expected
                } else {
                    // does this snapshot?
                    return Ok(ElfObject {
                        elf: obj,
                        data,
                        is_malformed: true,
                        ctx,
                    });
                }
            };
        }

        obj.program_headers =
            elf::ProgramHeader::parse(data, header.e_phoff as usize, header.e_phnum as usize, ctx)
                .map_err(|_| anyhow::format_err!("unable to parse program headers"))?;

        for ph in &obj.program_headers {
            if ph.p_type == elf::program_header::PT_INTERP && ph.p_filesz != 0 {
                let count = (ph.p_filesz - 1) as usize;
                let offset = ph.p_offset as usize;
                obj.interpreter = data
                    .pread_with::<&str>(offset, ::scroll::ctx::StrCtx::Length(count))
                    .ok();
            }
        }

        obj.section_headers =
            SectionHeader::parse(data, header.e_shoff as usize, header.e_shnum as usize, ctx)
                .map_err(|_| anyhow::format_err!("unable to parse section headers"))?;

        let get_strtab = |section_headers: &[SectionHeader], section_idx: usize| {
            if section_idx >= section_headers.len() {
                // FIXME: warn! here
                Ok(Strtab::default())
            } else {
                let shdr = &section_headers[section_idx];
                shdr.check_size(data.len())?;
                Strtab::parse(data, shdr.sh_offset as usize, shdr.sh_size as usize, 0x0)
            }
        };

        let strtab_idx = header.e_shstrndx as usize;
        obj.shdr_strtab = return_partial_on_err!(|| get_strtab(&obj.section_headers, strtab_idx));

        obj.syms = elf::Symtab::default();
        obj.strtab = Strtab::default();
        for shdr in &obj.section_headers {
            if shdr.sh_type as u32 == elf::section_header::SHT_SYMTAB {
                let size = shdr.sh_entsize;
                let count = if size == 0 { 0 } else { shdr.sh_size / size };
                obj.syms = return_partial_on_err!(|| elf::Symtab::parse(
                    data,
                    shdr.sh_offset as usize,
                    count as usize,
                    ctx
                ));

                obj.strtab = return_partial_on_err!(|| get_strtab(
                    &obj.section_headers,
                    shdr.sh_link as usize
                ));
            }
        }

        obj.soname = None;
        obj.libraries = vec![];
        obj.dynsyms = elf::Symtab::default();
        obj.dynrelas = elf::RelocSection::default();
        obj.dynrels = elf::RelocSection::default();
        obj.pltrelocs = elf::RelocSection::default();
        obj.dynstrtab = Strtab::default();
        let dynamic =
            return_partial_on_err!(|| elf::Dynamic::parse(data, &obj.program_headers, ctx));
        if let Some(ref dynamic) = dynamic {
            let dyn_info = &dynamic.info;
            obj.dynstrtab = return_partial_on_err!(|| Strtab::parse(
                data,
                dyn_info.strtab,
                dyn_info.strsz,
                0x0
            ));

            if dyn_info.soname != 0 {
                // FIXME: warn! here
                obj.soname = obj.dynstrtab.get_at(dyn_info.soname);
            }
            if dyn_info.needed_count > 0 {
                obj.libraries = dynamic.get_libraries(&obj.dynstrtab);
            }
            // parse the dynamic relocations
            obj.dynrelas = return_partial_on_err!(|| elf::RelocSection::parse(
                data,
                dyn_info.rela,
                dyn_info.relasz,
                true,
                ctx
            ));
            obj.dynrels = return_partial_on_err!(|| elf::RelocSection::parse(
                data,
                dyn_info.rel,
                dyn_info.relsz,
                false,
                ctx
            ));
            let is_rela = dyn_info.pltrel as u64 == elf::dynamic::DT_RELA;
            obj.pltrelocs = return_partial_on_err!(|| elf::RelocSection::parse(
                data,
                dyn_info.jmprel,
                dyn_info.pltrelsz,
                is_rela,
                ctx
            ));

            let mut num_syms = if let Some(gnu_hash) = dyn_info.gnu_hash {
                return_partial_on_err!(|| ElfObject::gnu_hash_len(data, gnu_hash as usize, ctx))
            } else if let Some(hash) = dyn_info.hash {
                return_partial_on_err!(|| ElfObject::hash_len(
                    data,
                    hash as usize,
                    header.e_machine,
                    ctx
                ))
            } else {
                0
            };
            let max_reloc_sym = obj
                .dynrelas
                .iter()
                .chain(obj.dynrels.iter())
                .chain(obj.pltrelocs.iter())
                .fold(0, |num, reloc| cmp::max(num, reloc.r_sym));
            if max_reloc_sym != 0 {
                num_syms = cmp::max(num_syms, max_reloc_sym + 1);
            }

            obj.dynsyms =
                return_partial_on_err!(|| elf::Symtab::parse(data, dyn_info.symtab, num_syms, ctx));
        }

        obj.shdr_relocs = vec![];
        for (idx, section) in obj.section_headers.iter().enumerate() {
            let is_rela = section.sh_type == elf::section_header::SHT_RELA;
            if is_rela || section.sh_type == elf::section_header::SHT_REL {
                return_partial_on_err!(|| section.check_size(data.len()));
                let sh_relocs = return_partial_on_err!(|| elf::RelocSection::parse(
                    data,
                    section.sh_offset as usize,
                    section.sh_size as usize,
                    is_rela,
                    ctx,
                ));
                obj.shdr_relocs.push((idx, sh_relocs));
            }
        }

        obj.versym = return_partial_on_err!(|| elf::symver::VersymSection::parse(
            data,
            &obj.section_headers,
            ctx
        ));
        obj.verdef = return_partial_on_err!(|| elf::symver::VerdefSection::parse(
            data,
            &obj.section_headers,
            ctx
        ));
        obj.verneed = return_partial_on_err!(|| elf::symver::VerneedSection::parse(
            data,
            &obj.section_headers,
            ctx
        ));

        Ok(ElfObject {
            elf: obj,
            data,
            is_malformed: false,
            ctx,
        })
    }

    /// The binary's soname, if any.
    pub fn name(&self) -> Option<&'data str> {
        self.elf.soname
    }

    /// The kind of this object, as specified in the ELF header.
    pub fn kind(&self) -> ModuleType {
        let kind = match self.elf.header.e_type {
            goblin::elf::header::ET_NONE => ModuleType::Unknown,
            goblin::elf::header::ET_REL => ModuleType::Unknown,
            goblin::elf::header::ET_EXEC => ModuleType::Exec,
            goblin::elf::header::ET_DYN => {
                if let Some(text_section) = self.section("text") {
                    return ModuleType::So {
                        elf_so_offset: text_section.offset,
                        elf_so_addr: text_section.address,
                    };
                }
                panic!("Failed to find text section for lib");
            }
            goblin::elf::header::ET_CORE => ModuleType::Unknown,
            _ => ModuleType::Unknown,
        };

        // When stripping debug information into a separate file with objcopy,
        // the eh_type field still reads ET_EXEC. However, the interpreter is
        // removed. Since an executable without interpreter does not make any
        // sense, we assume ``Debug`` in this case.
        if kind == ModuleType::Exec && self.elf.interpreter.is_none() {
            return ModuleType::Debug;
        }

        // The same happens for libraries. However, here we can only check for
        // a missing text section. If this still yields too many false positivies,
        // we will have to check either the size or offset of that section in
        // the future.
        if matches!(kind, ModuleType::So { .. }) && self.raw_section("text").is_none() {
            return ModuleType::Debug;
        }

        kind
    }

    /// The address at which the image prefers to be loaded into memory.
    ///
    /// ELF files store all internal addresses as if it was loaded at that address. When the image
    /// is actually loaded, that spot might already be taken by other images and so it must be
    /// relocated to a new address. At runtime, a relocation table manages the arithmetics behind
    /// this.
    ///
    /// Addresses used in `symbols` or `debug_session` have already been rebased relative to that
    /// load address, so that the caller only has to deal with addresses relative to the actual
    /// start of the image.
    pub fn load_address(&self) -> u64 {
        // For non-PIC executables (e_type == ET_EXEC), the load address is
        // the start address of the first PT_LOAD segment.  (ELF requires
        // the segments to be sorted by load address.)  For PIC executables
        // and dynamic libraries (e_type == ET_DYN), this address will
        // normally be zero.
        for phdr in &self.elf.program_headers {
            if phdr.p_type == elf::program_header::PT_LOAD {
                return phdr.p_vaddr;
            }
        }

        0
    }

    /// Determines whether this object exposes a public symbol table.
    pub fn has_symbols(&self) -> bool {
        !self.elf.syms.is_empty() || !self.elf.dynsyms.is_empty()
    }

    /// Returns an iterator over symbols in the public symbol table.
    pub fn symbols(&self) -> ElfSymbolIterator<'data, '_> {
        ElfSymbolIterator {
            symbols: self.elf.syms.iter(),
            strtab: &self.elf.strtab,
            dynamic_symbols: self.elf.dynsyms.iter(),
            dynamic_strtab: &self.elf.dynstrtab,
            sections: &self.elf.section_headers,
            load_addr: self.load_address(),
        }
    }

    /// Determines whether this object contains debug information.
    //pub fn has_debug_info(&self) -> bool {
    //    self.has_section("debug_info")
    // }

    /// Determines whether this object contains stack unwinding information.
    // pub fn has_unwind_info(&self) -> bool {
    //    self.has_section("eh_frame") || self.has_section("debug_frame")
    // }

    /// Determines whether this object contains embedded source.
    pub fn has_sources(&self) -> bool {
        false
    }

    /// Determines whether this object is malformed and was only partially parsed
    pub fn is_malformed(&self) -> bool {
        self.is_malformed
    }

    /// Returns the raw data of the ELF file.
    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    /// Decompresses the given compressed section data, if supported.
    pub fn decompress_section(&self, section_data: &[u8]) -> Option<Vec<u8>> {
        let (size, compressed) = if section_data.starts_with(b"ZLIB") {
            // The GNU compression header is a 4 byte magic "ZLIB", followed by an 8-byte big-endian
            // size prefix of the decompressed data. This adds up to 12 bytes of GNU header.
            if section_data.len() < 12 {
                return None;
            }

            let mut size_bytes = [0; 8];
            size_bytes.copy_from_slice(&section_data[4..12]);

            (u64::from_be_bytes(size_bytes), &section_data[12..])
        } else {
            let container = self.elf.header.container().ok()?;
            let endianness = self.elf.header.endianness().ok()?;
            let context = Ctx::new(container, endianness);

            let compression = CompressionHeader::parse(section_data, 0, context).ok()?;
            if compression.ch_type != ELFCOMPRESS_ZLIB {
                return None;
            }

            let compressed = &section_data[CompressionHeader::size(context)..];
            (compression.ch_size, compressed)
        };

        let mut decompressed = Vec::with_capacity(size as usize);
        Decompress::new(true)
            .decompress_vec(compressed, &mut decompressed, FlushDecompress::Finish)
            .ok()?;

        Some(decompressed)
    }

    pub fn section(&self, name: &str) -> Option<DwarfSection<'data>> {
        let (compressed, mut section) = self.find_section(name)?;

        if compressed {
            let decompressed = self.decompress_section(&section.data)?;
            section.data = Cow::Owned(decompressed);
        }

        Some(section)
    }

    pub fn raw_section(&self, name: &str) -> Option<DwarfSection<'data>> {
        let (_, section) = self.find_section(name)?;
        Some(section)
    }

    pub fn section_from_header(
        &self,
        header: &SectionHeader,
    ) -> Option<(bool, DwarfSection<'data>)> {
        // TODO
        if let Some(section_name) = self.elf.shdr_strtab.get_at(header.sh_name) {
            let offset = header.sh_offset as usize;
            if offset == 0 {
                // We're defensive here. On darwin, dsymutil leaves phantom section headers
                // while stripping their data from the file by setting their offset to 0. We
                // know that no section can start at an absolute file offset of zero, so we can
                // safely skip them in case similar things happen on linux.
                return None;
            }

            if section_name.is_empty() {
                panic!("empty section name");
            }

            // Before SHF_COMPRESSED was a thing, compressed sections were prefixed with `.z`.
            // Support this as an override to the flag.
            let (compressed, section_name) = match section_name.strip_prefix(".z") {
                Some(name) => (true, name),
                None => (header.sh_flags & SHF_COMPRESSED != 0, &section_name[1..]),
            };

            let size = header.sh_size as usize;
            let data = &self.data[offset..][..size];
            let section = DwarfSection {
                data: Cow::Borrowed(data),
                address: header.sh_addr,
                offset: header.sh_offset,
                align: header.sh_addralign,
            };

            return Some((compressed, section));
        }
        None
    }

    /// Locates and reads a section in an ELF binary.
    pub fn find_section(&self, name: &str) -> Option<(bool, DwarfSection<'data>)> {
        for header in &self.elf.section_headers {
            const SHT_MIPS_DWARF: u32 = 0x7000_001e;
            const SHT_PROGBITS: u32 = elf::section_header::SHT_PROGBITS;
            if !matches!(header.sh_type, SHT_PROGBITS | SHT_MIPS_DWARF) {
                continue;
            }

            if let Some(section_name) = self.elf.shdr_strtab.get_at(header.sh_name) {
                let offset = header.sh_offset as usize;
                if offset == 0 {
                    // We're defensive here. On darwin, dsymutil leaves phantom section headers
                    // while stripping their data from the file by setting their offset to 0. We
                    // know that no section can start at an absolute file offset of zero, so we can
                    // safely skip them in case similar things happen on linux.
                    return None;
                }

                if section_name.is_empty() {
                    continue;
                }

                // Before SHF_COMPRESSED was a thing, compressed sections were prefixed with `.z`.
                // Support this as an override to the flag.
                let (compressed, section_name) = match section_name.strip_prefix(".z") {
                    Some(name) => (true, name),
                    None => (header.sh_flags & SHF_COMPRESSED != 0, &section_name[1..]),
                };

                if section_name != name {
                    continue;
                }

                let size = header.sh_size as usize;
                let data = &self.data[offset..][..size];
                let section = DwarfSection {
                    data: Cow::Borrowed(data),
                    address: header.sh_addr,
                    offset: header.sh_offset,
                    align: header.sh_addralign,
                };

                return Some((compressed, section));
            }
        }

        None
    }

    /// Searches for a GNU build identifier node in an ELF file.
    ///
    /// Depending on the compiler and linker, the build ID can be declared in a
    /// PT_NOTE program header entry, the ".note.gnu.build-id" section, or even
    /// both.
    pub fn find_build_id(&self) -> Option<&'data [u8]> {
        // First, search the note program headers (PT_NOTE) for a NT_GNU_BUILD_ID.
        // We swallow all errors during this process and simply fall back to the
        // next method below.
        if let Some(mut notes) = self.elf.iter_note_headers(self.data) {
            while let Some(Ok(note)) = notes.next() {
                if note.n_type == elf::note::NT_GNU_BUILD_ID {
                    return Some(note.desc);
                }
            }
        }

        // Some old linkers or compilers might not output the above PT_NOTE headers.
        // In that case, search for a note section (SHT_NOTE). We are looking for a
        // note within the ".note.gnu.build-id" section. Again, swallow all errors
        // and fall through if reading the section is not possible.
        if let Some(mut notes) = self
            .elf
            .iter_note_sections(self.data, Some(".note.gnu.build-id"))
        {
            while let Some(Ok(note)) = notes.next() {
                if note.n_type == elf::note::NT_GNU_BUILD_ID {
                    return Some(note.desc);
                }
            }
        }

        None
    }
}

impl fmt::Debug for ElfObject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElfObject")
            .field("load_address", &format_args!("{:#x}", self.load_address()))
            .field("has_symbols", &self.has_symbols())
            //        .field("has_debug_info", &self.has_debug_info())
            //       .field("has_unwind_info", &self.has_unwind_info())
            .field("is_malformed", &self.is_malformed())
            .finish()
    }
}

/// An iterator over symbols in the ELF file.
///
/// Returned by [`ElfObject::symbols`](struct.ElfObject.html#method.symbols).
pub struct ElfSymbolIterator<'data, 'object> {
    symbols: elf::sym::SymIterator<'data>,
    strtab: &'object strtab::Strtab<'data>,
    dynamic_symbols: elf::sym::SymIterator<'data>,
    dynamic_strtab: &'object strtab::Strtab<'data>,
    sections: &'object [elf::SectionHeader],
    load_addr: u64,
}

impl<'data, 'object> Iterator for ElfSymbolIterator<'data, 'object> {
    type Item = TestSymbol;

    fn next(&mut self) -> Option<Self::Item> {
        fn get_symbols<'data>(
            symbols: &mut SymIterator,
            strtab: &Strtab<'data>,
            load_addr: u64,
            sections: &[SectionHeader],
        ) -> Option<TestSymbol> {
            for symbol in symbols {
                // Only check for function symbols.
                if symbol.st_type() != elf::sym::STT_FUNC {
                    continue;
                }

                // Sanity check of the symbol address. Since we only intend to iterate over function
                // symbols, they need to be mapped after the image's load address.
                if symbol.st_value < load_addr {
                    continue;
                }

                let section = match symbol.st_shndx {
                    self::SHN_UNDEF => None,
                    index => sections.get(index),
                };

                // We are only interested in symbols pointing into sections with executable flag.
                if !section.map_or(false, |header| header.is_executable()) {
                    continue;
                }

                let name = strtab.get_at(symbol.st_name).map(|s| s.to_owned());

                return Some(TestSymbol {
                    name,
                    // This might not be what I want
                    address: symbol.st_value - load_addr,
                    size: symbol.st_size,
                });
            }

            None
        }

        get_symbols(
            &mut self.symbols,
            self.strtab,
            self.load_addr,
            self.sections,
        )
        .or_else(|| {
            get_symbols(
                &mut self.dynamic_symbols,
                self.dynamic_strtab,
                self.load_addr,
                self.sections,
            )
        })
    }
}
