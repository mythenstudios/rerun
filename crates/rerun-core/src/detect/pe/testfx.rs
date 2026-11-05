//! Test-only builder for synthetic PE images (ADR 0013, `docs/09-testing.md`, "PE parser").
//! Every image, name and string is invented.
//!
//! Layout of a built image: DOS header, NT headers at `e_lfanew`, the section table, padding to
//! `SizeOfHeaders` (a multiple of 0x200); then one data section `.rdata` at RVA [`DATA_RVA`]
//! holding [`Builder::data`], then `extra_sections` empty sections without file data.

use super::layout as l;

/// RVA of the data section.
pub(super) const DATA_RVA: u32 = 0x1000;
/// File alignment of the built images.
pub(super) const FILE_ALIGN: usize = 0x200;

/// Writes `v` little-endian at `at`, growing `b` if needed.
pub(super) fn put(b: &mut Vec<u8>, at: usize, v: &[u8]) {
    if b.len() < at + v.len() {
        b.resize(at + v.len(), 0);
    }
    b[at..at + v.len()].copy_from_slice(v);
}

pub(super) fn put16(b: &mut Vec<u8>, at: usize, v: u16) {
    put(b, at, &v.to_le_bytes());
}

pub(super) fn put32(b: &mut Vec<u8>, at: usize, v: u32) {
    put(b, at, &v.to_le_bytes());
}

fn align(v: usize, to: usize) -> usize {
    v.div_ceil(to) * to
}

/// A synthetic image to build.
#[derive(Debug, Clone)]
pub(super) struct Builder {
    pub machine: u16,
    pub magic: u16,
    pub characteristics: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub image_base: u64,
    pub e_lfanew: u32,
    /// `NumberOfRvaAndSizes`.
    pub rva_count: u32,
    /// `SizeOfOptionalHeader`; `None`: the fixed part plus `min(rva_count, 16)` directories.
    pub opt_size: Option<u16>,
    /// Empty sections after the data section (no file data).
    pub extra_sections: usize,
    /// Data directories `(index, rva, size)`, written in this order.
    pub dirs: Vec<(usize, u32, u32)>,
    /// Content of the data section (generated parts follow it).
    pub data: Vec<u8>,
    /// Import directory: DLL names without NUL; `Some(vec![])` is a table with only the
    /// terminator.
    pub imports: Option<Vec<Vec<u8>>>,
    /// Delay-import directory: DLL names and whether the descriptor is RVA-based (`false`:
    /// VC6 style, the name is a virtual address).
    pub delay: Option<Vec<(Vec<u8>, bool)>>,
    /// Load config: its `Size` field and `DependentLoadFlags`.
    pub load_config: Option<(u32, u16)>,
    /// Resource directory: the entries of the root table.
    pub resources: Option<Vec<(ResId, Node)>>,
}

/// A built image and where its parts are.
#[derive(Debug, Clone)]
pub(super) struct Image {
    pub bytes: Vec<u8>,
    /// File offset of the COFF file header.
    pub coff: usize,
    /// File offset of the optional header.
    pub opt: usize,
    /// File offset of the section table.
    pub table: usize,
    /// File offset of the data section.
    pub data: usize,
    /// File offset of the import descriptor table.
    pub import_table: Option<usize>,
    /// File offset of the delay-import descriptor table.
    pub delay_table: Option<usize>,
    /// File offset of the load config.
    pub load_config: Option<usize>,
    /// File offset of the resource directory (its root table).
    pub rsrc: Option<usize>,
    /// File offsets of the generated DLL names: imports, then delay imports.
    pub names: Vec<usize>,
}

impl Builder {
    /// An x64 GUI executable (PE32+), nothing imported.
    pub fn x64() -> Self {
        Self {
            machine: l::MACHINE_AMD64,
            magic: l::OPTIONAL_MAGIC_PE32_PLUS,
            characteristics: 0x0022,
            subsystem: l::SUBSYSTEM_WINDOWS_GUI,
            dll_characteristics: 0x8160,
            image_base: 0x1_4000_0000,
            e_lfanew: 0x80,
            rva_count: 16,
            opt_size: None,
            extra_sections: 0,
            dirs: Vec::new(),
            data: Vec::new(),
            imports: None,
            delay: None,
            load_config: None,
            resources: None,
        }
    }

    /// The image with `blob` as its version resource ([`version_tree`]).
    pub fn with_version(mut self, blob: Vec<u8>) -> Self {
        self.resources = Some(version_tree(blob));
        self
    }

    /// An x86 GUI executable (PE32), not Large Address Aware, nothing imported.
    pub fn x86() -> Self {
        Self {
            machine: l::MACHINE_I386,
            magic: l::OPTIONAL_MAGIC_PE32,
            characteristics: 0x0102,
            dll_characteristics: 0x8140,
            image_base: 0x40_0000,
            ..Self::x64()
        }
    }

    /// Size of the fixed part of the optional header for `magic`.
    pub fn fixed(&self) -> usize {
        if self.magic == l::OPTIONAL_MAGIC_PE32 {
            l::OPT32_DATA_DIRECTORY
        } else {
            l::OPT64_DATA_DIRECTORY
        }
    }

    /// RVA of byte `at` of the data section.
    pub fn rva(at: usize) -> u32 {
        DATA_RVA + u32::try_from(at).unwrap()
    }

    /// The data section with the generated parts, their directories and offsets (relative to
    /// the data section).
    fn generate(&self) -> (Vec<u8>, Vec<(usize, u32, u32)>, Generated) {
        let mut data = self.data.clone();
        let mut dirs = Vec::new();
        let mut g = Generated::default();
        let mut name = |data: &mut Vec<u8>, bytes: &[u8]| {
            let at = data.len();
            data.extend_from_slice(bytes);
            data.push(0);
            g.names.push(at);
            Self::rva(at)
        };
        let import_names: Vec<u32> = self
            .imports
            .iter()
            .flatten()
            .map(|n| name(&mut data, n))
            .collect();
        let delay_names: Vec<(u32, bool)> = self
            .delay
            .iter()
            .flatten()
            .map(|(n, rva_based)| (name(&mut data, n), *rva_based))
            .collect();
        let align8 = |data: &mut Vec<u8>| data.resize(align(data.len(), 8), 0);
        if let Some(root) = &self.resources {
            align8(&mut data);
            let at = data.len();
            let tree = encode_tree(root, Self::rva(at));
            data.extend_from_slice(&tree);
            g.rsrc = Some(at);
            dirs.push((
                l::DIR_RESOURCE,
                Self::rva(at),
                u32::try_from(tree.len()).unwrap(),
            ));
        }
        if let Some((size, flags)) = self.load_config {
            align8(&mut data);
            let at = data.len();
            let field = if self.magic == l::OPTIONAL_MAGIC_PE32 {
                l::LOAD_CONFIG32_DEPENDENT_LOAD_FLAGS
            } else {
                l::LOAD_CONFIG64_DEPENDENT_LOAD_FLAGS
            };
            put32(&mut data, at + l::LOAD_CONFIG_SIZE, size);
            put16(&mut data, at + field, flags);
            g.load_config = Some(at);
            dirs.push((l::DIR_LOAD_CONFIG, Self::rva(at), size));
        }
        if self.delay.is_some() {
            align8(&mut data);
            let at = data.len();
            for (i, (rva, rva_based)) in delay_names.iter().enumerate() {
                let d = at + i * l::DELAYLOAD_DESCRIPTOR_SIZE;
                let (attributes, name) = if *rva_based {
                    (l::DELAYLOAD_RVA_BASED, *rva)
                } else {
                    let va = self.image_base + u64::from(*rva);
                    (0, u32::try_from(va).unwrap())
                };
                put32(&mut data, d + l::DELAYLOAD_ATTRIBUTES, attributes);
                put32(&mut data, d + l::DELAYLOAD_DLL_NAME_RVA, name);
                put32(&mut data, d + 12, *rva);
            }
            let size = (delay_names.len() + 1) * l::DELAYLOAD_DESCRIPTOR_SIZE;
            data.resize(at + size, 0);
            g.delay_table = Some(at);
            dirs.push((
                l::DIR_DELAY_IMPORT,
                Self::rva(at),
                u32::try_from(size).unwrap(),
            ));
        }
        if self.imports.is_some() {
            align8(&mut data);
            let at = data.len();
            for (i, rva) in import_names.iter().enumerate() {
                let d = at + i * l::IMPORT_DESCRIPTOR_SIZE;
                put32(&mut data, d + l::IMPORT_NAME, *rva);
                // FirstThunk: never read, only non-zero.
                put32(&mut data, d + 16, *rva);
            }
            let size = (import_names.len() + 1) * l::IMPORT_DESCRIPTOR_SIZE;
            data.resize(at + size, 0);
            g.import_table = Some(at);
            dirs.push((l::DIR_IMPORT, Self::rva(at), u32::try_from(size).unwrap()));
        }
        dirs.extend(self.dirs.iter().copied());
        (data, dirs, g)
    }

    pub fn build(&self) -> Image {
        let (data, dirs_written, g) = self.generate();
        let e = usize::try_from(self.e_lfanew).unwrap();
        let coff = e + 4;
        let opt = coff + l::FILE_HEADER_SIZE;
        let fixed = self.fixed();
        let dirs = usize::try_from(self.rva_count).unwrap().min(16);
        let opt_size = self.opt_size.map_or(fixed + dirs * 8, usize::from);
        let table = opt + opt_size;
        let sections = 1 + self.extra_sections;
        let headers_end = table + sections * l::SECTION_HEADER_SIZE;
        let size_of_headers = align(headers_end.max(l::DOS_HEADER_SIZE), FILE_ALIGN);
        let data_len = data.len().max(1);
        let raw_size = align(data_len, FILE_ALIGN);

        let mut b = vec![0u8; size_of_headers];
        put(&mut b, 0, l::DOS_SIGNATURE);
        put32(&mut b, l::DOS_E_LFANEW, self.e_lfanew);
        put(&mut b, e, l::NT_SIGNATURE);
        put16(&mut b, coff + l::FILE_MACHINE, self.machine);
        put16(
            &mut b,
            coff + l::FILE_NUMBER_OF_SECTIONS,
            u16::try_from(sections).unwrap(),
        );
        put16(
            &mut b,
            coff + l::FILE_SIZE_OF_OPTIONAL_HEADER,
            u16::try_from(opt_size).unwrap(),
        );
        put16(&mut b, coff + l::FILE_CHARACTERISTICS, self.characteristics);
        // The optional header fields are written only where `opt_size` leaves room, so a
        // too small header does not overwrite the section table.
        let opt_field = |b: &mut Vec<u8>, at: usize, v: &[u8]| {
            if at + v.len() <= opt_size {
                put(b, opt + at, v);
            }
        };
        opt_field(&mut b, l::OPT_MAGIC, &self.magic.to_le_bytes());
        if self.magic == l::OPTIONAL_MAGIC_PE32 {
            let base = u32::try_from(self.image_base).unwrap();
            opt_field(&mut b, l::OPT32_IMAGE_BASE, &base.to_le_bytes());
            opt_field(
                &mut b,
                l::OPT32_NUMBER_OF_RVA_AND_SIZES,
                &self.rva_count.to_le_bytes(),
            );
        } else {
            opt_field(&mut b, l::OPT64_IMAGE_BASE, &self.image_base.to_le_bytes());
            opt_field(
                &mut b,
                l::OPT64_NUMBER_OF_RVA_AND_SIZES,
                &self.rva_count.to_le_bytes(),
            );
        }
        let soh = u32::try_from(size_of_headers).unwrap();
        opt_field(&mut b, l::OPT_SIZE_OF_HEADERS, &soh.to_le_bytes());
        opt_field(&mut b, l::OPT_SUBSYSTEM, &self.subsystem.to_le_bytes());
        opt_field(
            &mut b,
            l::OPT_DLL_CHARACTERISTICS,
            &self.dll_characteristics.to_le_bytes(),
        );
        for &(index, rva, size) in &dirs_written {
            let at = fixed + index * l::DATA_DIRECTORY_SIZE;
            opt_field(&mut b, at, &rva.to_le_bytes());
            opt_field(&mut b, at + 4, &size.to_le_bytes());
        }

        // Section table: the data section, then empty ones far above it.
        let section = |b: &mut Vec<u8>, i: usize, name: &[u8], va: u32, vs: u32, rs, rp| {
            let s = table + i * l::SECTION_HEADER_SIZE;
            put(b, s, name);
            put32(b, s + l::SECTION_VIRTUAL_SIZE, vs);
            put32(b, s + l::SECTION_VIRTUAL_ADDRESS, va);
            put32(b, s + l::SECTION_SIZE_OF_RAW_DATA, rs);
            put32(b, s + l::SECTION_POINTER_TO_RAW_DATA, rp);
        };
        section(
            &mut b,
            0,
            b".rdata\0\0",
            DATA_RVA,
            u32::try_from(data_len).unwrap(),
            u32::try_from(raw_size).unwrap(),
            soh,
        );
        for i in 0..self.extra_sections {
            let va = 0x0100_0000 + u32::try_from(i).unwrap() * 0x1000;
            section(&mut b, i + 1, b".bss\0\0\0\0", va, 0x1000, 0, 0);
        }
        b.resize(size_of_headers + raw_size, 0);
        put(&mut b, size_of_headers, &data);
        let file = |at: usize| size_of_headers + at;
        Image {
            bytes: b,
            coff,
            opt,
            table,
            data: size_of_headers,
            import_table: g.import_table.map(file),
            delay_table: g.delay_table.map(file),
            load_config: g.load_config.map(file),
            rsrc: g.rsrc.map(file),
            names: g.names.into_iter().map(file).collect(),
        }
    }
}

/// Offsets of the generated parts, relative to the data section.
#[derive(Debug, Default)]
struct Generated {
    import_table: Option<usize>,
    delay_table: Option<usize>,
    load_config: Option<usize>,
    rsrc: Option<usize>,
    names: Vec<usize>,
}

/// `n` distinct DLL names of `len` bytes each (`len` at least 8).
pub(super) fn dll_names(n: usize, len: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let mut v = format!("m{i:06}").into_bytes();
            v.resize(len - 4, b'x');
            v.extend_from_slice(b".dll");
            v
        })
        .collect()
}

/// A plain DOS executable: `MZ`, a 64-byte header, `e_lfanew` 0, some code.
pub(super) fn dos_exe() -> Vec<u8> {
    let mut b = vec![0u8; 0x80];
    put(&mut b, 0, l::DOS_SIGNATURE);
    put(&mut b, 0x40, b"\xB4\x4C\xCD\x21");
    b
}

/// An `MZ` stub with a new-executable signature `sig` at `e_lfanew` 0x80.
pub(super) fn new_exe(sig: &[u8; 2]) -> Vec<u8> {
    let mut b = vec![0u8; 0x200];
    put(&mut b, 0, l::DOS_SIGNATURE);
    put32(&mut b, l::DOS_E_LFANEW, 0x80);
    put(&mut b, 0x80, sig);
    b
}

// ---------- Resources ----------

/// The name or ID of a resource directory entry.
#[derive(Debug, Clone, Copy)]
pub(super) enum ResId {
    Id(u16),
    /// A named entry (its string is never read; the name offset is 0).
    Name,
}

/// A resource directory node.
#[derive(Debug, Clone)]
pub(super) enum Node {
    Dir(Vec<(ResId, Node)>),
    Data(Vec<u8>),
}

/// `RT_VERSION` → ID 1 → language 0x0409 → `blob`. Encoded: root table at 0, the ID table at
/// [`TREE_NAMES`], the language table at [`TREE_LANGS`], the data entry at [`TREE_ENTRY`], the
/// blob at [`TREE_BLOB`].
pub(super) fn version_tree(blob: Vec<u8>) -> Vec<(ResId, Node)> {
    vec![(
        ResId::Id(l::RT_VERSION),
        Node::Dir(vec![(
            ResId::Id(1),
            Node::Dir(vec![(ResId::Id(l::LANG_EN_US), Node::Data(blob))]),
        )]),
    )]
}

/// Offsets of the parts of [`version_tree`] below the resource directory.
pub(super) const TREE_NAMES: usize = 24;
pub(super) const TREE_LANGS: usize = 48;
pub(super) const TREE_ENTRY: usize = 72;
pub(super) const TREE_BLOB: usize = 88;

fn encode_table(entries: &[(ResId, Node)], buf: &mut Vec<u8>, base: u32) -> u32 {
    let at = buf.len();
    let named = entries
        .iter()
        .filter(|(id, _)| matches!(id, ResId::Name))
        .count();
    buf.resize(at + 16 + 8 * entries.len(), 0);
    put16(buf, at + 12, u16::try_from(named).unwrap());
    put16(buf, at + 14, u16::try_from(entries.len() - named).unwrap());
    for (i, (id, node)) in entries.iter().enumerate() {
        let name = match id {
            ResId::Id(v) => u32::from(*v),
            ResId::Name => l::RESOURCE_NAME_IS_STRING,
        };
        let target = match node {
            Node::Dir(children) => {
                encode_table(children, buf, base) | l::RESOURCE_DATA_IS_DIRECTORY
            }
            Node::Data(bytes) => {
                let e = align(buf.len(), 4);
                buf.resize(e + 16, 0);
                let d = buf.len();
                buf.extend_from_slice(bytes);
                put32(buf, e, base + u32::try_from(d).unwrap());
                put32(buf, e + 4, u32::try_from(bytes.len()).unwrap());
                u32::try_from(e).unwrap()
            }
        };
        put32(buf, at + 16 + 8 * i, name);
        put32(buf, at + 20 + 8 * i, target);
    }
    u32::try_from(at).unwrap()
}

/// Encodes a resource directory whose root table holds `root`, depth first; `base` is its RVA.
pub(super) fn encode_tree(root: &[(ResId, Node)], base: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_table(root, &mut buf, base);
    buf
}

// ---------- VS_VERSIONINFO ----------

/// The value of a version block.
#[derive(Debug, Clone)]
pub(super) enum Value {
    None,
    Bin(Vec<u8>),
    /// UTF-16 text plus its NUL; `wValueLength` in words (the specification).
    Text(String),
    /// Raw UTF-16 units, no NUL added.
    Units(Vec<u16>),
}

/// A version block to encode.
#[derive(Debug, Clone)]
pub(super) struct Vs {
    pub key: String,
    pub value: Value,
    /// `wValueLength` instead of the computed one.
    pub value_len: Option<u16>,
    /// `wLength` instead of the computed one.
    pub length: Option<u16>,
    pub children: Vec<Vs>,
}

impl Vs {
    pub fn new(key: &str, value: Value, children: Vec<Vs>) -> Self {
        Self {
            key: key.to_owned(),
            value,
            value_len: None,
            length: None,
            children,
        }
    }

    /// A string block `key` = `value`.
    pub fn string(key: &str, value: &str) -> Self {
        Self::new(key, Value::Text(value.to_owned()), Vec::new())
    }

    /// The encoded block, as the root of a resource.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.resize(align(out.len(), 4), 0);
        let start = out.len();
        out.resize(start + 6, 0);
        for u in self.key.encode_utf16().chain([0]) {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out.resize(align(out.len(), 4), 0);
        let value_len = match &self.value {
            Value::None => 0,
            Value::Bin(b) => {
                out.extend_from_slice(b);
                b.len()
            }
            Value::Text(t) => {
                let units: Vec<u16> = t.encode_utf16().chain([0]).collect();
                for u in &units {
                    out.extend_from_slice(&u.to_le_bytes());
                }
                units.len()
            }
            Value::Units(units) => {
                for u in units {
                    out.extend_from_slice(&u.to_le_bytes());
                }
                units.len()
            }
        };
        for c in &self.children {
            c.write(out);
        }
        let length = self
            .length
            .unwrap_or_else(|| u16::try_from(out.len() - start).unwrap());
        let value_len = self
            .value_len
            .unwrap_or_else(|| u16::try_from(value_len).unwrap());
        put16(out, start, length);
        put16(out, start + 2, value_len);
        let w_type = u16::from(matches!(self.value, Value::Text(_) | Value::Units(_)));
        put16(out, start + 4, w_type);
    }
}

/// A `VS_FIXEDFILEINFO` with file version `file` and product version `product`.
pub(super) fn fixed_info(file: [u16; 4], product: [u16; 4]) -> Vec<u8> {
    let mut b = vec![0u8; l::FIXED_FILE_INFO_SIZE];
    let ms = |v: [u16; 4]| u32::from(v[0]) << 16 | u32::from(v[1]);
    let ls = |v: [u16; 4]| u32::from(v[2]) << 16 | u32::from(v[3]);
    put32(&mut b, l::FIXED_SIGNATURE, l::FIXED_SIGNATURE_VALUE);
    put32(&mut b, 4, 0x0001_0000);
    put32(&mut b, l::FIXED_FILE_VERSION_MS, ms(file));
    put32(&mut b, l::FIXED_FILE_VERSION_LS, ls(file));
    put32(&mut b, l::FIXED_PRODUCT_VERSION_MS, ms(product));
    put32(&mut b, l::FIXED_PRODUCT_VERSION_LS, ls(product));
    put32(&mut b, l::FIXED_FILE_FLAGS_MASK, 0x3F);
    put32(&mut b, l::FIXED_FILE_FLAGS, 0);
    put32(&mut b, l::FIXED_FILE_OS, 0x0004_0004);
    put32(&mut b, l::FIXED_FILE_TYPE, 1);
    put32(&mut b, l::FIXED_FILE_SUBTYPE, 0);
    b
}

/// A string table `key` (8 hex digits) with `strings`.
pub(super) fn string_table(key: &str, strings: &[(&str, &str)]) -> Vs {
    Vs::new(
        key,
        Value::None,
        strings.iter().map(|(k, v)| Vs::string(k, v)).collect(),
    )
}

/// `VarFileInfo` with one `Translation` pair.
pub(super) fn var_file_info(language: u16, codepage: u16) -> Vs {
    let mut pair = language.to_le_bytes().to_vec();
    pair.extend_from_slice(&codepage.to_le_bytes());
    Vs::new(
        "VarFileInfo",
        Value::None,
        vec![Vs::new("Translation", Value::Bin(pair), Vec::new())],
    )
}

/// A complete `VS_VERSION_INFO`: fixed part, `StringFileInfo` with `tables`, then
/// `VarFileInfo` with `translation`.
pub(super) fn version_info(tables: Vec<Vs>, translation: Option<(u16, u16)>) -> Vs {
    let mut children = vec![Vs::new("StringFileInfo", Value::None, tables)];
    if let Some((language, codepage)) = translation {
        children.push(var_file_info(language, codepage));
    }
    Vs::new(
        "VS_VERSION_INFO",
        Value::Bin(fixed_info([1, 2, 3, 4], [1, 2, 0, 0])),
        children,
    )
}

/// The usual game executable's strings (invented).
pub(super) const STRINGS: &[(&str, &str)] = &[
    ("CompanyName", "Invented Games"),
    ("FileDescription", "Invented Game"),
    ("FileVersion", "1.2.3.4"),
    ("InternalName", "game"),
    ("LegalCopyright", "(c) nobody"),
    ("OriginalFilename", "game.exe"),
    ("ProductName", "Invented"),
    ("ProductVersion", "1.2"),
];
