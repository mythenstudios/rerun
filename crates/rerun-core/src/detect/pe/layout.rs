//! Offsets and constants of the PE format, written out from `winnt.h`, `winuser.h` and
//! `verrsrc.h` (SDK 10.0.26100), ADR 0013. Offsets are relative to the start of their
//! structure. A Windows-only test pins them against the `windows-sys` structures and constants.

/// `IMAGE_DOS_SIGNATURE`.
pub const DOS_SIGNATURE: &[u8; 2] = b"MZ";
/// Size of `IMAGE_DOS_HEADER`.
pub const DOS_HEADER_SIZE: usize = 64;
/// `IMAGE_DOS_HEADER::e_lfanew`.
pub const DOS_E_LFANEW: usize = 0x3C;
/// `IMAGE_NT_SIGNATURE`.
pub const NT_SIGNATURE: &[u8; 4] = b"PE\0\0";
/// `IMAGE_OS2_SIGNATURE` (NE).
pub const NE_SIGNATURE: &[u8; 2] = b"NE";
/// `IMAGE_VXD_SIGNATURE` (LE).
pub const LE_SIGNATURE: &[u8; 2] = b"LE";
/// LX (OS/2 2.x), the 32-bit relative of LE.
pub const LX_SIGNATURE: &[u8; 2] = b"LX";

/// Size of `IMAGE_FILE_HEADER`.
pub const FILE_HEADER_SIZE: usize = 20;
/// `IMAGE_FILE_HEADER::Machine`.
pub const FILE_MACHINE: usize = 0;
/// `IMAGE_FILE_HEADER::NumberOfSections`.
pub const FILE_NUMBER_OF_SECTIONS: usize = 2;
/// `IMAGE_FILE_HEADER::SizeOfOptionalHeader`.
pub const FILE_SIZE_OF_OPTIONAL_HEADER: usize = 16;
/// `IMAGE_FILE_HEADER::Characteristics`.
pub const FILE_CHARACTERISTICS: usize = 18;

/// `IMAGE_FILE_MACHINE_I386`.
pub const MACHINE_I386: u16 = 0x014C;
/// `IMAGE_FILE_MACHINE_AMD64`.
pub const MACHINE_AMD64: u16 = 0x8664;
/// `IMAGE_FILE_MACHINE_ARM64`.
pub const MACHINE_ARM64: u16 = 0xAA64;

/// `IMAGE_FILE_LARGE_ADDRESS_AWARE`.
pub const FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
/// `IMAGE_FILE_DLL`.
pub const FILE_DLL: u16 = 0x2000;

/// `IMAGE_NT_OPTIONAL_HDR32_MAGIC`.
pub const OPTIONAL_MAGIC_PE32: u16 = 0x10B;
/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC`.
pub const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x20B;

/// `IMAGE_OPTIONAL_HEADER32::Magic` and `…64::Magic`.
pub const OPT_MAGIC: usize = 0;
/// `IMAGE_OPTIONAL_HEADER32::ImageBase` (`u32`).
pub const OPT32_IMAGE_BASE: usize = 28;
/// `IMAGE_OPTIONAL_HEADER64::ImageBase` (`u64`).
pub const OPT64_IMAGE_BASE: usize = 24;
/// `SizeOfHeaders`, the same in both formats.
pub const OPT_SIZE_OF_HEADERS: usize = 60;
/// `Subsystem`, the same in both formats.
pub const OPT_SUBSYSTEM: usize = 68;
/// `DllCharacteristics`, the same in both formats.
pub const OPT_DLL_CHARACTERISTICS: usize = 70;
/// `IMAGE_OPTIONAL_HEADER32::NumberOfRvaAndSizes`.
pub const OPT32_NUMBER_OF_RVA_AND_SIZES: usize = 92;
/// `IMAGE_OPTIONAL_HEADER64::NumberOfRvaAndSizes`.
pub const OPT64_NUMBER_OF_RVA_AND_SIZES: usize = 108;
/// `IMAGE_OPTIONAL_HEADER32::DataDirectory`: the size of the fixed part.
pub const OPT32_DATA_DIRECTORY: usize = 96;
/// `IMAGE_OPTIONAL_HEADER64::DataDirectory`: the size of the fixed part.
pub const OPT64_DATA_DIRECTORY: usize = 112;
/// Size of `IMAGE_DATA_DIRECTORY` (`VirtualAddress`, `Size`).
pub const DATA_DIRECTORY_SIZE: usize = 8;
/// `IMAGE_NUMBEROF_DIRECTORY_ENTRIES`.
pub const NUMBER_OF_DIRECTORY_ENTRIES: usize = 16;

/// `IMAGE_DIRECTORY_ENTRY_IMPORT`.
pub const DIR_IMPORT: usize = 1;
/// `IMAGE_DIRECTORY_ENTRY_RESOURCE`.
pub const DIR_RESOURCE: usize = 2;
/// `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG`.
pub const DIR_LOAD_CONFIG: usize = 10;
/// `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`.
pub const DIR_DELAY_IMPORT: usize = 13;
/// `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` (CLR runtime header).
pub const DIR_COM_DESCRIPTOR: usize = 14;

/// `IMAGE_SIZEOF_SECTION_HEADER`.
pub const SECTION_HEADER_SIZE: usize = 40;
/// `IMAGE_SECTION_HEADER::Misc.VirtualSize`.
pub const SECTION_VIRTUAL_SIZE: usize = 8;
/// `IMAGE_SECTION_HEADER::VirtualAddress`.
pub const SECTION_VIRTUAL_ADDRESS: usize = 12;
/// `IMAGE_SECTION_HEADER::SizeOfRawData`.
pub const SECTION_SIZE_OF_RAW_DATA: usize = 16;
/// `IMAGE_SECTION_HEADER::PointerToRawData`.
pub const SECTION_POINTER_TO_RAW_DATA: usize = 20;

/// Size of `IMAGE_IMPORT_DESCRIPTOR`.
pub const IMPORT_DESCRIPTOR_SIZE: usize = 20;
/// `IMAGE_IMPORT_DESCRIPTOR::Name`.
pub const IMPORT_NAME: usize = 12;
/// Size of `IMAGE_DELAYLOAD_DESCRIPTOR`.
pub const DELAYLOAD_DESCRIPTOR_SIZE: usize = 32;
/// `IMAGE_DELAYLOAD_DESCRIPTOR::Attributes`.
pub const DELAYLOAD_ATTRIBUTES: usize = 0;
/// `IMAGE_DELAYLOAD_DESCRIPTOR::DllNameRVA`.
pub const DELAYLOAD_DLL_NAME_RVA: usize = 4;
/// `Attributes.RvaBased`: clear in VC6-style descriptors, which hold virtual addresses.
pub const DELAYLOAD_RVA_BASED: u32 = 1;

/// `IMAGE_LOAD_CONFIG_DIRECTORY32::Size` and `…64::Size`.
pub const LOAD_CONFIG_SIZE: usize = 0;
/// `IMAGE_LOAD_CONFIG_DIRECTORY32::DependentLoadFlags`.
pub const LOAD_CONFIG32_DEPENDENT_LOAD_FLAGS: usize = 0x36;
/// `IMAGE_LOAD_CONFIG_DIRECTORY64::DependentLoadFlags`.
pub const LOAD_CONFIG64_DEPENDENT_LOAD_FLAGS: usize = 0x4E;

/// Size of `IMAGE_RESOURCE_DIRECTORY`.
pub const RESOURCE_DIRECTORY_SIZE: usize = 16;
/// `IMAGE_RESOURCE_DIRECTORY::NumberOfNamedEntries`.
pub const RESOURCE_NUMBER_OF_NAMED_ENTRIES: usize = 12;
/// `IMAGE_RESOURCE_DIRECTORY::NumberOfIdEntries`.
pub const RESOURCE_NUMBER_OF_ID_ENTRIES: usize = 14;
/// Size of `IMAGE_RESOURCE_DIRECTORY_ENTRY`.
pub const RESOURCE_ENTRY_SIZE: usize = 8;
/// `IMAGE_RESOURCE_DIRECTORY_ENTRY::Name` (or `Id`).
pub const RESOURCE_ENTRY_NAME: usize = 0;
/// `IMAGE_RESOURCE_DIRECTORY_ENTRY::OffsetToData`.
pub const RESOURCE_ENTRY_OFFSET_TO_DATA: usize = 4;
/// `IMAGE_RESOURCE_NAME_IS_STRING`.
pub const RESOURCE_NAME_IS_STRING: u32 = 0x8000_0000;
/// `IMAGE_RESOURCE_DATA_IS_DIRECTORY`.
pub const RESOURCE_DATA_IS_DIRECTORY: u32 = 0x8000_0000;
/// Size of `IMAGE_RESOURCE_DATA_ENTRY`.
pub const RESOURCE_DATA_ENTRY_SIZE: usize = 16;
/// `IMAGE_RESOURCE_DATA_ENTRY::OffsetToData` (an RVA).
pub const RESOURCE_DATA_OFFSET_TO_DATA: usize = 0;
/// `IMAGE_RESOURCE_DATA_ENTRY::Size`.
pub const RESOURCE_DATA_SIZE: usize = 4;
/// `RT_VERSION` (`winuser.h`).
pub const RT_VERSION: u16 = 16;
/// `VS_VERSION_INFO` (`verrsrc.h`), the resource ID of the version resource.
pub const VS_VERSION_INFO: u16 = 1;
/// `LANG_NEUTRAL` with `SUBLANG_NEUTRAL`.
pub const LANG_NEUTRAL: u16 = 0x0000;
/// `MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US)`.
pub const LANG_EN_US: u16 = 0x0409;

/// Size of `VS_FIXEDFILEINFO` (`verrsrc.h`).
pub const FIXED_FILE_INFO_SIZE: usize = 52;
/// `VS_FFI_SIGNATURE`.
pub const FIXED_SIGNATURE_VALUE: u32 = 0xFEEF_04BD;
/// `VS_FIXEDFILEINFO::dwSignature`.
pub const FIXED_SIGNATURE: usize = 0;
/// `VS_FIXEDFILEINFO::dwFileVersionMS`.
pub const FIXED_FILE_VERSION_MS: usize = 8;
/// `VS_FIXEDFILEINFO::dwFileVersionLS`.
pub const FIXED_FILE_VERSION_LS: usize = 12;
/// `VS_FIXEDFILEINFO::dwProductVersionMS`.
pub const FIXED_PRODUCT_VERSION_MS: usize = 16;
/// `VS_FIXEDFILEINFO::dwProductVersionLS`.
pub const FIXED_PRODUCT_VERSION_LS: usize = 20;
/// `VS_FIXEDFILEINFO::dwFileFlagsMask`.
pub const FIXED_FILE_FLAGS_MASK: usize = 24;
/// `VS_FIXEDFILEINFO::dwFileFlags`.
pub const FIXED_FILE_FLAGS: usize = 28;
/// `VS_FIXEDFILEINFO::dwFileOS`.
pub const FIXED_FILE_OS: usize = 32;
/// `VS_FIXEDFILEINFO::dwFileType`.
pub const FIXED_FILE_TYPE: usize = 36;
/// `VS_FIXEDFILEINFO::dwFileSubtype`.
pub const FIXED_FILE_SUBTYPE: usize = 40;

/// `IMAGE_SUBSYSTEM_NATIVE`.
pub const SUBSYSTEM_NATIVE: u16 = 1;
/// `IMAGE_SUBSYSTEM_WINDOWS_GUI`.
pub const SUBSYSTEM_WINDOWS_GUI: u16 = 2;
/// `IMAGE_SUBSYSTEM_WINDOWS_CUI`.
pub const SUBSYSTEM_WINDOWS_CUI: u16 = 3;

#[cfg(all(test, windows))]
mod tests;
